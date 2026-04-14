// Package scanner 实现扫描引擎核心
package scanner

import (
	"bufio"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/didebughu/go-grepper/internal/checker"
	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/rule"
)

// Scanner 扫描引擎
type Scanner struct {
	settings          *config.Settings
	checker           checker.Checker
	codeChecker       *CodeChecker    // 通用不安全函数匹配
	commentChecker    *CommentChecker // 注释检查
	results           *model.ResultsTracker
	jobs              int // 并行数
	verbose           bool
	enableRules       []string // 启用规则列表
	disableRules      []string // 禁用规则列表
	disableCategories []string // 禁用规则类别
}

// NewScanner 创建扫描引擎
func NewScanner(settings *config.Settings, jobs int, verbose bool, enableRules, disableRules, disableCategories []string) *Scanner {
	return &Scanner{
		settings:          settings,
		checker:           checker.NewChecker(settings.Language, settings),
		codeChecker:       NewCodeChecker(settings),
		commentChecker:    NewCommentChecker(settings),
		results:           &model.ResultsTracker{},
		jobs:              jobs,
		verbose:           verbose,
		enableRules:       enableRules,
		disableRules:      disableRules,
		disableCategories: disableCategories,
	}
}

// Scan 执行扫描（主入口）
func (s *Scanner) Scan(files []string) *model.ResultsTracker {
	s.results.Reset()

	if len(files) == 0 {
		return s.results
	}

	// 使用 worker pool 并行扫描文件
	fileCh := make(chan string, len(files))
	var wg sync.WaitGroup

	workers := min(s.jobs, len(files))

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileCh {
				s.scanFile(file)
			}
		}()
	}

	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)
	wg.Wait()

	return s.results
}

// scanFile 扫描单个文件（对应原 ScanFiles 中的内层循环）
func (s *Scanner) scanFile(filePath string) {
	tracker := &model.CodeTracker{}
	tracker.Reset()

	reporter := &resultReporter{
		results:           s.results,
		currentFile:       filePath,
		enableRules:       s.enableRules,
		disableRules:      s.disableRules,
		disableCategories: s.disableCategories,
	}

	file, err := os.Open(filePath)
	if err != nil {
		slog.Error("无法打开文件", "file", filePath, "error", err)
		return
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	lineNum := 0
	inBlockComment := false

	// 文件级统计
	var commentCount, codeCount, whitespaceCount, lineCount, fixmeCount, badfuncCount int64

	for sc.Scan() {
		lineNum++
		lineCount++
		line := sc.Text()

		// COBOL 起始列处理
		if s.settings.Language == config.LangCOBOL && s.settings.COBOLStartCol > 1 {
			if s.settings.COBOLStartCol > len(line) {
				line = ""
			} else {
				line = line[s.settings.COBOLStartCol-1:]
			}
		}

		if len(strings.TrimSpace(line)) == 0 {
			// 空白行
			whitespaceCount++
			continue
		}

		// 注释/代码分离逻辑（对应原 ScanLine）
		code, comment, nowInBlock := s.splitLine(line, inBlockComment)
		inBlockComment = nowInBlock

		// 检查注释
		if len(strings.TrimSpace(comment)) > 0 {
			commentCount++
			found := s.commentChecker.Check(comment, filePath, lineNum, reporter)
			if found {
				fixmeCount++
			}
		}

		// 检查代码
		if len(strings.TrimSpace(code)) > 0 {
			codeCount++

			// 第一层：不安全函数匹配
			if s.codeChecker.Check(code, filePath, lineNum, reporter) {
				badfuncCount++
			}

			// 第二层：语言特定深度检查
			if !s.settings.ConfigOnly {
				reporter.lineNumber = lineNum
				s.checker.CheckCode(code, filePath, lineNum, tracker, reporter)

				// 硬编码密码检查（通用）
				checkHardcodedPassword(code, filePath, lineNum, reporter)
			}
		}
	}

	// 文件级检查
	if !s.settings.ConfigOnly {
		s.checker.CheckFileLevelIssues(filePath, tracker, reporter)
	}

	// 合并文件统计到全局
	s.results.MergeFileStats(commentCount, codeCount, whitespaceCount, lineCount, fixmeCount, badfuncCount)
	s.results.IncrFileCount()

	if s.verbose {
		slog.Info("扫描完成", "file", filePath, "lines", lineCount)
	}
}

// splitLine 将一行代码分离为代码部分和注释部分（对应原 ScanLine）
func (s *Scanner) splitLine(line string, inBlockComment bool) (code, comment string, stillInBlock bool) {
	langCfg := s.settings.LangConfig

	// 如果当前在块注释中
	if inBlockComment {
		if langCfg.BlockEndComment != "" {
			endIdx := strings.Index(line, langCfg.BlockEndComment)
			if endIdx >= 0 {
				comment = line[:endIdx+len(langCfg.BlockEndComment)]
				remaining := line[endIdx+len(langCfg.BlockEndComment):]
				// 递归处理剩余部分
				restCode, restComment, restInBlock := s.splitLine(remaining, false)
				code = restCode
				if restComment != "" {
					comment += " " + restComment
				}
				return code, comment, restInBlock
			}
		}
		// 整行都是块注释
		return "", line, true
	}

	// 检查单行注释
	singleIdx := -1
	if langCfg.SingleLineComment != "" {
		singleIdx = strings.Index(line, langCfg.SingleLineComment)
	}

	// 检查备选单行注释
	altIdx := -1
	if langCfg.AltLineComment != "" {
		altIdx = strings.Index(line, langCfg.AltLineComment)
	}

	// 检查块注释开始
	blockIdx := -1
	if langCfg.BlockStartComment != "" {
		blockIdx = strings.Index(line, langCfg.BlockStartComment)
	}

	// 找到最早出现的注释标记
	minIdx := len(line)
	commentType := "" // "single", "alt", "block"

	if singleIdx >= 0 && singleIdx < minIdx {
		minIdx = singleIdx
		commentType = "single"
	}
	if altIdx >= 0 && altIdx < minIdx {
		minIdx = altIdx
		commentType = "alt"
	}
	if blockIdx >= 0 && blockIdx < minIdx {
		minIdx = blockIdx
		commentType = "block"
	}

	if commentType == "" {
		// 没有注释
		return line, "", false
	}

	code = line[:minIdx]

	switch commentType {
	case "single", "alt":
		comment = line[minIdx:]
		return code, comment, false
	case "block":
		// 查找块注释结束
		rest := line[minIdx+len(langCfg.BlockStartComment):]
		endIdx := strings.Index(rest, langCfg.BlockEndComment)
		if endIdx >= 0 {
			comment = line[minIdx : minIdx+len(langCfg.BlockStartComment)+endIdx+len(langCfg.BlockEndComment)]
			remaining := line[minIdx+len(langCfg.BlockStartComment)+endIdx+len(langCfg.BlockEndComment):]
			// 递归处理剩余部分
			restCode, restComment, restInBlock := s.splitLine(remaining, false)
			if restCode != "" {
				code += restCode
			}
			if restComment != "" {
				comment += " " + restComment
			}
			return code, comment, restInBlock
		}
		// 块注释未结束
		comment = line[minIdx:]
		return code, comment, true
	}

	return line, "", false
}

// checkHardcodedPassword 检查硬编码密码（通用检查）
func checkHardcodedPassword(codeLine, fileName string, lineNumber int, reporter *resultReporter) {
	lower := strings.ToLower(codeLine)
	if strings.Contains(lower, "password ") {
		pwIdx := strings.Index(lower, "password")
		eqIdx := strings.Index(codeLine, "= \"")
		if eqIdx > 0 && pwIdx < eqIdx {
			// 排除空字符串赋值
			if !strings.Contains(codeLine, "''") && !strings.Contains(codeLine, "\"\"") {
				reporter.ReportIssue(
					"GEN-PASSWD-001",
					"Code Appears to Contain Hard-Coded Password",
					"The code may contain a hard-coded password which an attacker could obtain from the source or by dis-assembling the executable. Please manually review the code:",
					fileName, model.SeverityMedium, codeLine, lineNumber,
				)
			}
		}
	}
}

// resultReporter 实现 IssueReporter 接口，将问题添加到 ResultsTracker
type resultReporter struct {
	results           *model.ResultsTracker
	currentFile       string
	lineNumber        int
	enableRules       []string
	disableRules      []string
	disableCategories []string
}

func (r *resultReporter) ReportIssue(ruleID, title, description, fileName string, severity int, codeLine string, lineNumber int) {
	// 规则过滤：检查规则是否启用
	if ruleID != "" && !rule.IsEnabled(ruleID, r.enableRules, r.disableRules, r.disableCategories) {
		return
	}
	result := model.NewScanResult(ruleID, title, description, fileName, severity, codeLine, lineNumber)
	r.results.AddResult(result)
}

func (r *resultReporter) ReportMemoryIssue(issues map[string]string) {
	for varName, allocType := range issues {
		r.ReportIssue(
			"CPP-MEMLK-001",
			"Potential Memory Leak",
			"The variable '"+varName+"' was allocated with '"+allocType+"' but may not be properly freed.",
			r.currentFile, model.SeverityHigh, "", 0,
		)
	}
}

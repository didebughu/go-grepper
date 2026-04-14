// Package app 实现应用主逻辑
package app

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/reporter"
	"github.com/didebughu/go-grepper/internal/rule"
	"github.com/didebughu/go-grepper/internal/scanner"
	"github.com/didebughu/go-grepper/internal/util"
)

// Options 命令行参数
type Options struct {
	Target            string   // 目标目录路径
	Languages         []string // 语言类型列表（为空则扫描所有语言）
	Extensions        []string // 文件扩展名
	Severity          string   // 最低报告级别
	OutputFile        string   // 输出文件
	OutputFormat      string   // 输出格式
	ConfigDir         string   // 配置目录
	ConfigFile        string   // 配置文件路径（新增）
	ConfigOnly        bool     // 仅配置检查
	IsAndroid         bool     // Android 检查
	COBOLStartCol     int      // COBOL 起始列
	IsZOS             bool     // z/OS 模式
	IncludeSigned     bool     // 有符号比较检查
	Verbose           bool     // 详细模式
	Jobs              int      // 并行数
	ExcludeDirs       []string // 排除目录（新增）
	ExcludePatterns   []string // 排除文件模式（新增）
	EnableRules       []string // 启用规则列表（新增）
	DisableRules      []string // 禁用规则列表（新增）
	DisableCategories []string // 禁用规则类别（新增）
}

// DefaultOptions 返回默认选项
func DefaultOptions() *Options {
	return &Options{
		Languages:     nil, // 为空表示扫描所有语言
		Severity:      "all",
		OutputFormat:  "text",
		COBOLStartCol: 7,
		Jobs:          runtime.NumCPU(),
	}
}

// Run 执行扫描（应用主入口）
func Run(opts *Options) int {
	// 验证目标路径
	if opts.Target == "" {
		fmt.Fprintln(os.Stderr, "错误: 未指定目标路径 (-t)")
		return 2
	}

	info, err := os.Stat(opts.Target)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "错误: 目标路径不存在: %s\n", opts.Target)
		return 3
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法访问目标路径: %v\n", err)
		return 3
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "错误: 目标路径必须是目录: %s\n", opts.Target)
		return 2
	}

	// 加载配置文件（Profile）
	profile, err := config.LoadProfile(opts.ConfigFile, opts.Target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 配置文件加载失败: %v\n", err)
		return 4
	}

	// 合并配置: CLI > 配置文件 > 默认值
	mergeProfileToOptions(opts, profile)

	// 解析语言列表（将字符串转为小写后解析）
	lowerLangs := make([]string, len(opts.Languages))
	for i, l := range opts.Languages {
		lowerLangs[i] = strings.ToLower(l)
	}
	langIDs, err := config.ParseLanguages(lowerLangs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		return 2
	}

	// 解析严重级别
	minSeverity := model.ParseSeverity(strings.ToLower(opts.Severity))

	// 创建全局结果跟踪器
	allResults := &model.ResultsTracker{}
	allResults.Reset()

	loader := config.NewLoader(opts.ConfigDir)

	// 遍历每种语言执行扫描
	for _, langID := range langIDs {
		// 加载该语言的配置
		settings, err := loader.LoadSettings(
			langID, opts.Extensions, opts.ConfigOnly, opts.IsAndroid,
			opts.COBOLStartCol, opts.IsZOS, opts.IncludeSigned, minSeverity,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 语言 %s 配置加载失败: %v\n", config.LanguageName(langID), err)
			return 4
		}

		// 收集文件（应用目录排除和文件模式排除）
		files, err := util.CollectFiles(opts.Target, settings.FileSuffixes, opts.ExcludeDirs, opts.ExcludePatterns)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 文件收集失败: %v\n", err)
			return 3
		}

		if len(files) == 0 {
			if opts.Verbose {
				slog.Info("跳过语言（未找到匹配文件）", "language", config.LanguageName(langID))
			}
			continue
		}

		if opts.Verbose {
			slog.Info("开始扫描",
				"target", opts.Target,
				"language", config.LanguageName(langID),
				"files", len(files),
				"jobs", opts.Jobs,
			)
		}

		// 执行扫描
		s := scanner.NewScanner(settings, opts.Jobs, opts.Verbose,
			opts.EnableRules, opts.DisableRules, opts.DisableCategories)
		results := s.Scan(files)

		// 合并结果到全局
		allResults.Merge(results)
	}

	if allResults.FileCount == 0 {
		fmt.Fprintln(os.Stderr, "警告: 未找到匹配的文件")
		return 0
	}

	// 输出结果
	rep, err := reporter.NewReporter(opts.OutputFormat, opts.OutputFile, minSeverity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 创建输出器失败: %v\n", err)
		return 5
	}

	if err := rep.WriteResults(allResults); err != nil {
		fmt.Fprintf(os.Stderr, "错误: 输出结果失败: %v\n", err)
		return 5
	}

	if err := rep.WriteSummary(allResults); err != nil {
		fmt.Fprintf(os.Stderr, "错误: 输出摘要失败: %v\n", err)
		return 5
	}

	// 根据是否发现问题返回退出码
	if allResults.TotalIssues() > 0 {
		return 1
	}
	return 0
}

// mergeProfileToOptions 将配置文件中的值合并到 Options（仅覆盖用户未显式指定的参数）
func mergeProfileToOptions(opts *Options, profile *config.Profile) {
	if profile == nil {
		return
	}

	// 语言（仅当 CLI 未指定时使用配置文件值）
	if len(profile.Language) > 0 && len(opts.Languages) == 0 {
		opts.Languages = profile.Language
	}

	// 严重级别
	if profile.Severity != "" && opts.Severity == "all" {
		opts.Severity = profile.Severity
	}

	// 输出格式
	if profile.Output.Format != "" && opts.OutputFormat == "text" {
		opts.OutputFormat = profile.Output.Format
	}

	// 输出文件
	if profile.Output.File != "" && opts.OutputFile == "" {
		opts.OutputFile = profile.Output.File
	}

	// 文件扩展名
	if len(profile.Extensions) > 0 && len(opts.Extensions) == 0 {
		opts.Extensions = profile.Extensions
	}

	// 排除目录
	if len(profile.ExcludeDirs) > 0 && len(opts.ExcludeDirs) == 0 {
		opts.ExcludeDirs = profile.ExcludeDirs
	}

	// 排除文件模式
	if len(profile.ExcludePatterns) > 0 && len(opts.ExcludePatterns) == 0 {
		opts.ExcludePatterns = profile.ExcludePatterns
	}

	// 规则启用/禁用
	if len(profile.Rules.Enable) > 0 && len(opts.EnableRules) == 0 {
		opts.EnableRules = profile.Rules.Enable
	}
	if len(profile.Rules.Disable) > 0 && len(opts.DisableRules) == 0 {
		opts.DisableRules = profile.Rules.Disable
	}
	if len(profile.Rules.DisableCategories) > 0 && len(opts.DisableCategories) == 0 {
		opts.DisableCategories = profile.Rules.DisableCategories
	}

	// 扫描行为
	if profile.Scan.ConfigOnly {
		opts.ConfigOnly = true
	}
	if profile.Scan.Jobs > 0 && opts.Jobs == runtime.NumCPU() {
		opts.Jobs = profile.Scan.Jobs
	}
	if profile.Scan.Verbose {
		opts.Verbose = true
	}

	// 语言特定配置
	if profile.Java.Android {
		opts.IsAndroid = true
	}
	if profile.CPP.IncludeSigned {
		opts.IncludeSigned = true
	}
	if profile.COBOL.StartCol > 0 && opts.COBOLStartCol == 7 {
		opts.COBOLStartCol = profile.COBOL.StartCol
	}
	if profile.COBOL.ZOS {
		opts.IsZOS = true
	}
}

// ListRules 列出所有规则
func ListRules(lang, format string) {
	var rules []*rule.Rule

	if lang != "" {
		rules = rule.ListByLanguage(lang)
	} else {
		rules = rule.ListAll()
	}

	// 排序
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	switch format {
	case "json":
		listRulesJSON(rules, lang)
	case "csv":
		listRulesCSV(rules)
	default:
		listRulesTable(rules, lang)
	}
}

func listRulesTable(rules []*rule.Rule, lang string) {
	langDisplay := "全部"
	if lang != "" {
		langDisplay = lang
	}

	fmt.Printf("\ngo-grepper 内置规则列表 (语言: %s)\n", langDisplay)
	fmt.Printf("共 %d 条规则\n\n", len(rules))

	fmt.Printf("%-22s | %-42s | %-10s | %-8s | %s\n",
		"规则 ID", "名称", "严重级别", "类别", "状态")
	fmt.Println(strings.Repeat("-", 22) + "-+-" + strings.Repeat("-", 42) + "-+-" +
		strings.Repeat("-", 10) + "-+-" + strings.Repeat("-", 8) + "-+-" + strings.Repeat("-", 6))

	for _, r := range rules {
		status := "启用"
		if !r.Enabled {
			status = "禁用"
		}
		fmt.Printf("%-22s | %-42s | %-10s | %-8s | %s\n",
			r.ID, r.Name, model.SeverityName(r.Severity), r.Category, status)
	}
	fmt.Println()
}

func listRulesJSON(rules []*rule.Rule, lang string) {
	type jsonRule struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		Severity    string `json:"severity"`
		Category    string `json:"category"`
		Enabled     bool   `json:"enabled"`
	}

	type jsonOutput struct {
		Language string     `json:"language"`
		Total    int        `json:"total"`
		Rules    []jsonRule `json:"rules"`
	}

	output := jsonOutput{
		Language: lang,
		Total:    len(rules),
	}

	for _, r := range rules {
		output.Rules = append(output.Rules, jsonRule{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Severity:    model.SeverityName(r.Severity),
			Category:    r.Category,
			Enabled:     r.Enabled,
		})
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
}

func listRulesCSV(rules []*rule.Rule) {
	fmt.Println("ID,Name,Severity,Category,Enabled")
	for _, r := range rules {
		status := "true"
		if !r.Enabled {
			status = "false"
		}
		fmt.Printf("%s,%s,%s,%s,%s\n", r.ID, r.Name, model.SeverityName(r.Severity), r.Category, status)
	}
}

// InitConfig 在当前目录生成默认配置文件
func InitConfig() {
	filename := config.ProfileFileName
	if _, err := os.Stat(filename); err == nil {
		fmt.Fprintf(os.Stderr, "配置文件已存在: %s\n", filename)
		return
	}

	content := config.DefaultConfigContent()
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "创建配置文件失败: %v\n", err)
		return
	}

	fmt.Printf("已生成默认配置文件: %s\n", filename)
}

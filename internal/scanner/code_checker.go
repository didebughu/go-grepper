package scanner

import (
	"regexp"
	"strings"

	"github.com/didebughu/go-grepper/internal/checker"
	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// CodeChecker 通用不安全函数检查器（基于配置文件）
// 对应原 modMain.CheckCode() 中的不安全函数匹配部分
type CodeChecker struct {
	settings *config.Settings
	patterns []*compiledPattern // 预编译的正则模式
}

type compiledPattern struct {
	regex    *regexp.Regexp
	funcName string
	desc     string
	severity int
}

// NewCodeChecker 创建并预编译所有不安全函数的正则模式
func NewCodeChecker(settings *config.Settings) *CodeChecker {
	cc := &CodeChecker{settings: settings}

	for _, bf := range settings.BadFunctions {
		// 对应原逻辑：添加 \b 词边界（仅当不含空格和点号时）
		pattern := strings.TrimSpace(bf.Name)
		if pattern == "" {
			continue
		}

		var regexStr string
		if !util.ContainsWhitespace(pattern) && !strings.Contains(pattern, ".") {
			regexStr = `\b` + regexp.QuoteMeta(pattern) + `\b`
		} else {
			regexStr = regexp.QuoteMeta(pattern)
		}

		// PL/SQL 大小写不敏感
		if settings.Language == config.LangSQL {
			regexStr = "(?i)" + regexStr
		}

		re, err := regexp.Compile(regexStr)
		if err != nil {
			continue
		}

		cc.patterns = append(cc.patterns, &compiledPattern{
			regex:    re,
			funcName: bf.Name,
			desc:     bf.Description,
			severity: bf.Severity,
		})
	}

	return cc
}

// Check 检查代码行中的不安全函数，返回是否发现问题
func (cc *CodeChecker) Check(codeLine, fileName string, lineNum int, reporter checker.IssueReporter) bool {
	found := false
	checkLine := codeLine

	// PL/SQL 大小写不敏感
	if cc.settings.Language == config.LangSQL {
		checkLine = strings.ToUpper(codeLine)
	}

	for _, p := range cc.patterns {
		if p.regex.MatchString(checkLine) {
			reporter.ReportIssue("GEN-BADFUNC-001", p.funcName, p.desc, fileName, p.severity, codeLine, lineNum)
			found = true
		}
	}

	return found
}

// checkHardcodedPasswordGeneric 检查硬编码密码（通用）
func checkHardcodedPasswordGeneric(codeLine, fileName string, lineNumber int, reporter checker.IssueReporter) {
	lower := strings.ToLower(codeLine)
	if strings.Contains(lower, "password ") {
		pwIdx := strings.Index(lower, "password")
		eqIdx := strings.Index(codeLine, "= \"")
		if eqIdx > 0 && pwIdx < eqIdx {
			if !strings.Contains(codeLine, "''") && !strings.Contains(codeLine, "\"\"") {
				reporter.ReportIssue(
					"GEN-PASSWD-001",
					"Code Appears to Contain Hard-Coded Password",
					"The code may contain a hard-coded password which an attacker could obtain from the source or by dis-assembling the executable.",
					fileName, model.SeverityMedium, codeLine, lineNumber,
				)
			}
		}
	}
}

package checker

import (
	"regexp"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// VBChecker VB 安全检查器（对应原 modVBCheck）
// 注意：VB 的许多检查与 C# 共享逻辑
type VBChecker struct{}

func (c *VBChecker) Language() int { return config.LangVB }

// 预编译正则表达式
var (
	// CheckRandomisation
	reVBRandomize  = regexp.MustCompile(`\bRandomize\b\(\)`)
	reVBRandomizeT = regexp.MustCompile(`\bRandomize\b\(\w*[Tt]ime\w*\)`)
	reVBRandomizeS = regexp.MustCompile(`\bRandomize\b\(\S+\)`)
	reVBRnd        = regexp.MustCompile(`\bRnd\b\s*\(`)

	// CheckSAML2Validation
	reVBOverrideSAML = regexp.MustCompile(`\bOverrides\b\s+\b(Sub|Function)\b\s+\bValidateConditions\b\(Saml2Conditions\b`)
	reVBEndSub       = regexp.MustCompile(`\bEnd\b\s+\b(Sub|Function)\b`)

	// CheckUnsafeTempFiles
	reVBTempFile = regexp.MustCompile(`(file\S*|File\S*|\.FileName)\s+=\s+"\S*(temp|tmp)\S*",`)

	// CheckCryptoKeys
	reVBCryptoKey = regexp.MustCompile(`\b(Private|Public|Dim)\b\s+\b(Const|ReadOnly)\b\s+\w*(crypt|Crypt|CRYPT|key|Key|KEY)\w*\s+As\s+String\s*=\s*"`)
	reVBCryptoIV  = regexp.MustCompile(`\b(Private|Public|Dim)\b\s+\b(Const|ReadOnly)\b\s+\w*(iv|Iv|IV)\s+As\s+Byte\(\)\s*=\s*New\s+Byte`)

	// 密码管理
	reVBPasswordCase = regexp.MustCompile(`\S*(Password|password|pwd|passwd)\S*\.(ToLower|ToUpper)\s*\(`)

	// 通用
	reVBSanitize = regexp.MustCompile(`(?i)(validate|encode|sanitize|sanitise)`)
)

// 内部 CSharpChecker 实例，用于复用共享检查逻辑
var sharedCSChecker = &CSharpChecker{}

func (c *VBChecker) CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	// 复用 C# 的共享检查（VB 和 C# 的 ASP.NET 检查逻辑相同）
	sharedCSChecker.checkInputValidation(codeLine, fileName, lineNumber, tracker, reporter)
	sharedCSChecker.checkSQLInjection(codeLine, fileName, lineNumber, tracker, reporter)
	sharedCSChecker.checkXSS(codeLine, fileName, lineNumber, tracker, reporter)
	sharedCSChecker.checkSecureStorage(codeLine, fileName, lineNumber, reporter)
	sharedCSChecker.checkLogDisplay(codeLine, fileName, lineNumber, tracker, reporter)
	sharedCSChecker.checkFileRace(codeLine, fileName, lineNumber, tracker, reporter)
	sharedCSChecker.checkHTTPRedirect(codeLine, fileName, lineNumber, tracker, reporter)
	sharedCSChecker.checkExecutable(codeLine, fileName, lineNumber, tracker, reporter)
	sharedCSChecker.checkWebConfig(codeLine, fileName, lineNumber, reporter)

	// VB 特有的检查
	c.checkRandomisation(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkSAML2Validation(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkUnsafeTempFiles(codeLine, fileName, lineNumber, reporter)
	c.checkCryptoKeys(codeLine, fileName, lineNumber, reporter)

	if reVBPasswordCase.MatchString(codeLine) {
		reporter.ReportIssue("VB-PASSWD-001", "Unsafe Password Management",
			"The application appears to handle passwords in a case-insensitive manner. This can greatly increase the likelihood of successful brute-force and/or dictionary attacks.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

func (c *VBChecker) CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter) {
	// VB 文件级检查与 C# 类似
}

// checkRandomisation 检查随机数安全
func (c *VBChecker) checkRandomisation(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reVBRandomize.MatchString(codeLine) || reVBRandomizeT.MatchString(codeLine) {
		// 无种子或时间种子
	} else if reVBRandomizeS.MatchString(codeLine) {
		// 有非时间种子
	}

	if reVBRnd.MatchString(codeLine) {
		reporter.ReportIssue("VB-RAND-001", "Use of Deterministic Pseudo-Random Values",
			"The code appears to use the Rnd() function to generate pseudo-random values. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkSAML2Validation 检查 SAML2 验证
func (c *VBChecker) checkSAML2Validation(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reVBOverrideSAML.MatchString(codeLine) {
		// 进入 SAML2 验证函数
		tracker.HasValidator = true // 复用标记
	} else if tracker.HasValidator && reVBEndSub.MatchString(codeLine) {
		// 函数结束但没有验证逻辑
		if !reVBSanitize.MatchString(codeLine) {
			reporter.ReportIssue("VB-AUTH-001", "Insufficient SAML2 Condition Validation",
				"The code includes a token handling class that inherits from Saml2SecurityTokenHandler. It appears not to perform any validation on the Saml2Conditions object passed.",
				fileName, model.SeverityMedium, "", lineNumber)
		}
		tracker.HasValidator = false
	}
}

// checkUnsafeTempFiles 检查不安全的临时文件
func (c *VBChecker) checkUnsafeTempFiles(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reVBTempFile.MatchString(codeLine) {
		reporter.ReportIssue("VB-TMPF-001", "Unsafe Temporary File Allocation",
			"The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition or a symbolic link attack.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkCryptoKeys 检查硬编码加密密钥
func (c *VBChecker) checkCryptoKeys(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reVBCryptoKey.MatchString(codeLine) || reVBCryptoIV.MatchString(codeLine) {
		reporter.ReportIssue("VB-CRYPTO-001", "Hardcoded Crypto Key",
			"The code appears to use hardcoded encryption keys. These can be rendered visible with the use of a debugger or hex editor, exposing encrypted data.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// removeSanitisedVars 移除已清理的变量（VB 版本）
func (c *VBChecker) removeSanitisedVars(codeLine string, tracker *model.CodeTracker) {
	for i, v := range tracker.CSharp.InputVariables {
		if strings.Contains(codeLine, v) && reVBSanitize.MatchString(codeLine) {
			tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables[:i], tracker.CSharp.InputVariables[i+1:]...)
			return
		}
	}
}

// getVarName 从代码行中提取变量名
func (c *VBChecker) getVarName(codeLine string) string {
	return util.GetVarName(codeLine, false)
}

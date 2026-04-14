package checker

import (
	"regexp"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// CSharpChecker C# 安全检查器（对应原 modCSharpCheck）
type CSharpChecker struct{}

func (c *CSharpChecker) Language() int { return config.LangCSharp }

// 预编译正则表达式
var (
	// CheckInputValidation
	reValidateReqTrue  = regexp.MustCompile(`(?i)<pages\s+validateRequest="true"`)
	reValidateReqFalse = regexp.MustCompile(`(?i)<pages\s+validateRequest="false"`)

	// CheckSQLInjection
	reCSExecSQL = regexp.MustCompile(`(?i)(ExecuteQuery|ExecuteSQL|ExecuteStatement|SqlCommand\()`)

	// CheckXSS
	reCSHttpCookie  = regexp.MustCompile(`\bHttpCookie\b\s+\S+\s+=\s+\S+\.Cookies\.Get\(`)
	reCSRequestForm = regexp.MustCompile(`\bRequest\b\.Form\("`)
	reCSRequestQS   = regexp.MustCompile(`=\s*Request\.QueryString\[`)
	reCSHtmlRaw     = regexp.MustCompile(`\bHtml\b\.Raw\(`)
	reCSAspLabel    = regexp.MustCompile(`<asp:Label\s+ID="`)

	// CheckSecureStorage
	reCSInsecureStore = regexp.MustCompile(`\s+(String|char\[\])\s+\S*(Password|password|key)\S*`)

	// CheckIntOverflow
	reCSChecked   = regexp.MustCompile(`\bint\b\s*\w+\s*=\s*\bchecked\b\s+\(`)
	reCSUnchecked = regexp.MustCompile(`\bint\b\s*\w+\s*=\s*\bunchecked\b\s+\(`)
	reCSIntAssign = regexp.MustCompile(`\bint\b\s*\w+\s*=`)

	// CheckFileRace
	reCSFileExists = regexp.MustCompile(`(File|Directory)\.Exists\(`)
	reCSFileUse    = regexp.MustCompile(`Process\.Start\(|new\s+FileInfo\(|Directory\.GetFiles\(|\.FileName;`)

	// CheckSerialization
	reCSDeserialize = regexp.MustCompile(`\.(Deserialize|ReadObject)\s*\(`)

	// CheckHTTPRedirect
	reCSRedirect    = regexp.MustCompile(`Response\.Redirect\(`)
	reCSRedirectLit = regexp.MustCompile(`Response\.Redirect\(\s*"\S+"\s*\)`)

	// CheckRandomisation
	reCSRandomize  = regexp.MustCompile(`\bRandomize\b\(\)`)
	reCSRandomizeT = regexp.MustCompile(`\bRandomize\b\(\w*[Tt]ime\w*\)`)
	reCSRandomizeS = regexp.MustCompile(`\bRandomize\b\(\S+\)`)
	reCSRandomNext = regexp.MustCompile(`\bRandom\b\.Next(Bytes\(|\()`)

	// CheckSAML2
	reCSOverrideSAML = regexp.MustCompile(`\boverride\b\s+\bvoid\b\s+\bValidateConditions\b\(Saml2Conditions\b`)

	// CheckUnsafeTempFiles
	reCSTempFile = regexp.MustCompile(`=\s*File\.Open\("\S*(temp|tmp)\S*",`)

	// CheckUnsafeCode
	reCSUnsafe = regexp.MustCompile(`\bunsafe\b`)

	// CheckExecutable
	reCSProcessStart = regexp.MustCompile(`(?i)\.ProcessStartInfo\(`)

	// CheckWebConfig
	reCSCustomErrors = regexp.MustCompile(`<\s*customErrors\s+mode\s*=\s*"Off"\s*/>`)
	reCSDebug        = regexp.MustCompile(`\bdebug\b\s*=\s*"\s*true\s*"`)

	// CheckLogDisplay
	reCSLogFuncs = regexp.MustCompile(`LogError|Logger|logger|Logging|logging|System\.Diagnostics\.Debug|System\.Diagnostics\.Trace`)

	// 通用
	reCSSanitize = regexp.MustCompile(`(?i)(validate|encode|sanitize|sanitise)`)

	// 密码管理
	reCSPasswordCase = regexp.MustCompile(`\S*(Password|password|pwd|passwd)\S*(\.|->) *(ToLower|ToUpper)\s*\(`)
)

func (c *CSharpChecker) CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	c.identifyLabels(codeLine, fileName, tracker)
	c.checkInputValidation(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkSQLInjection(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkXSS(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkSecureStorage(codeLine, fileName, lineNumber, reporter)
	c.checkIntOverflow(codeLine, fileName, lineNumber, reporter)
	c.checkLogDisplay(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkFileRace(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkHTTPRedirect(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkRandomisation(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkUnsafeTempFiles(codeLine, fileName, lineNumber, reporter)
	c.checkUnsafeCode(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkExecutable(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkWebConfig(codeLine, fileName, lineNumber, reporter)

	// 检查密码大小写不敏感处理
	if reCSPasswordCase.MatchString(codeLine) {
		reporter.ReportIssue("CS-PASSWD-001", "Unsafe Password Management",
			"The application appears to handle passwords in a case-insensitive manner. This can greatly increase the likelihood of successful brute-force and/or dictionary attacks.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

func (c *CSharpChecker) CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter) {
	// C# 文件级检查：检查 unsafe 块状态
	if tracker.CSharp.InUnsafeBlock {
		reporter.ReportIssue("CS-MISC-002", "Unsafe Code Block Not Properly Closed",
			"The file appears to contain an unsafe code block that may not be properly closed.",
			fileName, model.SeverityMedium, "", 0)
	}
}

// identifyLabels 识别 ASP 页面中的 Label
func (c *CSharpChecker) identifyLabels(codeLine, fileName string, tracker *model.CodeTracker) {
	lowerFile := strings.ToLower(fileName)
	if !tracker.HasValidator && (strings.HasSuffix(lowerFile, ".asp") || strings.HasSuffix(lowerFile, ".aspx")) && strings.Contains(codeLine, "<asp:Label ID=\"") {
		parts := reCSAspLabel.Split(codeLine, 2)
		if len(parts) > 1 {
			label := util.GetFirstItem(parts[1], "\"")
			if label != "" {
				for _, l := range tracker.CSharp.AspLabels {
					if l == label {
						return
					}
				}
				tracker.CSharp.AspLabels = append(tracker.CSharp.AspLabels, label)
			}
		}
	}
}

// checkInputValidation 检查输入验证
func (c *CSharpChecker) checkInputValidation(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	lowerFile := strings.ToLower(fileName)
	lowerLine := strings.ToLower(codeLine)

	if !tracker.HasValidator && strings.HasSuffix(lowerFile, ".config") && strings.Contains(lowerLine, `<pages validaterequset="true"`) {
		tracker.HasValidator = true
	} else if !tracker.HasValidator && strings.HasSuffix(lowerFile, ".xml") && strings.Contains(lowerLine, `validaterequest="true"`) {
		tracker.HasValidator = true
	} else if strings.HasSuffix(lowerFile, ".config") && reValidateReqFalse.MatchString(codeLine) {
		tracker.HasValidator = false
		reporter.ReportIssue("CS-INPUT-001", "Potential Input Validation Issues",
			"The application appears to deliberately de-activate the default .NET input validation functionality.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if strings.HasSuffix(lowerFile, ".xml") && strings.Contains(lowerLine, `validaterequest="false"`) {
		tracker.HasValidator = false
		reporter.ReportIssue("CS-INPUT-001", "Potential Input Validation Issues",
			"The application appears to deliberately de-activate the default .NET input validation functionality.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

// checkSQLInjection 检查 SQL 注入
func (c *CSharpChecker) checkSQLInjection(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.HasValidator {
		return
	}

	// 检查预准备的动态 SQL 语句
	lowerLine := strings.ToLower(codeLine)
	if strings.Contains(codeLine, "=") && (strings.Contains(lowerLine, "sql") || strings.Contains(lowerLine, "query")) &&
		strings.Contains(codeLine, "\"") && (strings.Contains(codeLine, "&") || strings.Contains(codeLine, "+")) {
		varName := util.GetVarName(codeLine, false)
		tracker.HasVulnSQLString = true
		if regexp.MustCompile(`^[a-zA-Z0-9_]*$`).MatchString(varName) {
			found := false
			for _, s := range tracker.SQLStatements {
				if s == varName {
					found = true
					break
				}
			}
			if !found {
				tracker.SQLStatements = append(tracker.SQLStatements, varName)
			}
		}
	}

	if reCSSanitize.MatchString(codeLine) {
		c.removeSanitisedVars(codeLine, tracker)
	} else if reCSExecSQL.MatchString(codeLine) {
		if strings.Contains(codeLine, "\"") && strings.Contains(codeLine, "&") {
			reporter.ReportIssue("CS-SQLI-001", "Potential SQL Injection",
				"The application appears to allow SQL injection via dynamic SQL statements.",
				fileName, model.SeverityCritical, codeLine, lineNumber)
		} else if tracker.HasVulnSQLString {
			for _, sqlVar := range tracker.SQLStatements {
				if strings.Contains(codeLine, sqlVar) {
					reporter.ReportIssue("CS-SQLI-002", "Potential SQL Injection",
						"The application appears to allow SQL injection via a pre-prepared dynamic SQL statement.",
						fileName, model.SeverityCritical, codeLine, lineNumber)
					break
				}
			}
		}
	}
}

// checkXSS 检查 XSS 漏洞
func (c *CSharpChecker) checkXSS(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.HasValidator {
		return
	}

	if reCSSanitize.MatchString(codeLine) {
		c.removeSanitisedVars(codeLine, tracker)
		return
	}

	// 跟踪输入变量
	if reCSHttpCookie.MatchString(codeLine) {
		varName := util.GetVarName(codeLine, false)
		c.addInputVar(varName, tracker)
	} else if reCSRequestForm.MatchString(codeLine) {
		parts := reCSRequestForm.Split(codeLine, 2)
		if len(parts) > 1 {
			varName := util.GetFirstItem(parts[0], "\"")
			c.addInputVar(varName, tracker)
		}
	} else if strings.Contains(codeLine, "=") && (strings.Contains(codeLine, ".Value") || reCSRequestQS.MatchString(codeLine)) {
		varName := util.GetVarName(codeLine, false)
		c.addInputVar(varName, tracker)
	}

	// 检查 Response.Write XSS
	if strings.Contains(codeLine, "Response.Write(") && strings.Contains(codeLine, "Request.Form(") {
		reporter.ReportIssue("CS-XSS-001", "Potential XSS",
			"The application appears to reflect user input to the screen with no apparent validation or sanitisation.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if strings.Contains(codeLine, "Response.Write(") {
		c.checkUserVarXSS(codeLine, fileName, lineNumber, tracker, reporter)
	}

	// 检查 Label 赋值
	if strings.Contains(codeLine, ".Text =") {
		for _, label := range tracker.CSharp.AspLabels {
			if strings.Contains(codeLine, label) {
				c.checkUserVarXSS(codeLine, fileName, lineNumber, tracker, reporter)
				break
			}
		}
	}

	// 检查 Html.Raw
	if reCSHtmlRaw.MatchString(codeLine) {
		found := false
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("CS-XSS-002", "Potential XSS",
					"The application uses the potentially dangerous Html.Raw construct in conjunction with a user-supplied variable.",
					fileName, model.SeverityHigh, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found {
			reporter.ReportIssue("CS-XSS-002", "Potential XSS",
				"The application uses the potentially dangerous Html.Raw construct.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

// checkUserVarXSS 检查用户变量 XSS
func (c *CSharpChecker) checkUserVarXSS(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	for _, v := range tracker.CSharp.InputVariables {
		if strings.Contains(codeLine, v) {
			reporter.ReportIssue("CS-XSS-001", "Potential XSS",
				"The application appears to reflect a user-supplied variable to the screen with no apparent validation or sanitisation.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
			return
		}
	}
	reporter.ReportIssue("CS-XSS-003", "Potential XSS",
		"The application appears to reflect data to the screen with no apparent validation or sanitisation. It was not clear if this variable is controlled by the user.",
		fileName, model.SeverityMedium, codeLine, lineNumber)
}

// checkSecureStorage 检查敏感信息存储
func (c *CSharpChecker) checkSecureStorage(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reCSInsecureStore.MatchString(codeLine) {
		reporter.ReportIssue("CS-CRYPTO-001", "Insecure Storage of Sensitive Information",
			"The code uses standard strings and byte arrays to store sensitive transient data such as passwords and cryptographic private keys instead of the more secure SecureString class.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkIntOverflow 检查整数溢出
func (c *CSharpChecker) checkIntOverflow(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reCSChecked.MatchString(codeLine) {
		return
	}
	if reCSUnchecked.MatchString(codeLine) && (strings.Contains(codeLine, "+") || strings.Contains(codeLine, "*")) {
		reporter.ReportIssue("CS-INTOV-002", "Integer Operation With Overflow Check Deliberately Disabled",
			"The code carries out integer operations with a deliberate disabling of overflow defences. Manually review the code to ensure that it is safe.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	} else if reCSIntAssign.MatchString(codeLine) && (strings.Contains(codeLine, "+") || strings.Contains(codeLine, "*")) {
		reporter.ReportIssue("CS-INTOV-001", "Integer Operation Without Overflow Check",
			"The code carries out integer operations without enabling overflow defences. Manually review the code to ensure that it is safe.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	}
}

// checkLogDisplay 检查日志输出
func (c *CSharpChecker) checkLogDisplay(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.HasValidator && !strings.Contains(strings.ToLower(codeLine), "password") {
		return
	}

	if reCSSanitize.MatchString(codeLine) && !strings.Contains(strings.ToLower(codeLine), "password") {
		c.removeSanitisedVars(codeLine, tracker)
	} else if reCSLogFuncs.MatchString(codeLine) && strings.Contains(strings.ToLower(codeLine), "password") {
		logIdx := strings.Index(strings.ToLower(codeLine), "log")
		pwIdx := strings.Index(strings.ToLower(codeLine), "password")
		if logIdx < pwIdx {
			reporter.ReportIssue("CS-LOG-001", "Application Appears to Log User Passwords",
				"The application appears to write user passwords to logfiles creating a risk of credential theft.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
		}
	} else if reCSLogFuncs.MatchString(codeLine) {
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("CS-LOG-002", "Unsanitized Data Written to Logs",
					"The application appears to write unsanitized data to its logfiles. If logs are viewed by a browser-based application this exposes risk of XSS attacks.",
					fileName, model.SeverityMedium, codeLine, lineNumber)
				break
			}
		}
	}
}

// checkFileRace 检查 TOCTOU 竞态条件
func (c *CSharpChecker) checkFileRace(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reCSFileExists.MatchString(codeLine) && !reCSFileUse.MatchString(codeLine) {
		tracker.CSharp.InUnsafeBlock = true // 复用字段作为 TOCTOU 标记
	} else if tracker.CSharp.InUnsafeBlock {
		if reCSFileUse.MatchString(codeLine) {
			reporter.ReportIssue("CS-RACE-001", "Potential TOCTOU (Time Of Check, Time Of Use) Vulnerability",
				"The .Exists() check occurs before the file/directory is accessed. The longer the time between the check and the access, the greater the likelihood that the check will no longer be valid.",
				fileName, model.SeverityStandard, codeLine, lineNumber)
			tracker.CSharp.InUnsafeBlock = false
		}
	}
}

// checkHTTPRedirect 检查 HTTP 重定向
func (c *CSharpChecker) checkHTTPRedirect(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if strings.Contains(codeLine, "Response.Redirect(") && strings.Contains(codeLine, "HTTP:") {
		reporter.ReportIssue("CS-REDIR-001", "URL request sent over HTTP:",
			"The URL used in the HTTP request appears to be unencrypted. Check the code manually to ensure that sensitive data is not being submitted.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	} else if reCSRedirect.MatchString(codeLine) && !reCSRedirectLit.MatchString(codeLine) {
		found := false
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("CS-REDIR-002", "URL Request Gets Path from Unvalidated Variable",
					"The URL used in the HTTP request is loaded from an unsanitised variable. This can allow an attacker to redirect the user to a site under the control of a third party.",
					fileName, model.SeverityMedium, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found {
			reporter.ReportIssue("CS-REDIR-003", "URL Request Gets Path from Variable",
				"The URL used in the HTTP request appears to be loaded from a variable. Check the code manually to ensure that malicious URLs cannot be submitted by an attacker.",
				fileName, model.SeverityStandard, codeLine, lineNumber)
		}
	}
}

// checkRandomisation 检查随机数安全
func (c *CSharpChecker) checkRandomisation(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reCSRandomize.MatchString(codeLine) || reCSRandomizeT.MatchString(codeLine) {
		tracker.HasValidator = false // 复用作为 seed 标记（简化）
	} else if reCSRandomizeS.MatchString(codeLine) {
		tracker.HasValidator = true
	}

	if reCSRandomNext.MatchString(codeLine) {
		reporter.ReportIssue("CS-RAND-001", "Use of Deterministic Pseudo-Random Values",
			"The code appears to use the Next() and/or NextBytes() functions to generate pseudo-random values. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkUnsafeTempFiles 检查不安全的临时文件
func (c *CSharpChecker) checkUnsafeTempFiles(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reCSTempFile.MatchString(codeLine) {
		reporter.ReportIssue("CS-TMPF-001", "Unsafe Temporary File Allocation",
			"The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition or a symbolic link attack.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkUnsafeCode 检查 unsafe 代码指令
func (c *CSharpChecker) checkUnsafeCode(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reCSUnsafe.MatchString(codeLine) {
		reporter.ReportIssue("CS-MISC-001", "Unsafe Code Directive",
			"The code uses the 'unsafe' directive which allows the use of C-style pointers. This code has an increased risk of unexpected behaviour, including buffer overflows, memory leaks and crashes.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
		tracker.CSharp.InUnsafeBlock = true
	}
}

// checkExecutable 检查命令执行
func (c *CSharpChecker) checkExecutable(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reCSSanitize.MatchString(codeLine) {
		return
	}

	if reCSProcessStart.MatchString(codeLine) {
		found := false
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("CS-CMDI-001", "User Controlled Variable Used on System Command Line",
					"The application appears to allow the use of an unvalidated user-controlled variable when executing a command.",
					fileName, model.SeverityHigh, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found && (!strings.Contains(codeLine, "\"") || (strings.Contains(codeLine, "\"") && strings.Contains(codeLine, "+"))) {
			reporter.ReportIssue("CS-CMDI-002", "Application Variable Used on System Command Line",
				"The application appears to allow the use of an unvalidated variable when executing a command. Carry out a manual check to determine whether the variable is user-controlled.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

// checkWebConfig 检查 web.config 配置
func (c *CSharpChecker) checkWebConfig(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if !strings.HasSuffix(strings.ToLower(fileName), "web.config") {
		return
	}

	if reCSCustomErrors.MatchString(codeLine) {
		reporter.ReportIssue("CS-CONF-001", ".NET Default Errors Enabled",
			"The application is configured to display .NET default errors. This can provide an attacker with useful information and should not be used in a live application.",
			fileName, model.SeverityMedium, "", lineNumber)
	} else if reCSDebug.MatchString(codeLine) {
		reporter.ReportIssue("CS-CONF-002", ".NET Debugging Enabled",
			"The application is configured to return .NET debug information. This can provide an attacker with useful information and should not be used in a live application.",
			fileName, model.SeverityMedium, "", lineNumber)
	}
}

// addInputVar 添加输入变量
func (c *CSharpChecker) addInputVar(varName string, tracker *model.CodeTracker) {
	if varName == "" || !regexp.MustCompile(`^[a-zA-Z0-9_]*$`).MatchString(varName) {
		return
	}
	for _, v := range tracker.CSharp.InputVariables {
		if v == varName {
			return
		}
	}
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, varName)
}

// removeSanitisedVars 移除已清理的变量
func (c *CSharpChecker) removeSanitisedVars(codeLine string, tracker *model.CodeTracker) {
	for i, v := range tracker.CSharp.InputVariables {
		if strings.Contains(codeLine, v) && reCSSanitize.MatchString(codeLine) {
			tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables[:i], tracker.CSharp.InputVariables[i+1:]...)
			return
		}
	}
}

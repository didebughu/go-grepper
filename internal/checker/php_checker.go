package checker

import (
	"regexp"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// PHPChecker PHP 安全检查器（对应原 modPHPCheck）
type PHPChecker struct{}

func (c *PHPChecker) Language() int { return config.LangPHP }

// 预编译正则表达式
var (
	// CheckSQLInjection
	rePHPSQLExec   = regexp.MustCompile(`(mysql_query|mssql_query|pg_query)\s*\(`)
	rePHPEscapeStr = regexp.MustCompile(`mysql_real_escape_string`)

	// CheckXSS
	rePHPSuperGlobal = regexp.MustCompile(`\$\w+\s*=\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)`)
	rePHPPrint       = regexp.MustCompile(`\b(print|echo|print_r)\b`)
	rePHPPrintSuper  = regexp.MustCompile(`\b(print|echo|print_r)\b\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)`)
	rePHPStripTags   = regexp.MustCompile(`strip_tags`)
	rePHPDOMXSS      = regexp.MustCompile(`\)\.innerHTML\s*=\s*('|")\s*<\s*\?\s*echo\s*\$_(GET|POST|COOKIE|SERVER|REQUEST)\s*\[`)

	// CheckLogDisplay
	rePHPLog = regexp.MustCompile(`AddLog|error_log`)

	// CheckRandomisation
	rePHPOpenSSLFalse = regexp.MustCompile(`\$\w+\s*=\s*\bopenssl_random_pseudo_bytes\b\s*\(\s*\S+\s*,\s*(0|false|False|FALSE)`)
	rePHPMtRandEmpty  = regexp.MustCompile(`\$\w+\s*=\s*\b(mt_rand|smt_rand)\b\s*\(\s*\)`)
	rePHPMtRandTime   = regexp.MustCompile(`\b(mt_rand|smt_rand)\b\s*\(\w*[Tt]ime\w*\)`)
	rePHPMtRandSeed   = regexp.MustCompile(`\b(mt_rand|smt_rand)\b\s*\(\s*\S+\s*\)`)

	// CheckFileValidation
	rePHPFilesArray = regexp.MustCompile(`\bif\b\s*\(\s*\$_FILES\s*\[`)

	// CheckFileInclusion
	rePHPIncludeVar = regexp.MustCompile(`\b(file_include|include|require|include_once|require_once)\b\s*\(\s*\$`)
	rePHPIncludeExt = regexp.MustCompile(`\b(file_include|include|require|include_once|require_once)\b\s*\(\s*('|")\w+\.(inc|txt|dat)`)
	rePHPFileAccess = regexp.MustCompile(`\b(fwrite|file_get_contents|fopen|glob|popen|file|readfile)\b\s*\(\s*\$`)

	// CheckExecutable
	rePHPExec      = regexp.MustCompile(`\b(exec|shell_exec|proc_open|eval|system|popen|passthru|pcntl_exec|assert)\b`)
	rePHPEscapeCmd = regexp.MustCompile(`escapeshellcmd`)

	// CheckBackTick
	rePHPBackTickSuper = regexp.MustCompile("`\\s*\\S*\\s*\\$_(GET|POST|COOKIE|REQUEST|SERVER)")
	rePHPBackTickVar   = regexp.MustCompile("`\\s*\\S*\\s*\\$\\w+")

	// CheckRegisterGlobals
	rePHPRegGlobals = regexp.MustCompile(`\bini_set\b\s*\(\s*('|")register_globals('|")\s*,\s*(1|true|TRUE|True|\$\w+)`)
	rePHPArrayMerge = regexp.MustCompile(`\$\w+\s*=\s*\barray_merge\b\s*\(\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*,\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)`)

	// CheckParseStr
	rePHPParseStr = regexp.MustCompile(`\bparse_str\b\s*\(\s*\$\w+\s*\)`)

	// CheckPhpIni
	rePHPIniRegGlob   = regexp.MustCompile(`\bregister_globals\b\s*=\s*\b(on|ON|On)\b`)
	rePHPIniSafeMode  = regexp.MustCompile(`\bsafe_mode\b\s*=\s*\b(off|OFF|Off)\b`)
	rePHPIniMagic     = regexp.MustCompile(`\b(magic_quotes_gpc|magic_quotes_runtime|magic_quotes_sybase)\b\s*=\s*\b(off|OFF|Off)\b`)
	rePHPIniDisable   = regexp.MustCompile(`\bdisable_functions\b\s*=\s*\w+`)
	rePHPIniMySQLRoot = regexp.MustCompile(`\bmysql\.default_user\b\s*=\s*\broot\b`)

	// 通用
	rePHPSanitize = regexp.MustCompile(`(?i)(validate|encode|sanitize|sanitise)`)

	// 密码管理
	rePHPPasswordCase = regexp.MustCompile(`(strtolower|strtoupper)\s*\(\s*\S*(Password|password|pwd|PWD|Pwd|Passwd|passwd)`)
)

func (c *PHPChecker) CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	// php.ini 文件特殊处理
	if strings.HasSuffix(strings.ToLower(fileName), "php.ini") {
		c.checkPhpIni(codeLine, fileName, lineNumber, tracker, reporter)
		return
	}

	c.checkSQLInjection(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkXSS(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkLogDisplay(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkRandomisation(codeLine, fileName, lineNumber, reporter)
	c.checkFileValidation(codeLine, fileName, lineNumber, reporter)
	c.checkFileInclusion(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkExecutable(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkBackTick(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkRegisterGlobals(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkParseStr(codeLine, fileName, lineNumber, tracker, reporter)

	if rePHPPasswordCase.MatchString(codeLine) {
		reporter.ReportIssue("PHP-PASSWD-001", "Unsafe Password Management",
			"The application appears to handle passwords in a case-insensitive manner. This can greatly increase the likelihood of successful brute-force and/or dictionary attacks.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

func (c *PHPChecker) CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter) {
	// 检查 php.ini 中是否禁用了危险函数
	if strings.HasSuffix(strings.ToLower(fileName), "php.ini") && !tracker.PHP.HasDisableFunctions {
		reporter.ReportIssue("PHP-CONF-008", "No Disabled Functions in php.ini",
			"The php.ini file does not appear to use the disable_functions directive. Consider disabling dangerous functions to reduce the attack surface.",
			fileName, model.SeverityLow, "", 0)
	}
}

// checkSQLInjection 检查 SQL 注入
func (c *PHPChecker) checkSQLInjection(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.HasValidator {
		return
	}

	lowerLine := strings.ToLower(codeLine)
	if strings.Contains(codeLine, "=") &&
		(strings.Contains(lowerLine, "sql") || strings.Contains(lowerLine, "query") || strings.Contains(lowerLine, "stmt")) &&
		strings.Contains(codeLine, "\"") && (strings.Contains(codeLine, "$") || strings.Contains(codeLine, "+")) {
		varName := util.GetVarName(codeLine, false)
		tracker.HasVulnSQLString = true
		if regexp.MustCompile(`^\$[a-zA-Z0-9_]*$`).MatchString(varName) {
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

	if rePHPSanitize.MatchString(codeLine) {
		return
	}

	if rePHPSQLExec.MatchString(codeLine) && !rePHPEscapeStr.MatchString(codeLine) {
		if tracker.HasVulnSQLString {
			for _, sqlVar := range tracker.SQLStatements {
				if strings.Contains(codeLine, sqlVar) {
					reporter.ReportIssue("PHP-SQLI-002", "Potential SQL Injection",
						"The application appears to allow SQL injection via a pre-prepared dynamic SQL statement.",
						fileName, model.SeverityCritical, codeLine, lineNumber)
					return
				}
			}
		}
		if strings.Contains(codeLine, "$") {
			reporter.ReportIssue("PHP-SQLI-001", "Potential SQL Injection", "The application appears to allow SQL injection via dynamic SQL statements.",
				fileName, model.SeverityCritical, codeLine, lineNumber)
		}
	}
}

// checkXSS 检查 XSS 漏洞
func (c *PHPChecker) checkXSS(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.HasValidator {
		return
	}

	if rePHPSanitize.MatchString(codeLine) {
		return
	}

	// 跟踪超全局变量赋值
	if rePHPSuperGlobal.MatchString(codeLine) {
		varName := util.GetVarName(codeLine, false)
		c.addInputVar(varName, tracker)
	}

	// 检查直接输出超全局变量
	if rePHPPrintSuper.MatchString(codeLine) && !rePHPStripTags.MatchString(codeLine) {
		reporter.ReportIssue("PHP-XSS-001", "Potential XSS",
			"The application appears to reflect a user-supplied variable to the screen with no apparent validation or sanitisation.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if rePHPPrint.MatchString(codeLine) && strings.Contains(codeLine, "$") && !rePHPStripTags.MatchString(codeLine) {
		c.checkUserVarXSS(codeLine, fileName, lineNumber, tracker, reporter)
	}

	// 检查 DOM-based XSS
	if rePHPDOMXSS.MatchString(codeLine) {
		reporter.ReportIssue("PHP-XSS-003", "Potential DOM-Based XSS",
			"The application appears to allow XSS via an unencoded/unsanitised input variable.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

// checkUserVarXSS 检查用户变量 XSS
func (c *PHPChecker) checkUserVarXSS(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	for _, v := range tracker.CSharp.InputVariables { // PHP 复用 CSharp.InputVariables
		if strings.Contains(codeLine, v) {
			reporter.ReportIssue("PHP-XSS-002", "Potential XSS",
				"The application appears to reflect a user-supplied variable to the screen with no apparent validation or sanitisation.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
			return
		}
	}
}

// checkLogDisplay 检查日志输出
func (c *PHPChecker) checkLogDisplay(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if rePHPSanitize.MatchString(codeLine) && !strings.Contains(strings.ToLower(codeLine), "password") {
		return
	}

	if rePHPLog.MatchString(codeLine) && strings.Contains(strings.ToLower(codeLine), "password") {
		logIdx := strings.Index(strings.ToLower(codeLine), "log")
		pwIdx := strings.Index(strings.ToLower(codeLine), "password")
		if logIdx < pwIdx {
			reporter.ReportIssue("PHP-LOG-001", "Application Appears to Log User Passwords",
				"The application appears to write user passwords to logfiles or the screen, creating a risk of credential theft.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
		}
	} else if rePHPLog.MatchString(codeLine) && !rePHPStripTags.MatchString(codeLine) {
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("PHP-LOG-002", "Unsanitized Data Written to Logs",
					"The application appears to write unsanitized data to its logfiles. If logs are viewed by a browser-based application this exposes risk of XSS attacks.",
					fileName, model.SeverityMedium, codeLine, lineNumber)
				break
			}
		}
	}
}

// checkRandomisation 检查随机数安全
func (c *PHPChecker) checkRandomisation(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if rePHPOpenSSLFalse.MatchString(codeLine) {
		reporter.ReportIssue("PHP-RAND-001", "Use of Deterministic Pseudo-Random Values",
			"The code appears to use the function with the 'secure' value deliberately set to 'false'. The resulting values are predictable and may be enumerated by a skilled attacker.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	} else if rePHPMtRandEmpty.MatchString(codeLine) || rePHPMtRandTime.MatchString(codeLine) {
		reporter.ReportIssue("PHP-RAND-002", "Use of Deterministic Pseudo-Random Values",
			"The code appears to use the mt_rand and/or smt_rand functions without a seed to generate pseudo-random values. The resulting values are predictable and may be enumerated by a skilled attacker.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	} else if rePHPMtRandSeed.MatchString(codeLine) {
		reporter.ReportIssue("PHP-RAND-002", "Use of Deterministic Pseudo-Random Values",
			"The code appears to use the mt_rand function. The resulting values are predictable, although this is partly mitigated by a seed that does not appear to be time-based.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	}
}

// checkFileValidation 检查文件验证
func (c *PHPChecker) checkFileValidation(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if rePHPFilesArray.MatchString(codeLine) {
		reporter.ReportIssue("PHP-FILE-001", "Unsafe Processing of $_FILES Array",
			"The code appears to use data within the $_FILES array in order to make decisions. This is obtained direct from the HTTP request and may be modified by the client to cause unexpected behaviour.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkFileInclusion 检查文件包含漏洞
func (c *PHPChecker) checkFileInclusion(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if rePHPIncludeVar.MatchString(codeLine) {
		found := false
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("PHP-FILE-002", "File Inclusion Vulnerability",
					"The code appears to use a user-controlled variable as a parameter for an include statement which could lead to a file include vulnerability.",
					fileName, model.SeverityHigh, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found {
			reporter.ReportIssue("PHP-FILE-004", "Variable Used as FileName",
				"The application appears to use a variable name in order to define a filename used by the application. It is unclear whether this variable can be controlled by the user.",
				fileName, model.SeverityLow, codeLine, lineNumber)
		}
	} else if rePHPIncludeExt.MatchString(codeLine) {
		reporter.ReportIssue("PHP-FILE-003", "File Inclusion Vulnerability",
			"The code appears to use an unsafe file extension for an include statement which could allow an attacker to download it directly and read the uncompiled code.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if rePHPFileAccess.MatchString(codeLine) {
		found := false
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("PHP-FILE-004", "File Access Vulnerability",
					"The code appears to use a user-controlled variable as a parameter when accessing the filesystem. This could lead to a system compromise.",
					fileName, model.SeverityHigh, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found {
			reporter.ReportIssue("PHP-FILE-004", "Variable Used as FileName",
				"The application appears to use a variable name in order to define a filename used by the application. It is unclear whether this variable can be controlled by the user.",
				fileName, model.SeverityLow, codeLine, lineNumber)
		}
	}
}

// checkExecutable 检查命令执行
func (c *PHPChecker) checkExecutable(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if rePHPSanitize.MatchString(codeLine) {
		return
	}

	if rePHPExec.MatchString(codeLine) && !rePHPEscapeCmd.MatchString(codeLine) {
		found := false
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("PHP-CMDI-001", "User Controlled Variable Used on System Command Line",
					"The application appears to allow the use of an unvalidated user-controlled variable when executing a command.",
					fileName, model.SeverityHigh, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found && strings.Contains(codeLine, "$") {
			reporter.ReportIssue("PHP-CMDI-002", "Application Variable Used on System Command Line",
				"The application appears to allow the use of an unvalidated variable when executing a command. Carry out a manual check to determine whether the variable is user-controlled.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

// checkBackTick 检查反引号命令执行
func (c *PHPChecker) checkBackTick(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if rePHPBackTickSuper.MatchString(codeLine) {
		reporter.ReportIssue("PHP-CMDI-003", "User Controlled Variable Used on System Command Line",
			"The application appears to allow the use of a HTTP request variable within backticks, allowing commandline execution.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if rePHPBackTickVar.MatchString(codeLine) {
		found := false
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("PHP-CMDI-003", "User Controlled Variable Used on System Command Line",
					"The application appears to allow the use of a user-controlled variable within backticks, allowing commandline execution.",
					fileName, model.SeverityHigh, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found {
			reporter.ReportIssue("PHP-CMDI-004", "Application Variable Used on System Command Line",
				"The application appears to allow the use of a variable within backticks, allowing commandline execution. Carry out a manual check to determine whether the variable is user-controlled.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

// checkRegisterGlobals 检查 register_globals
func (c *PHPChecker) checkRegisterGlobals(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.PHP.HasRegisterGlobals {
		return
	}

	if rePHPRegGlobals.MatchString(codeLine) {
		reporter.ReportIssue("PHP-CONF-001", "Use of 'register_globals'",
			"The application appears to re-activate the use of the dangerous 'register_globals' facility. Anything passed via GET or POST or COOKIE is automatically assigned as a global variable in the code, with potentially serious consequences.",
			fileName, model.SeverityCritical, codeLine, lineNumber)
	} else if rePHPArrayMerge.MatchString(codeLine) {
		reporter.ReportIssue("PHP-CONF-002", "Indiscriminate Merging of Input Variables",
			"The application appears to incorporate all incoming GET and POST data into a single array. This can facilitate GET to POST conversion and may result in unexpected behaviour.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

// checkParseStr 检查 parse_str 使用
func (c *PHPChecker) checkParseStr(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if rePHPParseStr.MatchString(codeLine) {
		found := false
		for _, v := range tracker.CSharp.InputVariables {
			if strings.Contains(codeLine, v) {
				reporter.ReportIssue("PHP-CONF-003", "Use of 'parse_str' with User Controlled Variable",
					"The application appears to use parse_str in an unsafe manner in combination with a user-controlled variable. Anything passed as part of the input string is automatically assigned as a global variable.",
					fileName, model.SeverityCritical, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found {
			reporter.ReportIssue("PHP-CONF-003", "Use of 'parse_str'",
				"The application appears to use parse_str in an unsafe manner. Anything passed as part of the input string is automatically assigned as a global variable. Carry out a manual check to determine whether the variable is user-controlled.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

// checkPhpIni 检查 php.ini 配置
func (c *PHPChecker) checkPhpIni(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	trimmed := strings.TrimSpace(codeLine)
	if strings.HasPrefix(trimmed, ";") || trimmed == "" {
		return
	}

	if rePHPIniRegGlob.MatchString(codeLine) {
		reporter.ReportIssue("PHP-CONF-004", "Use of 'register_globals'",
			"The application appears to activate the use of the dangerous 'register_globals' facility. Anything passed via GET or POST or COOKIE is automatically assigned as a global variable in the code.",
			fileName, model.SeverityCritical, codeLine, lineNumber)
	} else if rePHPIniSafeMode.MatchString(codeLine) {
		reporter.ReportIssue("PHP-CONF-005", "De-Activation of 'safe_mode'",
			"The application appears to de-activate the use of 'safe_mode', which can increase risks for any CGI-based applications.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	} else if rePHPIniMagic.MatchString(codeLine) {
		reporter.ReportIssue("PHP-CONF-006", "De-Activation of 'magic_quotes'",
			"The application appears to de-activate the use of 'magic_quotes', greatly increasing the risk of SQL injection.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if rePHPIniDisable.MatchString(codeLine) {
		tracker.PHP.HasDisableFunctions = true
	} else if rePHPIniMySQLRoot.MatchString(codeLine) {
		reporter.ReportIssue("PHP-CONF-007", "Log in to MySQL as 'root'",
			"The application appears to log in to MySQL as 'root', greatly increasing the consequences of a successful SQL injection attack.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

// addInputVar 添加输入变量
func (c *PHPChecker) addInputVar(varName string, tracker *model.CodeTracker) {
	if varName == "" {
		return
	}
	for _, v := range tracker.CSharp.InputVariables {
		if v == varName {
			return
		}
	}
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, varName)
}

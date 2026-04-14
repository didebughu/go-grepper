package checker

import (
	"regexp"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// PLSQLChecker PL/SQL 安全检查器（对应原 modPlSqlCheck）
type PLSQLChecker struct{}

func (c *PLSQLChecker) Language() int { return config.LangSQL }

// 预编译正则表达式
var (
	// CheckCrypto
	rePLSQLSQLKeyword = regexp.MustCompile(`(?i)('|")\s*(SELECT|UPDATE|DELETE|INSERT|MERGE|CREATE|SAVEPOINT|ROLLBACK|DROP)`)
	rePLSQLProcedure  = regexp.MustCompile(`\bPROCEDURE\b\s+\w+`)
	rePLSQLInParam    = regexp.MustCompile(`\w+\s+\bIN\b`)

	// CheckSqlInjection
	rePLSQLVarConcat = regexp.MustCompile(`('|")\s*\|\|\s*\w+`)
	rePLSQLConcatVar = regexp.MustCompile(`\w+\s*\|\|\s*('|")`)
	rePLSQLSQLVar    = regexp.MustCompile(`(?i)(SQL|QRY|QUERY)\w*\s*:=`)
	rePLSQLAssignEnd = regexp.MustCompile(`:=\s*$`)

	// CheckPrivs
	rePLSQLAuthCurrent = regexp.MustCompile(`\bAUTHID\b\s+\bCURRENT_USER\b`)
	rePLSQLAuthDefiner = regexp.MustCompile(`\bAUTHID\b\s+\bDEFINER\b`)
	rePLSQLAsIs        = regexp.MustCompile(`\b(AS|IS)\b`)

	// CheckViewFormat
	rePLSQLViewCreate = regexp.MustCompile(`CREATE OR REPLACE VIEW`)
)

func (c *PLSQLChecker) CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	c.checkCrypto(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkSqlInjection(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkPrivs(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkTransControl(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkErrorHandling(codeLine, fileName, lineNumber, reporter)
	c.checkViewFormat(codeLine, fileName, lineNumber, tracker, reporter)
}

func (c *PLSQLChecker) CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter) {
	// 检查是否使用了 Oracle 加密
	if !tracker.PLSQL.HasOracleEncrypt && strings.Contains(strings.ToUpper(fileName), "PASSWORD") {
		reporter.ReportIssue("PLSQL-CRYPTO-002", "Code Appears to Process Passwords Without Encryption",
			"The file name suggests password processing but no Oracle encryption module usage was detected.",
			fileName, model.SeverityHigh, "", 0)
	}
}

// checkCrypto 检查 Oracle 加密
func (c *PLSQLChecker) checkCrypto(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	// 不检查 SQL*Plus 文件
	if strings.HasSuffix(fileName, ".sql") {
		return
	}

	if !tracker.PLSQL.HasOracleEncrypt && (strings.Contains(codeLine, "DBMS_CRYPTO") || strings.Contains(codeLine, "DBMS_OBFUSCATION_TOOLKIT")) {
		tracker.PLSQL.HasOracleEncrypt = true
	}
	if !tracker.PLSQL.HasOracleEncrypt && strings.Contains(codeLine, "PASSWORD") && !strings.Contains(codeLine, "ACCEPT") {
		reporter.ReportIssue("PLSQL-CRYPTO-001", "Code Appears to Process Passwords Without the Use of a Standard Oracle Encryption Module",
			"The code contains references to 'password'. The absence of any hashing or decryption functions indicates that the password may be stored as plaintext.",
			fileName, model.SeverityHigh, "", lineNumber)
	}
}

// checkSqlInjection 检查 SQL 注入
func (c *PLSQLChecker) checkSqlInjection(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	// 跟踪过程参数
	if rePLSQLProcedure.MatchString(codeLine) {
		// 标记进入过程声明
	}

	if rePLSQLInParam.MatchString(codeLine) {
		parts := regexp.MustCompile(`\bIN\b`).Split(codeLine, 2)
		varName := util.GetLastItem(parts[0], " ")
		if varName != "" {
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

	// 跟踪 SQL 变量赋值
	if strings.Contains(codeLine, ":=") && rePLSQLSQLKeyword.MatchString(codeLine) {
		parts := strings.SplitN(codeLine, ":", 2)
		varName := strings.TrimSpace(parts[0])
		if varName != "" {
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
	} else if rePLSQLSQLVar.MatchString(codeLine) {
		parts := strings.SplitN(codeLine, ":", 2)
		varName := strings.TrimSpace(parts[0])
		if varName != "" {
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

	// 检查 EXECUTE IMMEDIATE 和 OPEN FOR
	if strings.Contains(codeLine, "EXECUTE IMMEDIATE") || strings.Contains(codeLine, "OPEN FOR") {
		if rePLSQLVarConcat.MatchString(codeLine) || rePLSQLConcatVar.MatchString(codeLine) {
			reporter.ReportIssue("PLSQL-SQLI-001", "Variable concatenated with dynamic SQL statement.",
				"Statement is potentially vulnerable to SQL injection, depending on the origin of input variables and opportunities for an attacker to modify them before they reach the procedure.",
				fileName, model.SeverityCritical, codeLine, lineNumber)
		} else if !strings.Contains(codeLine, "'") && !strings.Contains(codeLine, "\"") {
			for _, sqlVar := range tracker.SQLStatements {
				if strings.Contains(codeLine, sqlVar) {
					reporter.ReportIssue("PLSQL-SQLI-002", "Potential SQL Injection",
						"The application appears to allow SQL injection through use of an input variable within a query, depending on the origin of input variables.",
						fileName, model.SeverityCritical, codeLine, lineNumber)
					break
				}
			}
		}
	}
}

// checkPrivs 检查权限分配
func (c *PLSQLChecker) checkPrivs(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if !tracker.PLSQL.IsAutonomous && (strings.Contains(codeLine, "CREATE OR REPLACE PACKAGE BODY") || strings.Contains(codeLine, "CREATE PACKAGE BODY")) {
		tracker.PLSQL.IsAutonomous = false // 复用标记新包
		tracker.PLSQL.InView = true        // 复用标记新包状态
	}

	if tracker.PLSQL.InView {
		if rePLSQLAuthCurrent.MatchString(codeLine) {
			tracker.PLSQL.InView = false
		} else if rePLSQLAuthDefiner.MatchString(codeLine) {
			reporter.ReportIssue("PLSQL-PRIV-001", "Package Running Under Potentially Excessive Permissions",
				"The use of AUTHID DEFINER allows a user to run functions from this package in the role of the definer (usually a developer or administrator).",
				fileName, model.SeverityStandard, codeLine, lineNumber)
			tracker.PLSQL.InView = false
		} else if rePLSQLAsIs.MatchString(codeLine) {
			reporter.ReportIssue("PLSQL-PRIV-002", "Package Running Under Potentially Excessive Permissions",
				"The failure to use AUTHID CURRENT_USER allows a user to run functions from this package in the role of the definer (usually a developer or administrator).",
				fileName, model.SeverityStandard, "1", lineNumber)
			tracker.PLSQL.InView = false
		}
	}
}

// checkTransControl 检查事务控制
func (c *PLSQLChecker) checkTransControl(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if strings.HasSuffix(fileName, ".sql") {
		return
	}

	if strings.Contains(codeLine, "PRAGMA AUTONOMOUS_TRANSACTION") {
		tracker.PLSQL.IsAutonomous = true
	}

	if !tracker.PLSQL.IsAutonomous && (strings.Contains(codeLine, "COMMIT") || strings.Contains(codeLine, "ROLLBACK")) {
		reporter.ReportIssue("PLSQL-RESRC-001", "Stored Procedure Contains COMMIT and/or ROLLBACK Without PRAGMA AUTONOMOUS_TRANSACTION",
			"This can result in data corruption, since rolling back or committing will split a wider logical transaction into two possibly conflicting sub-transactions.",
			fileName, model.SeverityLow, "", lineNumber)
	}
}

// checkErrorHandling 检查错误处理
func (c *PLSQLChecker) checkErrorHandling(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if strings.Contains(codeLine, "ERROR") && strings.Contains(codeLine, "OUT") && strings.Contains(codeLine, "NUMBER") {
		reporter.ReportIssue("PLSQL-MISC-001", "Error Handling With Output Parameters",
			"The code appears to use output parameter(s) which implicitly signal an error by returning a special value, rather than raising an exception. This can make code harder to maintain and more error prone.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkViewFormat 检查视图中的数据格式化
func (c *PLSQLChecker) checkViewFormat(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if rePLSQLViewCreate.MatchString(codeLine) {
		tracker.PLSQL.InView = true
	}

	if tracker.PLSQL.InView {
		if strings.Contains(codeLine, "TO_CHAR") || strings.Contains(codeLine, "TRIM(") ||
			strings.Contains(codeLine, "TO_NUMBER") || strings.Contains(codeLine, "UPPER(") ||
			strings.Contains(codeLine, "LOWER(") {
			reporter.ReportIssue("PLSQL-MISC-002", "Data Formatting Within VIEW",
				"This can result in performance issues and can facilitate DoS attacks. There is also a possibility of data corruption due to mismatch between views and underlying tables.",
				fileName, model.SeverityStandard, codeLine, lineNumber)
		}
	}
}

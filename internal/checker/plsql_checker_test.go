package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/model"
)

// ==================== checkCrypto 测试 ====================

func TestPLSQL_CheckCrypto_PasswordWithoutEncryption(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCrypto("  IF PASSWORD = 'admin' THEN", "test.pks", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Passwords Without the Use of a Standard Oracle Encryption") {
		t.Errorf("应检测到未加密的密码处理，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckCrypto_PasswordWithDBMSCrypto(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 先设置加密标记
	checker.checkCrypto("  DBMS_CRYPTO.ENCRYPT(data, key);", "test.pks", 5, tracker, reporter)
	reporter.Issues = nil // 清空之前的报告

	// 再检查密码行，不应报告
	checker.checkCrypto("  IF PASSWORD = 'admin' THEN", "test.pks", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("使用了 DBMS_CRYPTO 后不应报告密码问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckCrypto_PasswordWithObfuscationToolkit(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCrypto("  DBMS_OBFUSCATION_TOOLKIT.DES3Encrypt(input);", "test.pks", 5, tracker, reporter)
	reporter.Issues = nil

	checker.checkCrypto("  IF PASSWORD = 'admin' THEN", "test.pks", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("使用了 DBMS_OBFUSCATION_TOOLKIT 后不应报告密码问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckCrypto_SkipSQLFile(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCrypto("  IF PASSWORD = 'admin' THEN", "test.sql", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf(".sql 文件不应检查加密，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckCrypto_PasswordWithACCEPT(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCrypto("  ACCEPT PASSWORD PROMPT 'Enter password:'", "test.pks", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("包含 ACCEPT 的行不应报告密码问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSqlInjection 测试 ====================

func TestPLSQL_CheckSqlInjection_ExecuteImmediateWithConcat(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSqlInjection(`  EXECUTE IMMEDIATE 'SELECT * FROM users WHERE id=' || user_id;`, "test.pks", 20, tracker, reporter)

	if !reporter.hasIssueWithTitle("Variable concatenated with dynamic SQL") {
		t.Errorf("应检测到 EXECUTE IMMEDIATE 中的变量拼接，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityCritical) {
		t.Errorf("SQL 注入应为 Critical 级别")
	}
}

func TestPLSQL_CheckSqlInjection_OpenForWithConcat(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSqlInjection(`  OPEN FOR 'SELECT * FROM t WHERE id=' || param;`, "test.pks", 20, tracker, reporter)

	if !reporter.hasIssueWithTitle("Variable concatenated with dynamic SQL") {
		t.Errorf("应检测到 OPEN FOR 中的变量拼接，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckSqlInjection_ExecuteImmediateWithTrackedVar(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 先跟踪 SQL 变量
	checker.checkSqlInjection(`  sqlStmt := 'SELECT * FROM users WHERE id=' || user_id;`, "test.pks", 10, tracker, reporter)
	reporter.Issues = nil

	// 然后在 EXECUTE IMMEDIATE 中使用
	checker.checkSqlInjection(`  EXECUTE IMMEDIATE sqlStmt;`, "test.pks", 20, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到使用跟踪变量的 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckSqlInjection_SQLVarTracking(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 跟踪 SQL 变量名
	checker.checkSqlInjection(`  sqlQuery := 'SELECT * FROM users';`, "test.pks", 10, tracker, reporter)

	if len(tracker.SQLStatements) == 0 {
		t.Errorf("应跟踪 SQL 变量名 sqlQuery")
	}
}

func TestPLSQL_CheckSqlInjection_INParamTracking(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSqlInjection(`  p_user_id IN NUMBER`, "test.pks", 5, tracker, reporter)

	found := false
	for _, s := range tracker.SQLStatements {
		if s == "p_user_id" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("应跟踪 IN 参数 p_user_id，当前跟踪列表: %v", tracker.SQLStatements)
	}
}

func TestPLSQL_CheckSqlInjection_SafeExecuteImmediate(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSqlInjection(`  EXECUTE IMMEDIATE 'DROP TABLE temp_table';`, "test.pks", 20, tracker, reporter)

	if reporter.hasIssueWithTitle("SQL Injection") {
		t.Errorf("使用字面量的 EXECUTE IMMEDIATE 不应报告 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkPrivs 测试 ====================

func TestPLSQL_CheckPrivs_AuthidDefiner(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 进入包体
	checker.checkPrivs("CREATE OR REPLACE PACKAGE BODY my_pkg AS", "test.pks", 1, tracker, reporter)
	// AUTHID DEFINER
	checker.checkPrivs("  AUTHID DEFINER", "test.pks", 2, tracker, reporter)

	if !reporter.hasIssueWithTitle("Excessive Permissions") {
		t.Errorf("应检测到 AUTHID DEFINER 的权限问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckPrivs_AuthidCurrentUser(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 先进入包体状态
	checker.checkPrivs("CREATE OR REPLACE PACKAGE BODY my_pkg", "test.pks", 1, tracker, reporter)
	// 然后设置 AUTHID CURRENT_USER，不应报告问题
	checker.checkPrivs("  AUTHID CURRENT_USER", "test.pks", 2, tracker, reporter)

	// 只检查是否有 "Excessive Permissions" 相关的问题
	hasExcessivePerms := false
	for _, issue := range reporter.Issues {
		if issue.LineNumber == 2 {
			hasExcessivePerms = true
		}
	}
	if hasExcessivePerms {
		t.Errorf("AUTHID CURRENT_USER 行不应报告权限问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckPrivs_NoAuthid(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkPrivs("CREATE OR REPLACE PACKAGE BODY my_pkg AS", "test.pks", 1, tracker, reporter)
	// 直接遇到 AS/IS 而没有 AUTHID
	checker.checkPrivs("  IS", "test.pks", 2, tracker, reporter)

	if !reporter.hasIssueWithTitle("Excessive Permissions") {
		t.Errorf("缺少 AUTHID 应报告权限问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkTransControl 测试 ====================

func TestPLSQL_CheckTransControl_CommitWithoutPragma(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkTransControl("  COMMIT;", "test.pks", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("COMMIT and/or ROLLBACK Without PRAGMA AUTONOMOUS_TRANSACTION") {
		t.Errorf("应检测到没有 PRAGMA 的 COMMIT，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckTransControl_RollbackWithoutPragma(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkTransControl("  ROLLBACK;", "test.pks", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("COMMIT and/or ROLLBACK Without PRAGMA AUTONOMOUS_TRANSACTION") {
		t.Errorf("应检测到没有 PRAGMA 的 ROLLBACK，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckTransControl_CommitWithPragma(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkTransControl("  PRAGMA AUTONOMOUS_TRANSACTION;", "test.pks", 5, tracker, reporter)
	reporter.Issues = nil
	checker.checkTransControl("  COMMIT;", "test.pks", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("有 PRAGMA 后 COMMIT 不应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckTransControl_SkipSQLFile(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkTransControl("  COMMIT;", "test.sql", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf(".sql 文件不应检查事务控制，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkErrorHandling 测试 ====================

func TestPLSQL_CheckErrorHandling_ErrorOutNumber(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()

	checker.checkErrorHandling("  p_ERROR_code OUT NUMBER", "test.pks", 10, reporter)

	if !reporter.hasIssueWithTitle("Error Handling With Output Parameters") {
		t.Errorf("应检测到使用输出参数的错误处理，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckErrorHandling_NoMatch(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()

	checker.checkErrorHandling("  p_result OUT VARCHAR2", "test.pks", 10, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("不包含 ERROR+OUT+NUMBER 的行不应报告，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkViewFormat 测试 ====================

func TestPLSQL_CheckViewFormat_ToCharInView(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkViewFormat("CREATE OR REPLACE VIEW my_view AS", "test.pks", 1, tracker, reporter)
	checker.checkViewFormat("  SELECT TO_CHAR(date_col, 'YYYY-MM-DD') FROM t", "test.pks", 2, tracker, reporter)

	if !reporter.hasIssueWithTitle("Data Formatting Within VIEW") {
		t.Errorf("应检测到视图中的数据格式化，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckViewFormat_TrimInView(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkViewFormat("CREATE OR REPLACE VIEW my_view AS", "test.pks", 1, tracker, reporter)
	checker.checkViewFormat("  SELECT TRIM(name) FROM t", "test.pks", 2, tracker, reporter)

	if !reporter.hasIssueWithTitle("Data Formatting Within VIEW") {
		t.Errorf("应检测到视图中的 TRIM 格式化，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckViewFormat_UpperInView(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkViewFormat("CREATE OR REPLACE VIEW my_view AS", "test.pks", 1, tracker, reporter)
	checker.checkViewFormat("  SELECT UPPER(name) FROM t", "test.pks", 2, tracker, reporter)

	if !reporter.hasIssueWithTitle("Data Formatting Within VIEW") {
		t.Errorf("应检测到视图中的 UPPER 格式化，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_CheckViewFormat_NotInView(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 不在视图中
	checker.checkViewFormat("  SELECT TO_CHAR(date_col, 'YYYY-MM-DD') FROM t", "test.pks", 2, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("不在视图中不应报告格式化问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckFileLevelIssues 测试 ====================

func TestPLSQL_FileLevelIssues_PasswordFileWithoutEncryption(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.CheckFileLevelIssues("PASSWORD_MANAGER.pks", tracker, reporter)

	if !reporter.hasIssueWithTitle("Passwords Without Encryption") {
		t.Errorf("密码相关文件名但无加密应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPLSQL_FileLevelIssues_PasswordFileWithEncryption(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.PLSQL.HasOracleEncrypt = true

	checker.CheckFileLevelIssues("PASSWORD_MANAGER.pks", tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("有加密的密码文件不应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckCode 集成测试 ====================

func TestPLSQL_CheckCode_Integration(t *testing.T) {
	checker := &PLSQLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	lines := []string{
		"CREATE OR REPLACE PACKAGE BODY my_pkg AS",
		"  IS",
		"  PROCEDURE process_user(p_user_id IN NUMBER) IS",
		"    sqlStmt VARCHAR2(200);",
		"  BEGIN",
		"    sqlStmt := 'SELECT * FROM users WHERE id=' || p_user_id;",
		"    EXECUTE IMMEDIATE sqlStmt;",
		"    COMMIT;",
		"  END;",
	}

	for i, line := range lines {
		checker.CheckCode(line, "test.pks", i+1, tracker, reporter)
	}

	if len(reporter.Issues) == 0 {
		t.Errorf("集成测试应检测到多个问题")
	}

	// 应至少检测到权限问题和事务控制问题
	if !reporter.hasIssueWithTitle("Excessive Permissions") {
		t.Errorf("应检测到权限问题，实际报告: %s", reporter.dumpIssues())
	}
}

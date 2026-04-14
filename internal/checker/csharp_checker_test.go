package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/model"
)

// ==================== checkInputValidation 测试 ====================

func TestCSharp_CheckInputValidation_ValidateRequestFalse(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkInputValidation(`<pages validateRequest="false" />`, "web.config", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Input Validation") {
		t.Errorf("应检测到关闭输入验证，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckInputValidation_ValidateRequestTrue(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkInputValidation(`<pages validateRequest="true" />`, "web.config", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("开启输入验证不应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSQLInjection 测试 ====================

func TestCSharp_CheckSQLi_DynamicSQL(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLInjection(`  cmd = new SqlCommand("SELECT * FROM users WHERE id=" & userId);`, "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到动态 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityCritical) {
		t.Errorf("SQL 注入应为 Critical 级别")
	}
}

func TestCSharp_CheckSQLi_PreparedDynamic(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLInjection(`  String sql = "SELECT * FROM users WHERE id=" & userId;`, "Test.cs", 5, tracker, reporter)
	reporter.Issues = nil

	checker.checkSQLInjection(`  cmd = new SqlCommand(sql);`, "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到预准备的动态 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckSQLi_WithValidator(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.HasValidator = true

	checker.checkSQLInjection(`  cmd = new SqlCommand("SELECT * FROM users WHERE id=" & userId);`, "Test.cs", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("有验证器时不应报告 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkXSS 测试 ====================

func TestCSharp_CheckXSS_ResponseWriteRequestForm(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSS(`  Response.Write(Request.Form("name"));`, "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential XSS") {
		t.Errorf("应检测到 XSS，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckXSS_HtmlRaw(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSS(`  @Html.Raw(someVar)`, "Test.cshtml", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential XSS") {
		t.Errorf("应检测到 Html.Raw 的 XSS，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckXSS_HtmlRawWithUserVar(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "userInput")

	checker.checkXSS(`  @Html.Raw(userInput)`, "Test.cshtml", 10, tracker, reporter)

	if !reporter.hasIssueWithSeverity(model.SeverityHigh) {
		t.Errorf("用户变量的 Html.Raw 应为 High 级别，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckXSS_ResponseWriteWithUserVar(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "userInput")

	checker.checkXSS(`  Response.Write(userInput);`, "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential XSS") {
		t.Errorf("应检测到用户变量的 XSS，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityHigh) {
		t.Errorf("用户变量的 XSS 应为 High 级别")
	}
}

// ==================== checkSecureStorage 测试 ====================

func TestCSharp_CheckSecureStorage_StringPassword(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkSecureStorage("  String userPassword = GetPassword();", "Test.cs", 10, reporter)

	if !reporter.hasIssueWithTitle("Insecure Storage") {
		t.Errorf("应检测到不安全的密码存储，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckSecureStorage_CharArrayKey(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkSecureStorage("  char[] cryptokey = new char[32];", "Test.cs", 10, reporter)

	if !reporter.hasIssueWithTitle("Insecure Storage") {
		t.Errorf("应检测到不安全的密钥存储，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkIntOverflow 测试 ====================

func TestCSharp_CheckIntOverflow_UncheckedOperation(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkIntOverflow("  int result = unchecked (a + b);", "Test.cs", 10, reporter)

	if !reporter.hasIssueWithTitle("Overflow Check Deliberately Disabled") {
		t.Errorf("应检测到禁用溢出检查，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckIntOverflow_NoCheck(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkIntOverflow("  int result = a + b;", "Test.cs", 10, reporter)

	if !reporter.hasIssueWithTitle("Without Overflow Check") {
		t.Errorf("应检测到无溢出检查的整数运算，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckIntOverflow_Checked(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkIntOverflow("  int result = checked (a + b);", "Test.cs", 10, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("使用 checked 不应报告溢出问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkFileRace 测试 ====================

func TestCSharp_CheckFileRace_TOCTOU(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileRace("  if (File.Exists(path)) {", "Test.cs", 10, tracker, reporter)
	checker.checkFileRace("    Process.Start(path);", "Test.cs", 11, tracker, reporter)

	if !reporter.hasIssueWithTitle("TOCTOU") {
		t.Errorf("应检测到 TOCTOU 竞态条件，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkHTTPRedirect 测试 ====================

func TestCSharp_CheckHTTPRedirect_HTTP(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkHTTPRedirect(`  Response.Redirect("HTTP://example.com");`, "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("URL request sent over HTTP") {
		t.Errorf("应检测到 HTTP 重定向，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckHTTPRedirect_VariableURL(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkHTTPRedirect("  Response.Redirect(redirectUrl);", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("URL Request Gets Path from Variable") {
		t.Errorf("应检测到变量 URL 重定向，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckHTTPRedirect_UserControlledURL(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "userUrl")

	checker.checkHTTPRedirect("  Response.Redirect(userUrl);", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unvalidated Variable") {
		t.Errorf("应检测到用户控制的 URL 重定向，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkRandomisation 测试 ====================

func TestCSharp_CheckRandomisation_RandomNext(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRandomisation("  int val = Random.Next(100);", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("应检测到伪随机数使用，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckRandomisation_RandomNextBytes(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRandomisation("  Random.NextBytes(buffer);", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("应检测到 NextBytes 伪随机数使用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUnsafeTempFiles 测试 ====================

func TestCSharp_CheckUnsafeTempFiles_FileOpen(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkUnsafeTempFiles(`  fs = File.Open("C:\temp\data.dat",`, "Test.cs", 10, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Temporary File") {
		t.Errorf("应检测到不安全的临时文件，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUnsafeCode 测试 ====================

func TestCSharp_CheckUnsafeCode_UnsafeBlock(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkUnsafeCode("  unsafe {", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Code Directive") {
		t.Errorf("应检测到 unsafe 代码指令，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkExecutable 测试 ====================

func TestCSharp_CheckExecutable_ProcessStartWithUserVar(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "userCmd")

	checker.checkExecutable("  new System.Diagnostics.ProcessStartInfo(userCmd);", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("User Controlled Variable Used on System Command Line") {
		t.Errorf("应检测到用户控制变量的命令执行，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckExecutable_ProcessStartWithVariable(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkExecutable("  new System.Diagnostics.ProcessStartInfo(cmd);", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Application Variable Used on System Command Line") {
		t.Errorf("应检测到变量的命令执行，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkWebConfig 测试 ====================

func TestCSharp_CheckWebConfig_CustomErrorsOff(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkWebConfig(`  <customErrors mode="Off"/>`, "web.config", 10, reporter)

	if !reporter.hasIssueWithTitle("Default Errors Enabled") {
		t.Errorf("应检测到默认错误启用，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckWebConfig_DebugTrue(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkWebConfig(`  <compilation debug="true" />`, "web.config", 10, reporter)

	if !reporter.hasIssueWithTitle("Debugging Enabled") {
		t.Errorf("应检测到调试启用，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckWebConfig_NotWebConfig(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()

	checker.checkWebConfig(`  <customErrors mode="Off"/>`, "Test.cs", 10, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("非 web.config 文件不应检查配置，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkLogDisplay 测试 ====================

func TestCSharp_CheckLogDisplay_LogPassword(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkLogDisplay("  Logger.Info(\"User password: \" + password);", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Log User Passwords") {
		t.Errorf("应检测到日志记录密码，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCSharp_CheckLogDisplay_LogUnsanitizedInput(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "userInput")

	checker.checkLogDisplay("  Logger.Info(userInput);", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsanitized Data Written to Logs") {
		t.Errorf("应检测到未清理数据写入日志，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== 密码管理测试 ====================

func TestCSharp_PasswordCase_ToLower(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.CheckCode("  if (Password.ToLower() == input) {", "Test.cs", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Password Management") {
		t.Errorf("应检测到不安全的密码管理，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckCode 集成测试 ====================

func TestCSharp_CheckCode_Integration(t *testing.T) {
	checker := &CSharpChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	lines := []string{
		`  String userPassword = GetPassword();`,
		`  int result = a + b;`,
		`  unsafe {`,
		`    int* ptr = &result;`,
		`  }`,
	}

	for i, line := range lines {
		checker.CheckCode(line, "Test.cs", i+1, tracker, reporter)
	}

	if len(reporter.Issues) == 0 {
		t.Errorf("集成测试应检测到多个问题")
	}
}

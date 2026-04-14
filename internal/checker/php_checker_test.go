package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/model"
)

// ==================== checkSQLInjection 测试 ====================

func TestPHP_CheckSQLi_MysqlQueryWithVar(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLInjection(`  mysql_query("SELECT * FROM users WHERE id=$userId");`, "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityCritical) {
		t.Errorf("SQL 注入应为 Critical 级别")
	}
}

func TestPHP_CheckSQLi_WithEscapeString(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLInjection(`  mysql_query("SELECT * FROM users WHERE id=" . mysql_real_escape_string($userId));`, "test.php", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("SQL Injection") {
		t.Errorf("使用 mysql_real_escape_string 不应报告 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckSQLi_PreparedDynamic(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLInjection(`  $sql = "SELECT * FROM users WHERE id=" . $userId;`, "test.php", 5, tracker, reporter)
	reporter.Issues = nil

	checker.checkSQLInjection(`  mysql_query($sql);`, "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到预准备的动态 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkXSS 测试 ====================

func TestPHP_CheckXSS_EchoSuperGlobal(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSS(`  echo $_GET["name"];`, "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential XSS") {
		t.Errorf("应检测到直接输出超全局变量的 XSS，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckXSS_PrintSuperGlobal(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSS(`  print $_POST["data"];`, "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential XSS") {
		t.Errorf("应检测到 print 超全局变量的 XSS，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckXSS_WithStripTags(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSS(`  echo strip_tags($_GET["name"]);`, "test.php", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("XSS") {
		t.Errorf("使用 strip_tags 不应报告 XSS，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckXSS_DOMBasedXSS(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSS(`  ).innerHTML = '<? echo $_GET["name"] ?>`, "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("DOM-Based XSS") {
		t.Errorf("应检测到 DOM-Based XSS，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckXSS_SuperGlobalTracking(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSS(`  $name = $_GET["name"];`, "test.php", 5, tracker, reporter)

	if len(tracker.CSharp.InputVariables) == 0 {
		t.Errorf("应跟踪超全局变量赋值")
	}
}

// ==================== checkRandomisation 测试 ====================

func TestPHP_CheckRandomisation_MtRandEmpty(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()

	checker.checkRandomisation("  $val = mt_rand();", "test.php", 10, reporter)

	if !reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("应检测到无种子的 mt_rand，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckRandomisation_MtRandWithTimeSeed(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()

	checker.checkRandomisation("  mt_rand(time())", "test.php", 10, reporter)

	if !reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("应检测到时间种子的 mt_rand，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckRandomisation_OpenSSLFalse(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()

	checker.checkRandomisation("  $bytes = openssl_random_pseudo_bytes(16, false);", "test.php", 10, reporter)

	if !reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("应检测到 openssl secure=false，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkFileValidation 测试 ====================

func TestPHP_CheckFileValidation_FilesArray(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()

	checker.checkFileValidation(`  if ($_FILES["file"]["size"] > 0) {`, "test.php", 10, reporter)

	if !reporter.hasIssueWithTitle("$_FILES Array") {
		t.Errorf("应检测到 $_FILES 数组使用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkFileInclusion 测试 ====================

func TestPHP_CheckFileInclusion_IncludeVariable(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileInclusion("  include($page);", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Variable Used as FileName") {
		t.Errorf("应检测到变量文件包含，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckFileInclusion_IncludeUserVar(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "$page")

	checker.checkFileInclusion("  include($page);", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("File Inclusion Vulnerability") {
		t.Errorf("应检测到用户控制的文件包含漏洞，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckFileInclusion_UnsafeExtension(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileInclusion(`  include('config.inc');`, "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("File Inclusion Vulnerability") {
		t.Errorf("应检测到不安全扩展名的文件包含，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckFileInclusion_FileAccessWithUserVar(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "$path")

	checker.checkFileInclusion("  fopen($path, 'r');", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("File Access Vulnerability") {
		t.Errorf("应检测到用户控制的文件访问漏洞，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkExecutable 测试 ====================

func TestPHP_CheckExecutable_ExecWithUserVar(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "$cmd")

	checker.checkExecutable("  exec($cmd);", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("User Controlled Variable Used on System Command Line") {
		t.Errorf("应检测到用户控制变量的命令执行，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckExecutable_SystemWithVar(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkExecutable("  system($command);", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Application Variable Used on System Command Line") {
		t.Errorf("应检测到变量的命令执行，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckExecutable_WithEscapeShellCmd(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkExecutable("  exec(escapeshellcmd($cmd));", "test.php", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("Command Line") {
		t.Errorf("使用 escapeshellcmd 不应报告命令执行问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkBackTick 测试 ====================

func TestPHP_CheckBackTick_SuperGlobal(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkBackTick("  `ls $_GET[\"dir\"]`", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("User Controlled Variable Used on System Command Line") {
		t.Errorf("应检测到反引号中的超全局变量，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckBackTick_Variable(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkBackTick("  `ls $dir`", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Application Variable Used on System Command Line") {
		t.Errorf("应检测到反引号中的变量，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkRegisterGlobals 测试 ====================

func TestPHP_CheckRegisterGlobals_IniSet(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRegisterGlobals(`  ini_set('register_globals', true);`, "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("register_globals") {
		t.Errorf("应检测到 register_globals 启用，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityCritical) {
		t.Errorf("register_globals 应为 Critical 级别")
	}
}

func TestPHP_CheckRegisterGlobals_ArrayMerge(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRegisterGlobals(`  $vars = array_merge($_GET, $_POST);`, "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Merging of Input Variables") {
		t.Errorf("应检测到输入变量合并，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkParseStr 测试 ====================

func TestPHP_CheckParseStr_WithUserVar(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CSharp.InputVariables = append(tracker.CSharp.InputVariables, "$input")

	checker.checkParseStr("  parse_str($input);", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("parse_str") {
		t.Errorf("应检测到 parse_str 使用，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityCritical) {
		t.Errorf("用户控制变量的 parse_str 应为 Critical 级别")
	}
}

func TestPHP_CheckParseStr_WithUnknownVar(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkParseStr("  parse_str($data);", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("parse_str") {
		t.Errorf("应检测到 parse_str 使用，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityMedium) {
		t.Errorf("未知变量的 parse_str 应为 Medium 级别")
	}
}

// ==================== checkPhpIni 测试 ====================

func TestPHP_CheckPhpIni_RegisterGlobalsOn(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkPhpIni("register_globals = on", "php.ini", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("register_globals") {
		t.Errorf("应检测到 php.ini 中的 register_globals，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckPhpIni_SafeModeOff(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkPhpIni("safe_mode = off", "php.ini", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("safe_mode") {
		t.Errorf("应检测到 safe_mode 关闭，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckPhpIni_MagicQuotesOff(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkPhpIni("magic_quotes_gpc = off", "php.ini", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("magic_quotes") {
		t.Errorf("应检测到 magic_quotes 关闭，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckPhpIni_MySQLRoot(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkPhpIni("mysql.default_user = root", "php.ini", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("MySQL as 'root'") {
		t.Errorf("应检测到 MySQL root 登录，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_CheckPhpIni_DisableFunctions(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkPhpIni("disable_functions = exec,system", "php.ini", 10, tracker, reporter)

	if !tracker.PHP.HasDisableFunctions {
		t.Errorf("应标记已禁用函数")
	}
}

func TestPHP_CheckPhpIni_Comment(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkPhpIni("; register_globals = on", "php.ini", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("注释行不应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckFileLevelIssues 测试 ====================

func TestPHP_FileLevelIssues_NoDisableFunctions(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.CheckFileLevelIssues("php.ini", tracker, reporter)

	if !reporter.hasIssueWithTitle("No Disabled Functions") {
		t.Errorf("应报告 php.ini 中没有禁用函数，实际报告: %s", reporter.dumpIssues())
	}
}

func TestPHP_FileLevelIssues_HasDisableFunctions(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.PHP.HasDisableFunctions = true

	checker.CheckFileLevelIssues("php.ini", tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("有禁用函数不应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== 密码管理测试 ====================

func TestPHP_PasswordCase_Strtolower(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.CheckCode("  $hash = strtolower($password);", "test.php", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Password Management") {
		t.Errorf("应检测到不安全的密码管理，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckCode 集成测试 ====================

func TestPHP_CheckCode_Integration(t *testing.T) {
	checker := &PHPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	lines := []string{
		`  $name = $_GET["name"];`,
		`  echo $name;`,
		`  mysql_query("SELECT * FROM users WHERE name=$name");`,
	}

	for i, line := range lines {
		checker.CheckCode(line, "test.php", i+1, tracker, reporter)
	}

	if len(reporter.Issues) == 0 {
		t.Errorf("集成测试应检测到多个问题")
	}
}

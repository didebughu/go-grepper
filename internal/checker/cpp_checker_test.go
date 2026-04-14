package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/model"
)

// ==================== trackVarAssignments 测试 ====================

func TestCPP_TrackVarAssignments_MallocFixed(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.trackVarAssignments("  char *buf = malloc(256);", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("malloc( ) Using Fixed Value") {
		t.Errorf("应检测到 malloc 使用固定值，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_TrackVarAssignments_MallocVariable(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.trackVarAssignments("  char *buf = malloc(sizeof(int) * n);", "test.c", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("malloc( ) Using Fixed Value") {
		t.Errorf("malloc 使用变量大小不应报告固定值问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_TrackVarAssignments_MallocTracking(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.trackVarAssignments("  char *ptr = malloc(100);", "test.c", 10, tracker, reporter)

	if _, ok := tracker.CPP.MemAssign["ptr"]; !ok {
		t.Errorf("应跟踪 malloc 分配的变量 ptr")
	}
}

func TestCPP_TrackVarAssignments_FreeRelease(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.trackVarAssignments("  char *ptr = malloc(100);", "test.c", 10, tracker, reporter)
	checker.trackVarAssignments("  free(ptr);", "test.c", 20, tracker, reporter)

	if _, ok := tracker.CPP.MemAssign["ptr"]; ok {
		t.Errorf("free 后应移除 ptr 的跟踪")
	}
}

func TestCPP_TrackVarAssignments_NewTracking(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.trackVarAssignments("  int *arr = new int[10];", "test.cpp", 10, tracker, reporter)

	if _, ok := tracker.CPP.MemAssign["arr"]; !ok {
		t.Errorf("应跟踪 new 分配的变量 arr")
	}
}

func TestCPP_TrackVarAssignments_DeleteRelease(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.trackVarAssignments("  int *arr = new int[10];", "test.cpp", 10, tracker, reporter)
	checker.trackVarAssignments("  delete(arr);", "test.cpp", 20, tracker, reporter)

	if _, ok := tracker.CPP.MemAssign["arr"]; ok {
		t.Errorf("delete 后应移除 arr 的跟踪")
	}
}

// ==================== trackUserVarAssignments 测试 ====================

func TestCPP_TrackUserVarAssignments_Argv(t *testing.T) {
	checker := &CPPChecker{}
	tracker := newTracker()

	checker.trackUserVarAssignments("  char *input = argv[1];", tracker)

	if len(tracker.CPP.UserVariables) == 0 {
		t.Errorf("应跟踪 argv 赋值的用户变量")
	}
}

func TestCPP_TrackUserVarAssignments_Getenv(t *testing.T) {
	checker := &CPPChecker{}
	tracker := newTracker()

	checker.trackUserVarAssignments("  char *path = getenv(\"PATH\");", tracker)

	if len(tracker.CPP.UserVariables) == 0 {
		t.Errorf("应跟踪 getenv 赋值的用户变量")
	}
}

// ==================== checkBuffer 测试 ====================

func TestCPP_CheckBuffer_StrcpyOverflow(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 先声明缓冲区
	checker.checkBuffer("  char buf[10];", "test.c", 5, tracker, reporter)
	// 然后使用 strcpy
	checker.checkBuffer("  strcpy(buf, input);", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential Buffer Overflow") {
		t.Errorf("应检测到潜在缓冲区溢出，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_CheckBuffer_SprintfOverflow(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkBuffer("  char dest[64];", "test.c", 5, tracker, reporter)
	checker.checkBuffer("  sprintf(dest, \"%s\", src);", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential Buffer Overflow") {
		t.Errorf("应检测到 sprintf 的潜在缓冲区溢出，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_CheckBuffer_MemcpyOverflow(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkBuffer("  BYTE data[32];", "test.c", 5, tracker, reporter)
	checker.checkBuffer("  memcpy(data, src, len);", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential Buffer Overflow") {
		t.Errorf("应检测到 memcpy 的潜在缓冲区溢出，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkDestructorThrow 测试 ====================

func TestCPP_CheckDestructorThrow_ThrowInDestructor(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkDestructorThrow("MyClass::~MyClass() {", "test.cpp", 10, tracker, reporter)
	checker.checkDestructorThrow("  throw std::runtime_error(\"error\");", "test.cpp", 11, tracker, reporter)

	if !reporter.hasIssueWithTitle("Exception Throw in Destructor") {
		t.Errorf("应检测到析构函数中的异常抛出，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_CheckDestructorThrow_NoThrow(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkDestructorThrow("MyClass::~MyClass() {", "test.cpp", 10, tracker, reporter)
	checker.checkDestructorThrow("  cleanup();", "test.cpp", 11, tracker, reporter)
	checker.checkDestructorThrow("}", "test.cpp", 12, tracker, reporter)

	if reporter.hasIssueWithTitle("Exception Throw in Destructor") {
		t.Errorf("没有 throw 不应报告析构函数异常问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkRace 测试 ====================

func TestCPP_CheckRace_TOCTOU(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRace("  stat(filename, &st);", "test.c", 10, tracker, reporter)
	checker.checkRace("  // some other code", "test.c", 11, tracker, reporter)
	checker.checkRace("  fp = fopen(filename, \"r\");", "test.c", 12, tracker, reporter)

	if !reporter.hasIssueWithTitle("TOCTOU") {
		t.Errorf("应检测到 TOCTOU 竞态条件，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_CheckRace_StatAndFopenSameLine(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRace("  lstat(filename, &st);", "test.c", 10, tracker, reporter)
	checker.checkRace("  fp = fopen(filename, \"r\");", "test.c", 11, tracker, reporter)

	// distance == 1, 不应报告
	if reporter.hasIssueWithTitle("TOCTOU") {
		t.Errorf("stat 和 fopen 相邻不应报告 TOCTOU，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkPrintF 测试 ====================

func TestCPP_CheckPrintF_FormatStringVuln(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()

	checker.checkPrintF("  printf(userInput)", "test.c", 10, reporter)

	if !reporter.hasIssueWithTitle("Format String Vulnerability") {
		t.Errorf("应检测到 printf 格式字符串漏洞，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_CheckPrintF_SafePrintf(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()

	checker.checkPrintF(`  printf("%s", userInput)`, "test.c", 10, reporter)

	if reporter.hasIssueWithTitle("Format String Vulnerability") {
		t.Errorf("使用格式字符串的 printf 不应报告漏洞，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUnsafeTempFiles 测试 ====================

func TestCPP_CheckUnsafeTempFiles_FopenTemp(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()

	checker.checkUnsafeTempFiles(`  fp = fopen("/tmp/myapp.dat", O_RDWR)`, "test.c", 10, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Temporary File") {
		t.Errorf("应检测到不安全的临时文件，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkReallocFailure 测试 ====================

func TestCPP_CheckReallocFailure_SamePointer(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkReallocFailure("  ptr = realloc(ptr, newsize);", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Dangerous Use of realloc") {
		t.Errorf("应检测到 realloc 源和目标相同的危险用法，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_CheckReallocFailure_DifferentPointer(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkReallocFailure("  newptr = realloc(ptr, newsize);", "test.c", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("Dangerous Use of realloc") {
		t.Errorf("realloc 源和目标不同不应报告，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUnsafeSafe 测试 ====================

func TestCPP_CheckUnsafeSafe_SnprintfAssign(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()

	checker.checkUnsafeSafe("  len = snprintf(buf, sizeof(buf), \"%s\", str);", "test.c", 10, reporter)

	if !reporter.hasIssueWithTitle("Potential Misuse of Safe Function") {
		t.Errorf("应检测到安全函数返回值的潜在误用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkCmdInjection 测试 ====================

func TestCPP_CheckCmdInjection_SystemWithUserVar(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CPP.UserVariables = append(tracker.CPP.UserVariables, "userCmd")

	checker.checkCmdInjection("  system(userCmd);", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("User Controlled Variable Used on System Command Line") {
		t.Errorf("应检测到用户控制变量的命令注入，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityHigh) {
		t.Errorf("用户控制变量的命令注入应为 High 级别")
	}
}

func TestCPP_CheckCmdInjection_SystemWithGetenv(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCmdInjection("  system(getenv(\"SHELL\"));", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Application Variable Used on System Command Line") {
		t.Errorf("应检测到 getenv 的命令注入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_CheckCmdInjection_SystemWithStrcat(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCmdInjection("  system(strcat(cmd, arg));", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Application Variable Used on System Command Line") {
		t.Errorf("应检测到 strcat 的命令注入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCPP_CheckCmdInjection_SafeSystemCall(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCmdInjection("  system(\"ls -la\");", "test.c", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("User Controlled Variable") {
		t.Errorf("使用字面量的 system 调用不应报告用户控制变量问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSigned 测试 ====================

func TestCPP_CheckSigned_SignedUnsignedComparison(t *testing.T) {
	checker := &CPPChecker{IncludeSigned: true}
	reporter := newMockReporter()
	tracker := newTracker()

	// 先声明无符号变量
	checker.checkSigned("  unsigned int uval = 10;", "test.c", 5, tracker, reporter)
	// 然后进行比较
	checker.checkSigned("  if (sval == uval)", "test.c", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Signed/Unsigned Comparison") {
		t.Errorf("应检测到有符号/无符号比较，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckFileLevelIssues 测试 ====================

func TestCPP_FileLevelIssues_MemoryLeak(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CPP.MemAssign["leaked_ptr"] = "malloc"

	checker.CheckFileLevelIssues("test.c", tracker, reporter)

	if len(reporter.MemoryIssues) == 0 {
		t.Errorf("应报告未释放的内存分配")
	}
}

func TestCPP_FileLevelIssues_NoLeak(t *testing.T) {
	checker := &CPPChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.CheckFileLevelIssues("test.c", tracker, reporter)

	if len(reporter.MemoryIssues) > 0 {
		t.Errorf("没有未释放内存不应报告内存问题")
	}
}

// ==================== CheckCode 集成测试 ====================

func TestCPP_CheckCode_Integration(t *testing.T) {
	checker := &CPPChecker{IncludeSigned: false}
	reporter := newMockReporter()
	tracker := newTracker()

	lines := []string{
		"  char buf[10];",
		"  char *input = argv[1];",
		"  strcpy(buf, input);",
		"  printf(input)",
	}

	for i, line := range lines {
		checker.CheckCode(line, "test.c", i+1, tracker, reporter)
	}

	if len(reporter.Issues) == 0 {
		t.Errorf("集成测试应检测到多个问题")
	}

	if !reporter.hasIssueWithTitle("Buffer Overflow") {
		t.Errorf("应检测到缓冲区溢出，实际报告: %s", reporter.dumpIssues())
	}
}

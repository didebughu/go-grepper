package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/model"
)

// ==================== checkIdentificationDivision 测试 ====================

func TestCOBOL_CheckProgramID_Match(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkIdentificationDivision("       PROGRAM-ID. MYPROGRAM.", "MYPROGRAM.cob", 1, tracker, reporter)

	if tracker.COBOL.ProgramID != "MYPROGRAM" {
		t.Errorf("PROGRAM-ID 应为 MYPROGRAM，实际: %s", tracker.COBOL.ProgramID)
	}
	if len(reporter.Issues) > 0 {
		t.Errorf("文件名匹配 PROGRAM-ID 不应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckProgramID_Mismatch(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkIdentificationDivision("       PROGRAM-ID. MYPROGRAM.", "OTHER.cob", 1, tracker, reporter)

	if !reporter.hasIssueWithTitle("Filename Does Not Match PROGRAM-ID") {
		t.Errorf("应检测到文件名不匹配 PROGRAM-ID，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckProgramID_Multiple(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkIdentificationDivision("       PROGRAM-ID. MYPROGRAM.", "MYPROGRAM.cob", 1, tracker, reporter)
	checker.checkIdentificationDivision("       PROGRAM-ID. ANOTHER.", "MYPROGRAM.cob", 50, tracker, reporter)

	if !reporter.hasIssueWithTitle("Multiple Use of PROGRAM-ID") {
		t.Errorf("应检测到多个 PROGRAM-ID，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== trackVarAssignments 测试 ====================

func TestCOBOL_TrackVarAssignments_PIC(t *testing.T) {
	checker := &COBOLChecker{}
	tracker := newTracker()

	checker.trackVarAssignments("       05 WS-NAME PIC X(20).", tracker)

	if _, ok := tracker.COBOL.PICs["WS-NAME"]; !ok {
		t.Errorf("应跟踪 PIC 变量 WS-NAME")
	}
}

func TestCOBOL_TrackVarAssignments_ACCEPT(t *testing.T) {
	checker := &COBOLChecker{}
	tracker := newTracker()

	checker.trackVarAssignments("           ACCEPT WS-INPUT.", tracker)

	if _, ok := tracker.COBOL.PICs["WS-INPUT"]; !ok {
		t.Errorf("应跟踪 ACCEPT 的输入变量 WS-INPUT")
	}
}

// ==================== checkCICS 测试 ====================

func TestCOBOL_CheckCICS_Send(t *testing.T) {
	checker := &COBOLChecker{IsZOS: true}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCICS("           EXEC CICS", "test.cob", 10, tracker, reporter)
	checker.checkCICS("             SEND TEXT", "test.cob", 11, tracker, reporter)

	if !reporter.hasIssueWithTitle("Redirection of Output From CICS") {
		t.Errorf("应检测到 CICS SEND，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckCICS_UnsafeCommand(t *testing.T) {
	checker := &COBOLChecker{IsZOS: true}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCICS("           EXEC CICS", "test.cob", 10, tracker, reporter)
	checker.checkCICS("             DELETE FILE", "test.cob", 11, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Command within CICS") {
		t.Errorf("应检测到 CICS 中的不安全命令，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckCICS_NotZOS(t *testing.T) {
	checker := &COBOLChecker{IsZOS: false}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkCICS("           EXEC CICS", "test.cob", 10, tracker, reporter)
	checker.checkCICS("             SEND TEXT", "test.cob", 11, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("非 z/OS 模式不应检查 CICS，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSQL 测试 ====================

func TestCOBOL_CheckSQL_UserVarInSQL(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.COBOL.PICs["WS-INPUT"] = model.PICVar{VarName: "WS-INPUT", Length: 10}

	checker.checkSQL("           EXEC SQL", "test.cob", 10, tracker, reporter)
	checker.checkSQL("             SELECT * FROM USERS WHERE ID = :WS-INPUT", "test.cob", 11, tracker, reporter)

	if !reporter.hasIssueWithTitle("User Controlled Variable Used within SQL") {
		t.Errorf("应检测到 SQL 中的用户变量，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkBuffer 测试 ====================

func TestCOBOL_CheckBuffer_PICLengthMismatch(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.COBOL.PICs["WS-LONG"] = model.PICVar{VarName: "WS-LONG", Length: 20}
	tracker.COBOL.PICs["WS-SHORT"] = model.PICVar{VarName: "WS-SHORT", Length: 5}

	checker.checkBuffer("           MOVE WS-LONG TO WS-SHORT.", "test.cob", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("PIC Length Mismatch") {
		t.Errorf("应检测到 PIC 长度不匹配，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckBuffer_PICLengthMatch(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.COBOL.PICs["WS-SRC"] = model.PICVar{VarName: "WS-SRC", Length: 10}
	tracker.COBOL.PICs["WS-DST"] = model.PICVar{VarName: "WS-DST", Length: 10}

	checker.checkBuffer("           MOVE WS-SRC TO WS-DST.", "test.cob", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("PIC Length Mismatch") {
		t.Errorf("长度匹配不应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSigned 测试 ====================

func TestCOBOL_CheckSigned_SignMismatch(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.COBOL.PICs["WS-SIGNED"] = model.PICVar{VarName: "WS-SIGNED", Length: 5, IsSigned: true, IsNumeric: true}
	tracker.COBOL.PICs["WS-UNSIGNED"] = model.PICVar{VarName: "WS-UNSIGNED", Length: 5, IsNumeric: true}

	checker.checkSigned("           MOVE WS-SIGNED TO WS-UNSIGNED.", "test.cob", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("PIC Sign Mismatch") {
		t.Errorf("应检测到 PIC 符号不匹配，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckSigned_AlphaToNumeric(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.COBOL.PICs["WS-ALPHA"] = model.PICVar{VarName: "WS-ALPHA", Length: 5, IsNumeric: false}
	tracker.COBOL.PICs["WS-NUM"] = model.PICVar{VarName: "WS-NUM", Length: 5, IsNumeric: true}

	checker.checkSigned("           MOVE WS-ALPHA TO WS-NUM.", "test.cob", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("PIC Mismatch") {
		t.Errorf("应检测到字母到数字的 PIC 不匹配，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkRandomisation 测试 ====================

func TestCOBOL_CheckRandomisation_Random(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()

	checker.checkRandomisation("           COMPUTE WS-VAL = RANDOM.", "test.cob", 10, reporter)

	if !reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("应检测到 RANDOM 使用，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckRandomisation_IsRandom(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()

	checker.checkRandomisation("           ORGANIZATION IS RANDOM.", "test.cob", 10, reporter)

	if reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("IS RANDOM 不应报告伪随机问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckRandomisation_RandomPrefix(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()

	checker.checkRandomisation("           MOVE RANDOM-SEED TO WS-VAR.", "test.cob", 10, reporter)

	if reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("RANDOM- 前缀不应报告伪随机问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUnsafeTempFiles 测试 ====================

func TestCOBOL_CheckUnsafeTempFiles_OpenTemp(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()

	checker.checkUnsafeTempFiles("           OPEN OUTPUT temp-file", "test.cob", 10, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Temporary File") {
		t.Errorf("应检测到不安全的临时文件，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkDynamicCall 测试 ====================

func TestCOBOL_CheckDynamicCall_DynamicWithVar(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.COBOL.PICs["WSPROG"] = model.PICVar{VarName: "WSPROG", Length: 8}

	checker.checkDynamicCall("           CALL WSPROG USING WSDATA.", "test.cob", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("User Controlled Variable From JCL Used for Dynamic Function Call") {
		t.Errorf("应检测到用户控制变量的动态调用，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_CheckDynamicCall_StaticCall(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkDynamicCall(`           CALL 'MYPROG' USING WS-DATA.`, "test.cob", 10, tracker, reporter)

	// 静态调用不应报告动态调用问题
	if reporter.hasIssueWithTitle("Dynamic Function Call") {
		t.Errorf("静态调用不应报告动态调用问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkLogDisplay 测试 ====================

func TestCOBOL_CheckLogDisplay_LogPassword(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkLogDisplay("           CALL Logger USING password-field.", "test.cob", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Log User Passwords") {
		t.Errorf("应检测到日志记录密码，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== 密码管理测试 ====================

func TestCOBOL_PasswordCase(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.CheckCode("           MOVE LOWER-CASE(Password-field) TO WS-VAR.", "test.cob", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Password Management") {
		t.Errorf("应检测到不安全的密码管理，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckFileLevelIssues 测试 ====================

func TestCOBOL_FileLevelIssues_NoProgramID(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.CheckFileLevelIssues("test.cob", tracker, reporter)

	if !reporter.hasIssueWithTitle("No PROGRAM-ID") {
		t.Errorf("应报告缺少 PROGRAM-ID，实际报告: %s", reporter.dumpIssues())
	}
}

func TestCOBOL_FileLevelIssues_HasProgramID(t *testing.T) {
	checker := &COBOLChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.COBOL.ProgramID = "MYPROGRAM"

	checker.CheckFileLevelIssues("test.cob", tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("有 PROGRAM-ID 不应报告问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckCode 集成测试 ====================

func TestCOBOL_CheckCode_Integration(t *testing.T) {
	checker := &COBOLChecker{IsZOS: true}
	reporter := newMockReporter()
	tracker := newTracker()

	lines := []string{
		"       PROGRAM-ID. TESTPROG.",
		"       05 WS-INPUT PIC X(20).",
		"           ACCEPT WS-INPUT.",
		"           EXEC CICS",
		"             SEND TEXT",
		"           END-EXEC.",
	}

	for i, line := range lines {
		checker.CheckCode(line, "OTHER.cob", i+1, tracker, reporter)
	}

	if len(reporter.Issues) == 0 {
		t.Errorf("集成测试应检测到多个问题")
	}
}

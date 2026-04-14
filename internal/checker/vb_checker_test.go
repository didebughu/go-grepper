package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/model"
)

// ==================== checkRandomisation 测试 ====================

func TestVB_CheckRandomisation_Rnd(t *testing.T) {
	checker := &VBChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRandomisation("  x = Rnd (10)", "Test.vb", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Deterministic Pseudo-Random") {
		t.Errorf("应检测到 Rnd 伪随机数使用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSAML2Validation 测试 ====================

func TestVB_CheckSAML2_EmptyOverride(t *testing.T) {
	checker := &VBChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSAML2Validation("  Overrides Sub ValidateConditions(Saml2Conditions conditions)", "Test.vb", 10, tracker, reporter)
	checker.checkSAML2Validation("  End Sub", "Test.vb", 11, tracker, reporter)

	if !reporter.hasIssueWithTitle("SAML2 Condition Validation") {
		t.Errorf("应检测到空的 SAML2 验证覆盖，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUnsafeTempFiles 测试 ====================

func TestVB_CheckUnsafeTempFiles_HardcodedTemp(t *testing.T) {
	checker := &VBChecker{}
	reporter := newMockReporter()

	checker.checkUnsafeTempFiles(`  fileName = "C:\temp\data.dat",`, "Test.vb", 10, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Temporary File") {
		t.Errorf("应检测到不安全的临时文件，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkCryptoKeys 测试 ====================

func TestVB_CheckCryptoKeys_HardcodedKey(t *testing.T) {
	checker := &VBChecker{}
	reporter := newMockReporter()

	checker.checkCryptoKeys(`  Private Const encryptKey As String = "mysecretkey"`, "Test.vb", 10, reporter)

	if !reporter.hasIssueWithTitle("Hardcoded Crypto Key") {
		t.Errorf("应检测到硬编码加密密钥，实际报告: %s", reporter.dumpIssues())
	}
}

func TestVB_CheckCryptoKeys_HardcodedIV(t *testing.T) {
	checker := &VBChecker{}
	reporter := newMockReporter()

	checker.checkCryptoKeys(`  Private Const iv As Byte() = New Byte() {1, 2, 3}`, "Test.vb", 10, reporter)

	if !reporter.hasIssueWithTitle("Hardcoded Crypto Key") {
		t.Errorf("应检测到硬编码 IV，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== 密码管理测试 ====================

func TestVB_PasswordCase_ToLower(t *testing.T) {
	checker := &VBChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.CheckCode("  If Password.ToLower() = input Then", "Test.vb", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Password Management") {
		t.Errorf("应检测到不安全的密码管理，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckCode 集成测试 ====================

func TestVB_CheckCode_Integration(t *testing.T) {
	checker := &VBChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	lines := []string{
		`  Dim x As Integer = Rnd (10)`,
		`  Private Const cryptoKey As String = "secret"`,
	}

	for i, line := range lines {
		checker.CheckCode(line, "Test.vb", i+1, tracker, reporter)
	}

	if len(reporter.Issues) == 0 {
		t.Errorf("集成测试应检测到多个问题")
	}
}

// ==================== Language 测试 ====================

func TestVB_Language(t *testing.T) {
	checker := &VBChecker{}
	if checker.Language() != 4 { // config.LangVB = 4
		t.Errorf("VBChecker 语言应为 4 (VB)，实际: %d", checker.Language())
	}
	_ = model.SeverityMedium // 确保 import 使用
}

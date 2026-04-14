package checker

import (
	"fmt"
	"strings"

	"github.com/didebughu/go-grepper/internal/model"
)

// reportedIssue 记录一个被报告的安全问题
type reportedIssue struct {
	RuleID      string
	Title       string
	Description string
	FileName    string
	Severity    int
	CodeLine    string
	LineNumber  int
}

// mockReporter 模拟 IssueReporter 接口，用于测试
type mockReporter struct {
	Issues       []reportedIssue
	MemoryIssues []map[string]string
}

func newMockReporter() *mockReporter {
	return &mockReporter{}
}

func (m *mockReporter) ReportIssue(ruleID, title, description, fileName string, severity int, codeLine string, lineNumber int) {
	m.Issues = append(m.Issues, reportedIssue{
		RuleID:      ruleID,
		Title:       title,
		Description: description,
		FileName:    fileName,
		Severity:    severity,
		CodeLine:    codeLine,
		LineNumber:  lineNumber,
	})
}

func (m *mockReporter) ReportMemoryIssue(issues map[string]string) {
	m.MemoryIssues = append(m.MemoryIssues, issues)
}

// hasIssueWithTitle 检查是否存在包含指定标题关键词的问题
func (m *mockReporter) hasIssueWithTitle(keyword string) bool {
	for _, issue := range m.Issues {
		if strings.Contains(issue.Title, keyword) {
			return true
		}
	}
	return false
}

// hasIssueWithSeverity 检查是否存在指定严重级别的问题
func (m *mockReporter) hasIssueWithSeverity(severity int) bool {
	for _, issue := range m.Issues {
		if issue.Severity == severity {
			return true
		}
	}
	return false
}

// issueCount 返回包含指定标题关键词的问题数量
func (m *mockReporter) issueCount(keyword string) int {
	count := 0
	for _, issue := range m.Issues {
		if strings.Contains(issue.Title, keyword) {
			count++
		}
	}
	return count
}

// dumpIssues 输出所有问题（调试用）
func (m *mockReporter) dumpIssues() string {
	var sb strings.Builder
	for i, issue := range m.Issues {
		sb.WriteString(fmt.Sprintf("[%d] Title=%q Severity=%d File=%q Line=%d Code=%q\n",
			i, issue.Title, issue.Severity, issue.FileName, issue.LineNumber, issue.CodeLine))
	}
	return sb.String()
}

// newTracker 创建一个已初始化的 CodeTracker
func newTracker() *model.CodeTracker {
	tracker := &model.CodeTracker{}
	tracker.Reset()
	return tracker
}

// Package checker 定义语言特定安全检查器接口
package checker

import "github.com/didebughu/go-grepper/internal/model"

// Checker 语言特定安全检查器接口
// 将原来的 Select Case 分发改为接口多态
type Checker interface {
	// CheckCode 对单行代码执行语言特定的安全检查
	CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter)

	// CheckFileLevelIssues 文件扫描完成后执行文件级检查
	CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter)

	// Language 返回支持的语言标识
	Language() int
}

// IssueReporter 问题报告回调接口（解耦检查器与结果收集）
// 对应原来各检查模块中直接调用 frmMain.ListCodeIssue() 的方式
type IssueReporter interface {
	// ReportIssue 报告一个安全问题（新增 ruleID 参数）
	ReportIssue(ruleID, title, description, fileName string, severity int, codeLine string, lineNumber int)

	// ReportMemoryIssue 报告内存相关问题（C/C++ 专用）
	ReportMemoryIssue(issues map[string]string)
}

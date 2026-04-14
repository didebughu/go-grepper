package scanner

import (
	"strings"

	"github.com/didebughu/go-grepper/internal/checker"
	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
)

// CommentChecker 注释安全检查器（对应原 CheckComment）
type CommentChecker struct {
	settings *config.Settings
}

// NewCommentChecker 创建注释检查器
func NewCommentChecker(settings *config.Settings) *CommentChecker {
	return &CommentChecker{settings: settings}
}

// Check 检查注释中是否包含可疑关键词，返回是否发现问题
func (cc *CommentChecker) Check(comment, fileName string, lineNum int, reporter checker.IssueReporter) bool {
	found := false
	lowerComment := strings.ToLower(comment)

	for _, badComment := range cc.settings.BadComments {
		if strings.Contains(lowerComment, strings.ToLower(strings.TrimSpace(badComment))) {
			reporter.ReportIssue(
				"GEN-COMMENT-001",
				"Comment Appears to Contain Task/Issue",
				"The comment contains '"+strings.TrimSpace(badComment)+"' which may indicate unfinished or problematic code.",
				fileName, model.SeverityInfo, comment, lineNum,
			)
			found = true
			break // 每行注释只报告一次
		}
	}

	// 检查注释中是否包含密码
	if strings.Contains(lowerComment, "password") || strings.Contains(lowerComment, "passwd") {
		reporter.ReportIssue(
			"GEN-COMMENT-002",
			"Comment Appears to Contain Password",
			"The comment appears to include a password.",
			fileName, model.SeverityHigh, comment, lineNum,
		)
		found = true
	}

	return found
}

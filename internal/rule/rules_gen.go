// Package rule - 通用规则注册（GEN-*）
package rule

import "github.com/didebughu/go-grepper/internal/model"

func init() {
	Register(&Rule{
		ID:          "GEN-PASSWD-001",
		Name:        "Hardcoded Password",
		Description: "The code may contain a hard-coded password which an attacker could obtain from the source or by dis-assembling the executable.",
		Severity:    model.SeverityMedium,
		Languages:   []string{"all"},
		Category:    "PASSWD",
		Enabled:     true,
	})
	Register(&Rule{
		ID:          "GEN-COMMENT-001",
		Name:        "Suspicious Comment",
		Description: "The comment contains a keyword which may indicate unfinished or problematic code.",
		Severity:    model.SeverityInfo,
		Languages:   []string{"all"},
		Category:    "COMMENT",
		Enabled:     true,
	})
	Register(&Rule{
		ID:          "GEN-COMMENT-002",
		Name:        "Comment Contains Password",
		Description: "The comment appears to include a password.",
		Severity:    model.SeverityHigh,
		Languages:   []string{"all"},
		Category:    "COMMENT",
		Enabled:     true,
	})
	Register(&Rule{
		ID:          "GEN-BADFUNC-001",
		Name:        "Unsafe Function",
		Description: "A function matching the unsafe function configuration was detected.",
		Severity:    model.SeverityStandard,
		Languages:   []string{"all"},
		Category:    "BADFUNC",
		Enabled:     true,
	})
}

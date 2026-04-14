package reporter

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/didebughu/go-grepper/internal/model"
)

// TextReporter 纯文本输出
type TextReporter struct {
	outputPath  string
	minSeverity int
}

// NewTextReporter 创建文本输出器
func NewTextReporter(outputPath string, minSeverity int) (*TextReporter, error) {
	return &TextReporter{
		outputPath:  outputPath,
		minSeverity: minSeverity,
	}, nil
}

func (r *TextReporter) WriteResults(results *model.ResultsTracker) error {
	w, closer, err := r.getWriter()
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	filtered := filterResults(results.Results, r.minSeverity)

	fmt.Fprintln(w, "=== go-grepper Scan Results ===")
	fmt.Fprintln(w)

	for _, result := range filtered {
		if result.RuleID != "" {
			fmt.Fprintf(w, "[%s] [%s] %s\n", result.SeverityDesc, result.RuleID, result.Title)
		} else {
			fmt.Fprintf(w, "[%s] %s\n", result.SeverityDesc, result.Title)
		}
		if result.FileName != "" {
			if result.LineNumber > 0 {
				fmt.Fprintf(w, "  File: %s:%d\n", result.FileName, result.LineNumber)
			} else {
				fmt.Fprintf(w, "  File: %s\n", result.FileName)
			}
		}
		if result.Description != "" {
			fmt.Fprintf(w, "  Description: %s\n", result.Description)
		}
		if result.CodeLine != "" {
			fmt.Fprintf(w, "  Code: %s\n", strings.TrimSpace(result.CodeLine))
		}
		fmt.Fprintln(w)
	}

	return nil
}

func (r *TextReporter) WriteSummary(results *model.ResultsTracker) error {
	w, closer, err := r.getWriter()
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	counts := results.IssueCountBySeverity()

	fmt.Fprintln(w, "--- Summary ---")
	fmt.Fprintf(w, "Total files: %d\n", results.FileCount)
	fmt.Fprintf(w, "Total lines: %d (Code: %d | Comments: %d | Whitespace: %d)\n",
		results.OverallLineCount, results.OverallCodeCount,
		results.OverallCommentCount, results.OverallWhitespaceCount)

	totalIssues := results.TotalIssues()
	fmt.Fprintf(w, "Issues found: %d (Critical: %d | High: %d | Medium: %d | Standard: %d | Low: %d)\n",
		totalIssues,
		counts[model.SeverityCritical],
		counts[model.SeverityHigh],
		counts[model.SeverityMedium],
		counts[model.SeverityStandard],
		counts[model.SeverityLow],
	)

	return nil
}

func (r *TextReporter) getWriter() (io.Writer, func(), error) {
	if r.outputPath == "" {
		return os.Stdout, nil, nil
	}

	f, err := os.OpenFile(r.outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("无法打开输出文件: %w", err)
	}
	return f, func() { f.Close() }, nil
}

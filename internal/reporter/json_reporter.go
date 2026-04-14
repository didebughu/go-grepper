package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/didebughu/go-grepper/internal/model"
)

// JSONReporter JSON 输出
type JSONReporter struct {
	outputPath  string
	minSeverity int
}

// NewJSONReporter 创建 JSON 输出器
func NewJSONReporter(outputPath string, minSeverity int) (*JSONReporter, error) {
	return &JSONReporter{
		outputPath:  outputPath,
		minSeverity: minSeverity,
	}, nil
}

// jsonOutput JSON 输出结构
type jsonOutput struct {
	Metadata jsonMetadata       `json:"metadata"`
	Summary  jsonSummary        `json:"summary"`
	Results  []model.ScanResult `json:"results"`
}

type jsonMetadata struct {
	ScanTime string `json:"scan_time"`
	Version  string `json:"version"`
}

type jsonSummary struct {
	FilesScanned    int            `json:"files_scanned"`
	TotalLines      int64          `json:"total_lines"`
	CodeLines       int64          `json:"code_lines"`
	CommentLines    int64          `json:"comment_lines"`
	WhitespaceLines int64          `json:"whitespace_lines"`
	IssuesCount     map[string]int `json:"issues_count"`
}

func (r *JSONReporter) WriteResults(results *model.ResultsTracker) error {
	filtered := filterResults(results.Results, r.minSeverity)
	counts := results.IssueCountBySeverity()

	output := jsonOutput{
		Metadata: jsonMetadata{
			ScanTime: time.Now().Format(time.RFC3339),
			Version:  "2.0.0",
		},
		Summary: jsonSummary{
			FilesScanned:    results.FileCount,
			TotalLines:      results.OverallLineCount,
			CodeLines:       results.OverallCodeCount,
			CommentLines:    results.OverallCommentCount,
			WhitespaceLines: results.OverallWhitespaceCount,
			IssuesCount: map[string]int{
				"critical": counts[model.SeverityCritical],
				"high":     counts[model.SeverityHigh],
				"medium":   counts[model.SeverityMedium],
				"standard": counts[model.SeverityStandard],
				"low":      counts[model.SeverityLow],
			},
		},
		Results: filtered,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 序列化失败: %w", err)
	}

	if r.outputPath == "" {
		_, err = os.Stdout.Write(data)
		fmt.Fprintln(os.Stdout)
		return err
	}

	return os.WriteFile(r.outputPath, data, 0644)
}

func (r *JSONReporter) WriteSummary(_ *model.ResultsTracker) error {
	// JSON 格式中摘要已包含在 WriteResults 中
	return nil
}

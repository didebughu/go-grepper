package reporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/didebughu/go-grepper/internal/model"
)

// CSVReporter CSV 输出
type CSVReporter struct {
	outputPath  string
	minSeverity int
}

// NewCSVReporter 创建 CSV 输出器
func NewCSVReporter(outputPath string, minSeverity int) (*CSVReporter, error) {
	return &CSVReporter{
		outputPath:  outputPath,
		minSeverity: minSeverity,
	}, nil
}

func (r *CSVReporter) WriteResults(results *model.ResultsTracker) error {
	filtered := filterResults(results.Results, r.minSeverity)

	w := os.Stdout
	if r.outputPath != "" {
		f, err := os.Create(r.outputPath)
		if err != nil {
			return fmt.Errorf("无法创建 CSV 文件: %w", err)
		}
		defer f.Close()
		w = f
	}

	writer := csv.NewWriter(w)
	defer writer.Flush()

	// 写入表头
	if err := writer.Write([]string{"RuleID", "Severity", "Title", "Description", "File", "Line", "Code"}); err != nil {
		return err
	}

	for _, result := range filtered {
		record := []string{
			result.RuleID,
			result.SeverityDesc,
			result.Title,
			result.Description,
			result.FileName,
			strconv.Itoa(result.LineNumber),
			strings.TrimSpace(result.CodeLine),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func (r *CSVReporter) WriteSummary(_ *model.ResultsTracker) error {
	// CSV 格式中摘要可选
	return nil
}

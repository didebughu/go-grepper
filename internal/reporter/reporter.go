// Package reporter 实现扫描结果输出
package reporter

import "github.com/didebughu/go-grepper/internal/model"

// Reporter 结果输出接口
type Reporter interface {
	// WriteResults 输出所有扫描结果
	WriteResults(results *model.ResultsTracker) error
	// WriteSummary 输出统计摘要
	WriteSummary(results *model.ResultsTracker) error
}

// NewReporter 根据格式创建对应的 Reporter
func NewReporter(format string, outputPath string, minSeverity int) (Reporter, error) {
	switch format {
	case "json":
		return NewJSONReporter(outputPath, minSeverity)
	case "xml":
		return NewXMLReporter(outputPath, minSeverity)
	case "csv":
		return NewCSVReporter(outputPath, minSeverity)
	case "text":
		return NewTextReporter(outputPath, minSeverity)
	default:
		return NewTextReporter(outputPath, minSeverity)
	}
}

// filterResults 按严重级别过滤结果
func filterResults(results []model.ScanResult, minSeverity int) []model.ScanResult {
	if minSeverity <= 0 || minSeverity >= model.SeverityPossiblySafe {
		return results
	}

	var filtered []model.ScanResult
	for _, r := range results {
		if r.Severity <= minSeverity {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

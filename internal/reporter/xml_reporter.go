package reporter

import (
	"encoding/xml"
	"fmt"
	"os"

	"github.com/didebughu/go-grepper/internal/model"
)

// XMLReporter XML 输出（兼容原 VCG XML 导出格式，保留 XML 根元素名称以兼容旧工具）
type XMLReporter struct {
	outputPath  string
	minSeverity int
}

// NewXMLReporter 创建 XML 输出器
func NewXMLReporter(outputPath string, minSeverity int) (*XMLReporter, error) {
	return &XMLReporter{
		outputPath:  outputPath,
		minSeverity: minSeverity,
	}, nil
}

type xmlOutput struct {
	XMLName xml.Name           `xml:"VCGResults"`
	Results []model.ScanResult `xml:"Result"`
}

func (r *XMLReporter) WriteResults(results *model.ResultsTracker) error {
	filtered := filterResults(results.Results, r.minSeverity)

	output := xmlOutput{
		Results: filtered,
	}

	data, err := xml.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("XML 序列化失败: %w", err)
	}

	xmlData := []byte(xml.Header)
	xmlData = append(xmlData, data...)

	if r.outputPath == "" {
		_, err = os.Stdout.Write(xmlData)
		fmt.Fprintln(os.Stdout)
		return err
	}

	return os.WriteFile(r.outputPath, xmlData, 0644)
}

func (r *XMLReporter) WriteSummary(_ *model.ResultsTracker) error {
	// XML 格式中摘要可选
	return nil
}

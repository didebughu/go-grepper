package model

// ScanResult 单条扫描结果（对应原 ScanResult 类）
// 去除了 IsChecked/CheckColour 等 GUI 专用字段
type ScanResult struct {
	RuleID       string `json:"rule_id" xml:"RuleID"`
	Title        string `json:"title" xml:"Title"`
	Description  string `json:"description" xml:"Description"`
	FileName     string `json:"file_name" xml:"FileName"`
	LineNumber   int    `json:"line_number" xml:"LineNumber"`
	CodeLine     string `json:"code_line" xml:"CodeLine"`
	Severity     int    `json:"severity" xml:"Severity"`
	SeverityDesc string `json:"severity_desc" xml:"SeverityDesc"`
}

// NewScanResult 创建一个新的扫描结果
func NewScanResult(ruleID, title, description, fileName string, severity int, codeLine string, lineNumber int) ScanResult {
	return ScanResult{
		RuleID:       ruleID,
		Title:        title,
		Description:  description,
		FileName:     fileName,
		LineNumber:   lineNumber,
		CodeLine:     codeLine,
		Severity:     severity,
		SeverityDesc: SeverityName(severity),
	}
}

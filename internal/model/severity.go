// Package model 定义 go-grepper 扫描相关的数据模型
package model

// 严重级别常量（对应原 CodeIssue 中的常量）
const (
	SeverityCritical     = 1
	SeverityHigh         = 2
	SeverityMedium       = 3
	SeverityStandard     = 4
	SeverityLow          = 5
	SeverityInfo         = 6
	SeverityPossiblySafe = 7
)

// SeverityName 返回严重级别的描述名称
func SeverityName(level int) string {
	switch level {
	case SeverityCritical:
		return "Critical"
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityStandard:
		return "Standard"
	case SeverityLow:
		return "Low"
	case SeverityInfo:
		return "Suspicious Comment"
	case SeverityPossiblySafe:
		return "Potential Issue"
	default:
		return "Standard"
	}
}

// ParseSeverity 将字符串解析为严重级别
func ParseSeverity(s string) int {
	switch s {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "standard":
		return SeverityStandard
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	case "all":
		return SeverityPossiblySafe
	default:
		return SeverityPossiblySafe
	}
}

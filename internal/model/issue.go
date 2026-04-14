package model

// CodeIssue 不安全函数定义（对应原 CodeIssue 类）
// 用于存储从 .conf 配置文件加载的危险函数名称及其描述
type CodeIssue struct {
	FunctionName string // 函数名称
	Description  string // 描述信息
	Severity     int    // 严重级别
}

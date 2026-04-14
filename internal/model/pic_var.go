package model

// PICVar COBOL PIC 变量（对应原 PICVar 类）
// COBOL PIC 变量有多种属性：可以是数值型或字母数字型，有符号或无符号，
// 并且有长度属性，类似于数组。
type PICVar struct {
	VarName   string // 变量名
	IsSigned  bool   // 是否有符号
	IsNumeric bool   // 是否数值型
	Length    int    // 长度
}

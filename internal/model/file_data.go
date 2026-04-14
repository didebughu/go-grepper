package model

// FileData 文件扫描统计数据（对应原 FileData 类）
type FileData struct {
	ShortName       string // 短文件名
	FileName        string // 完整文件路径
	LineCount       int64  // 总行数
	CodeCount       int64  // 代码行数
	CommentCount    int64  // 注释行数
	WhitespaceCount int64  // 空白行数
	FixMeCount      int64  // FixMe/TODO 注释数
	BadFuncCount    int64  // 不安全函数数
}

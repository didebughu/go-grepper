package model

// SyncBlock Java 线程同步块跟踪（对应原 SyncBlock 类）
type SyncBlock struct {
	BlockIndex   int      // 块索引
	OuterObject  string   // 外部锁对象
	InnerObjects []string // 内部被锁对象列表
}

// IsLockedBy 检查指定对象是否在锁定列表中
func (sb *SyncBlock) IsLockedBy(innerObject string) bool {
	for _, obj := range sb.InnerObjects {
		if obj == innerObject {
			return true
		}
	}
	return false
}

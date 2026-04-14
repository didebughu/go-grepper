package model

import "sync"

// ResultsTracker 扫描结果跟踪器（线程安全）
// 对应原 ResultsTracker.vb，添加 sync.Mutex 支持并发
type ResultsTracker struct {
	mu sync.Mutex

	// 所有扫描结果
	Results []ScanResult

	// 全局统计
	FileCount              int
	OverallCommentCount    int64
	OverallCodeCount       int64
	OverallWhitespaceCount int64
	OverallLineCount       int64
	OverallFixMeCount      int64
	OverallBadFuncCount    int64

	// 当前文件统计（非线程安全，仅在单个 goroutine 中使用）
	CommentCount    int64
	CodeCount       int64
	WhitespaceCount int64
	LineCount       int64
	FixMeCount      int64
	BadFuncCount    int64
}

// AddResult 线程安全地添加扫描结果
func (rt *ResultsTracker) AddResult(result ScanResult) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.Results = append(rt.Results, result)
}

// IncrFileCount 线程安全地增加文件计数
func (rt *ResultsTracker) IncrFileCount() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.FileCount++
}

// MergeFileStats 将文件级统计合并到全局统计（线程安全）
func (rt *ResultsTracker) MergeFileStats(comment, code, whitespace, line, fixme, badfunc int64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.OverallCommentCount += comment
	rt.OverallCodeCount += code
	rt.OverallWhitespaceCount += whitespace
	rt.OverallLineCount += line
	rt.OverallFixMeCount += fixme
	rt.OverallBadFuncCount += badfunc
}

// Reset 重置所有计数器
func (rt *ResultsTracker) Reset() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.Results = nil
	rt.FileCount = 0
	rt.OverallCommentCount = 0
	rt.OverallCodeCount = 0
	rt.OverallWhitespaceCount = 0
	rt.OverallLineCount = 0
	rt.OverallFixMeCount = 0
	rt.OverallBadFuncCount = 0
}

// ResetFileCounters 重置文件级计数器
func (rt *ResultsTracker) ResetFileCounters() {
	rt.CommentCount = 0
	rt.CodeCount = 0
	rt.WhitespaceCount = 0
	rt.LineCount = 0
	rt.FixMeCount = 0
	rt.BadFuncCount = 0
}

// IssueCountBySeverity 按严重级别统计问题数量
func (rt *ResultsTracker) IssueCountBySeverity() map[int]int {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	counts := make(map[int]int)
	for _, r := range rt.Results {
		counts[r.Severity]++
	}
	return counts
}

// TotalIssues 返回总问题数
func (rt *ResultsTracker) TotalIssues() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.Results)
}

// Merge 将另一个 ResultsTracker 的结果合并到当前实例（用于多语言扫描结果合并）
func (rt *ResultsTracker) Merge(other *ResultsTracker) {
	if other == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	other.mu.Lock()
	defer other.mu.Unlock()

	rt.Results = append(rt.Results, other.Results...)
	rt.FileCount += other.FileCount
	rt.OverallCommentCount += other.OverallCommentCount
	rt.OverallCodeCount += other.OverallCodeCount
	rt.OverallWhitespaceCount += other.OverallWhitespaceCount
	rt.OverallLineCount += other.OverallLineCount
	rt.OverallFixMeCount += other.OverallFixMeCount
	rt.OverallBadFuncCount += other.OverallBadFuncCount
}

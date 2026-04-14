package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CollectFiles 遍历目标目录收集匹配后缀的文件列表
// target 必须是一个目录路径
// excludeDirs 排除的目录名列表
// excludePatterns 排除的文件 glob 模式列表
func CollectFiles(target string, suffixes []string, excludeDirs []string, excludePatterns []string) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("目标路径必须是目录: %s", target)
	}

	// 遍历目录
	var files []string
	err = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			// 检查是否在排除目录列表中
			dirName := filepath.Base(path)
			relPath, _ := filepath.Rel(target, path)
			for _, excl := range excludeDirs {
				if dirName == excl || relPath == excl || strings.HasPrefix(relPath, excl+string(filepath.Separator)) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		// 检查排除模式
		for _, pattern := range excludePatterns {
			if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
				return nil
			}
		}
		if matchSuffix(path, suffixes) {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// matchSuffix 检查文件是否匹配指定后缀
func matchSuffix(filename string, suffixes []string) bool {
	if len(suffixes) == 0 {
		return true
	}

	lower := strings.ToLower(filename)
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

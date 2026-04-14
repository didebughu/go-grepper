package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ProfileFileName 配置文件名
const ProfileFileName = ".go-grepper.yaml"

// LoadProfile 按优先级查找并加载配置文件
// 仅支持两种查找方式：
//  1. 命令行参数 --config 指定的文件路径
//  2. 扫描目标目录下的 .go-grepper.yaml
func LoadProfile(configPath, targetDir string) (*Profile, error) {
	profile := DefaultProfile()

	// 按优先级查找配置文件（不查找用户主目录）
	var candidates []string

	if configPath != "" {
		candidates = append(candidates, configPath)
	}
	if targetDir != "" {
		candidates = append(candidates, filepath.Join(targetDir, ProfileFileName))
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, profile); err != nil {
			return nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
		}
		return profile, nil
	}

	return profile, nil // 未找到配置文件，使用默认值
}

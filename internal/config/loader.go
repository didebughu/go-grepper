package config

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/didebughu/go-grepper/configs"
	"github.com/didebughu/go-grepper/internal/model"
)

// Loader 配置文件加载器
type Loader struct {
	configDir string // 自定义配置目录（为空则使用嵌入配置）
}

// NewLoader 创建配置加载器
func NewLoader(configDir string) *Loader {
	return &Loader{configDir: configDir}
}

// LoadSettings 根据选项加载完整配置
func (l *Loader) LoadSettings(language int, suffixes []string, configOnly, isAndroid bool,
	cobolStartCol int, isZOS, includeSigned bool, outputLevel int) (*Settings, error) {

	langConfig, ok := LanguageConfigs[language]
	if !ok {
		return nil, fmt.Errorf("不支持的语言类型: %d", language)
	}

	settings := &Settings{
		Language:      language,
		LangConfig:    langConfig,
		OutputLevel:   outputLevel,
		ConfigOnly:    configOnly,
		IsAndroid:     isAndroid,
		COBOLStartCol: cobolStartCol,
		IsZOS:         isZOS,
		IncludeSigned: includeSigned,
	}

	// 设置文件后缀
	if len(suffixes) > 0 {
		settings.FileSuffixes = suffixes
	} else {
		settings.FileSuffixes = langConfig.DefaultSuffixes
	}

	// 加载不安全函数列表
	badFuncs, err := l.LoadBadFunctions(langConfig.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("加载不安全函数配置失败: %w", err)
	}
	settings.BadFunctions = badFuncs

	// 加载可疑注释关键词
	badComments, err := l.LoadBadComments("badcomments.conf")
	if err != nil {
		return nil, fmt.Errorf("加载可疑注释配置失败: %w", err)
	}
	settings.BadComments = badComments

	return settings, nil
}

// LoadBadFunctions 加载不安全函数列表（对应原 LoadUnsafeFunctionList）
// 配置文件格式: function name[=>][[N]][description]
// 其中 N 是严重级别 0-3（0=Standard, 1=Critical, 2=High, 3=Medium）
func (l *Loader) LoadBadFunctions(filename string) ([]BadFunction, error) {
	data, err := l.readConfigFile(filename)
	if err != nil {
		return nil, err
	}

	var functions []BadFunction
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 跳过空行和注释
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		bf := BadFunction{
			Severity: model.SeverityStandard, // 默认级别
		}

		// 解析函数名和描述
		if strings.Contains(line, "=>") {
			parts := strings.SplitN(line, "=>", 2)
			bf.Name = parts[0]
			desc := strings.TrimSpace(parts[1])

			// 提取严重级别 [N]
			if len(desc) >= 3 && desc[0] == '[' && desc[2] == ']' {
				if level, err := strconv.Atoi(string(desc[1])); err == nil {
					switch level {
					case 0:
						bf.Severity = model.SeverityStandard
					case 1:
						bf.Severity = model.SeverityCritical
					case 2:
						bf.Severity = model.SeverityHigh
					case 3:
						bf.Severity = model.SeverityMedium
					}
					desc = strings.TrimSpace(desc[3:])
				}
			}

			bf.Description = desc
		} else {
			bf.Name = line
			bf.Description = ""
		}

		functions = append(functions, bf)
	}

	return functions, scanner.Err()
}

// LoadBadComments 加载可疑注释关键词列表（对应原 LoadBadComments）
func (l *Loader) LoadBadComments(filename string) ([]string, error) {
	data, err := l.readConfigFile(filename)
	if err != nil {
		return nil, err
	}

	var comments []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 跳过空行和注释
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		comments = append(comments, line)
	}

	return comments, scanner.Err()
}

// readConfigFile 读取配置文件（优先使用自定义目录，否则使用嵌入配置）
func (l *Loader) readConfigFile(filename string) ([]byte, error) {
	// 优先使用自定义配置目录
	if l.configDir != "" {
		filePath := filepath.Join(l.configDir, filename)
		if _, err := os.Stat(filePath); err == nil {
			return os.ReadFile(filePath)
		}
	}

	// 使用嵌入的默认配置
	return fs.ReadFile(configs.FS, filename)
}

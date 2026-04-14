// Package config 定义应用配置和语言配置
package config

import (
	"fmt"
	"strings"
)

// 语言类型常量（对应原 AppSettings 中的常量）
const (
	LangCPP    = 0 // C/C++
	LangJava   = 1 // Java
	LangSQL    = 2 // PL/SQL
	LangCSharp = 3 // C#
	LangVB     = 4 // VB
	LangPHP    = 5 // PHP
	LangCOBOL  = 6 // COBOL
	LangR      = 7 // R
)

// LanguageConfig 每种语言的配置
type LanguageConfig struct {
	Name              string   // 语言名称
	DefaultSuffixes   []string // 默认文件后缀
	ConfigFile        string   // 不安全函数配置文件名
	SingleLineComment string   // 单行注释符
	AltLineComment    string   // 备选单行注释符（VB='、PHP=#）
	BlockStartComment string   // 块注释开始符
	BlockEndComment   string   // 块注释结束符
	CaseSensitive     bool     // 函数匹配是否大小写敏感
}

// Settings 全局应用配置（对应原 AppSettings）
type Settings struct {
	Language      int            // 语言类型
	LangConfig    LanguageConfig // 当前语言配置
	FileSuffixes  []string       // 文件后缀列表
	BadFunctions  []BadFunction  // 从 .conf 加载的不安全函数列表
	BadComments   []string       // 从 badcomments.conf 加载的可疑注释关键词
	OutputLevel   int            // 输出级别过滤
	ConfigOnly    bool           // 仅配置检查模式
	IsAndroid     bool           // Android 检查
	COBOLStartCol int            // COBOL 起始列
	IsZOS         bool           // z/OS 模式
	IncludeSigned bool           // 有符号比较检查
}

// BadFunction 不安全函数定义（对应原 CodeIssue 在配置加载中的用途）
type BadFunction struct {
	Name        string // 函数名称
	Description string // 描述信息
	Severity    int    // 严重级别
}

// LanguageConfigs 预定义各语言配置映射表
var LanguageConfigs = map[int]LanguageConfig{
	LangCPP: {
		Name:              "C/C++",
		DefaultSuffixes:   []string{".cpp", ".hpp", ".c", ".h"},
		ConfigFile:        "cppfunctions.conf",
		SingleLineComment: "//",
		BlockStartComment: "/*",
		BlockEndComment:   "*/",
		CaseSensitive:     true,
	},
	LangJava: {
		Name:              "Java",
		DefaultSuffixes:   []string{".java", ".jsp", ".jspf", "web.xml", "config.xml"},
		ConfigFile:        "javafunctions.conf",
		SingleLineComment: "//",
		BlockStartComment: "/*",
		BlockEndComment:   "*/",
		CaseSensitive:     true,
	},
	LangSQL: {
		Name:              "PL/SQL",
		DefaultSuffixes:   []string{".pls", ".pkb", ".pks"},
		ConfigFile:        "plsqlfunctions.conf",
		SingleLineComment: "--",
		BlockStartComment: "/*",
		BlockEndComment:   "*/",
		CaseSensitive:     false,
	},
	LangCSharp: {
		Name:              "C#",
		DefaultSuffixes:   []string{".cs", ".aspx", "web.config"},
		ConfigFile:        "csfunctions.conf",
		SingleLineComment: "//",
		BlockStartComment: "/*",
		BlockEndComment:   "*/",
		CaseSensitive:     true,
	},
	LangVB: {
		Name:              "VB",
		DefaultSuffixes:   []string{".vb", ".asp", ".aspx", "web.config"},
		ConfigFile:        "vbfunctions.conf",
		SingleLineComment: "'",
		AltLineComment:    "REM",
		CaseSensitive:     false,
	},
	LangPHP: {
		Name:              "PHP",
		DefaultSuffixes:   []string{".php", ".php3", "php.ini"},
		ConfigFile:        "phpfunctions.conf",
		SingleLineComment: "//",
		AltLineComment:    "#",
		BlockStartComment: "/*",
		BlockEndComment:   "*/",
		CaseSensitive:     true,
	},
	LangCOBOL: {
		Name:              "COBOL",
		DefaultSuffixes:   []string{".cob", ".cbl", ".clt", ".cl2", ".cics"},
		ConfigFile:        "cobolfunctions.conf",
		SingleLineComment: "*",
		AltLineComment:    "/",
		CaseSensitive:     true,
	},
	LangR: {
		Name:              "R",
		DefaultSuffixes:   []string{".r"},
		ConfigFile:        "rfunctions.conf",
		SingleLineComment: "#",
		CaseSensitive:     true,
	},
}

// ParseLanguage 将语言字符串解析为语言常量
func ParseLanguage(lang string) (int, bool) {
	switch lang {
	case "c", "c++", "cpp":
		return LangCPP, true
	case "java":
		return LangJava, true
	case "plsql", "pl/sql", "sql":
		return LangSQL, true
	case "csharp", "c#", "cs", "c-sharp":
		return LangCSharp, true
	case "vb", "visualbasic", "visual-basic":
		return LangVB, true
	case "php":
		return LangPHP, true
	case "cobol":
		return LangCOBOL, true
	case "r":
		return LangR, true
	default:
		return -1, false
	}
}

// ParseLanguages 将多个语言字符串解析为语言常量列表
// 如果输入为空，返回所有支持的语言
func ParseLanguages(langs []string) ([]int, error) {
	if len(langs) == 0 {
		return AllLanguageIDs(), nil
	}

	seen := make(map[int]bool)
	var result []int
	for _, lang := range langs {
		langID, ok := ParseLanguage(lang)
		if !ok {
			return nil, fmt.Errorf("不支持的语言: %s", lang)
		}
		if !seen[langID] {
			seen[langID] = true
			result = append(result, langID)
		}
	}
	return result, nil
}

// AllLanguageIDs 返回所有支持的语言 ID 列表
func AllLanguageIDs() []int {
	return []int{LangCPP, LangJava, LangSQL, LangCSharp, LangVB, LangPHP, LangCOBOL, LangR}
}

// LanguageName 返回语言名称
func LanguageName(lang int) string {
	if cfg, ok := LanguageConfigs[lang]; ok {
		return cfg.Name
	}
	return "Unknown"
}

// LanguageNames 返回多个语言的名称，逗号分隔
func LanguageNames(langs []int) string {
	names := make([]string, 0, len(langs))
	for _, lang := range langs {
		names = append(names, LanguageName(lang))
	}
	return strings.Join(names, ", ")
}

// Package util 提供通用工具函数
package util

import (
	"regexp"
	"strings"
)

var whitespaceRegex = regexp.MustCompile(`\s+`)

// GetVarName 从代码行中提取变量名
func GetVarName(codeLine string, splitOnEquals bool) string {
	var varName string

	if strings.Contains(codeLine, "=") || splitOnEquals {
		parts := strings.SplitN(strings.TrimSpace(codeLine), "=", 2)
		varName = parts[0]
	} else {
		parts := strings.SplitN(strings.TrimSpace(codeLine), ";", 2)
		varName = parts[0]
	}

	varName = GetLastItem(varName, " ")

	// 清理括号
	varName = strings.TrimLeft(varName, "(")
	varName = strings.TrimSpace(varName)
	varName = strings.TrimRight(varName, ")")
	varName = strings.TrimSpace(varName)

	return varName
}

// GetLastItem 按分隔符分割字符串并返回最后一项（对应原 GetLastItem）
func GetLastItem(listString string, separator string) string {
	listString = strings.TrimSpace(listString)

	var parts []string
	if separator == " " {
		// 使用正则防止空格分割产生空字符串
		parts = whitespaceRegex.Split(listString, -1)
	} else {
		parts = strings.Split(listString, separator)
	}

	if len(parts) == 0 {
		return ""
	}

	return strings.TrimSpace(parts[len(parts)-1])
}

// GetFirstItem 按分隔符分割字符串并返回第一项（对应原 GetFirstItem）
func GetFirstItem(listString string, separator string) string {
	listString = strings.TrimSpace(listString)

	var parts []string
	if separator == " " {
		parts = whitespaceRegex.Split(listString, -1)
	} else {
		parts = strings.Split(listString, separator)
	}

	if len(parts) == 0 {
		return ""
	}

	return strings.TrimSpace(parts[0])
}

// ContainsWhitespace 检查字符串是否包含空白字符
func ContainsWhitespace(s string) bool {
	return whitespaceRegex.MatchString(s)
}

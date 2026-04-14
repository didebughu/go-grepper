// Package configs 嵌入默认配置文件
package configs

import "embed"

//go:embed *.conf
var FS embed.FS

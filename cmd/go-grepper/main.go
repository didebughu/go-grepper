// go-grepper - 代码安全扫描工具
package main

import (
	"fmt"
	"os"

	"github.com/didebughu/go-grepper/internal/app"
	_ "github.com/didebughu/go-grepper/internal/rule" // 触发规则注册
	"github.com/spf13/cobra"
)

// 版本信息
var (
	version = "2.0"
)

func main() {
	opts := app.DefaultOptions()

	rootCmd := &cobra.Command{
		Use:   "go-grepper",
		Short: "go-grepper - 代码安全扫描工具",
		Long: `go-grepper 是一个代码安全扫描工具，
支持 C/C++、Java、C#、VB、PHP、PL/SQL、COBOL、R 等多种语言的快速安全扫描。`,
	}
	// 禁用默认的 completion 子命令
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "扫描目标代码",
		Long:  "扫描指定目标目录中的代码安全问题",
		Run: func(cmd *cobra.Command, args []string) {
			exitCode := app.Run(opts)
			os.Exit(exitCode)
		},
	}

	// 必选参数
	scanCmd.Flags().StringVarP(&opts.Target, "target", "t", "", "目标目录路径（必选）")
	_ = scanCmd.MarkFlagRequired("target")

	// 可选参数
	scanCmd.Flags().StringSliceVarP(&opts.Languages, "language", "l", nil,
		"目标语言（可多选，逗号分隔，为空则扫描所有语言）: cpp|java|csharp|vb|php|plsql|cobol|r")
	scanCmd.Flags().StringSliceVarP(&opts.Extensions, "extensions", "e", nil,
		"自定义文件扩展名，逗号分隔 (如: .c,.h,.cpp)")
	scanCmd.Flags().StringVarP(&opts.Severity, "severity", "s", opts.Severity,
		"最低报告级别: critical|high|medium|standard|low|info|all")
	scanCmd.Flags().StringVarP(&opts.OutputFile, "output", "o", "",
		"输出文件路径")
	scanCmd.Flags().StringVarP(&opts.OutputFormat, "format", "f", opts.OutputFormat,
		"输出格式: text|json|xml|csv")
	scanCmd.Flags().StringVar(&opts.ConfigDir, "config-dir", "",
		"自定义配置文件目录")
	scanCmd.Flags().StringVar(&opts.ConfigFile, "config", "",
		"配置文件路径（默认自动查找 .go-grepper.yaml）")
	scanCmd.Flags().BoolVar(&opts.ConfigOnly, "config-only", false,
		"仅检查配置文件中的不安全函数，跳过语义分析")
	scanCmd.Flags().BoolVar(&opts.IsAndroid, "android", false,
		"启用 Android 特定检查 (仅 Java)")
	scanCmd.Flags().IntVar(&opts.COBOLStartCol, "cobol-start-col", opts.COBOLStartCol,
		"COBOL 起始列号")
	scanCmd.Flags().BoolVar(&opts.IsZOS, "cobol-zos", false,
		"启用 z/OS CICS 检查 (仅 COBOL)")
	scanCmd.Flags().BoolVar(&opts.IncludeSigned, "include-signed", false,
		"启用有符号/无符号比较检查 (仅 C/C++, Beta)")
	scanCmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false,
		"详细输出模式")
	scanCmd.Flags().IntVarP(&opts.Jobs, "jobs", "j", opts.Jobs,
		"并行扫描文件数")

	// v2.0 新增参数
	scanCmd.Flags().StringSliceVar(&opts.ExcludeDirs, "exclude-dir", nil,
		"排除目录，逗号分隔 (如: vendor,node_modules)")
	scanCmd.Flags().StringSliceVar(&opts.ExcludePatterns, "exclude-pattern", nil,
		"排除文件模式，逗号分隔 (如: *_test.java,*.generated.java)")
	scanCmd.Flags().StringSliceVar(&opts.EnableRules, "enable-rule", nil,
		"仅启用指定规则，逗号分隔 (如: JAVA-SQLI-001,JAVA-XSS-001)")
	scanCmd.Flags().StringSliceVar(&opts.DisableRules, "disable-rule", nil,
		"禁用指定规则，逗号分隔 (如: JAVA-INTOV-001,GEN-COMMENT-001)")
	scanCmd.Flags().StringSliceVar(&opts.DisableCategories, "disable-category", nil,
		"禁用规则类别，逗号分隔 (如: COMMENT,RAND)")

	rootCmd.AddCommand(scanCmd)

	// rules 命令
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "列出所有扫描规则",
		Long:  "列出所有内置的安全扫描规则，支持按语言过滤",
		Run: func(cmd *cobra.Command, args []string) {
			lang, _ := cmd.Flags().GetString("language")
			format, _ := cmd.Flags().GetString("format")
			app.ListRules(lang, format)
		},
	}
	rulesCmd.Flags().StringP("language", "l", "",
		"按语言过滤: cpp|java|csharp|vb|php|plsql|cobol|r (为空则显示全部)")
	rulesCmd.Flags().StringP("format", "f", "table",
		"输出格式: table|json|csv")
	rootCmd.AddCommand(rulesCmd)

	// init 命令
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "生成默认配置文件",
		Long:  "在当前目录生成 .go-grepper.yaml 默认配置文件",
		Run: func(cmd *cobra.Command, args []string) {
			app.InitConfig()
		},
	}
	rootCmd.AddCommand(initCmd)

	// 版本命令
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("go-grepper version %s\n", version)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

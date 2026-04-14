# go-grepper

一个快速的、开箱即用的多语言源代码安全审计命令行工具。

## 项目背景

VCG (Visual Code Grepper) 是由 NCC Group 开发的开源代码安全审计工具，使用 VB.NET WinForms 构建，仅支持 Windows 平台操作。

**go-grepper** 初步目标是将 VCG 的核心安全分析能力，重构为一个跨平台、高性能的命令行工具。后续计划支持更多主流语言和优化规则。

## 支持语言

| 语言 | 检查能力 |
|------|---------|
| C/C++ | 缓冲区溢出、内存泄漏、格式化字符串、竞态条件、命令注入等 |
| Java | SQL 注入、XSS、Servlet 安全、线程安全、序列化、XXE、Android 特定检查等 |
| C# | 输入验证、SQL 注入、XSS、unsafe 代码、web.config 安全配置等 |
| PHP | SQL 注入、XSS、文件包含、命令执行、php.ini 配置检查等 |
| PL/SQL | Oracle 加密、自治事务、视图安全、动态 SQL 等 |
| COBOL | PIC 变量安全、CICS API、SQL 注入等 |
| VB | 基础安全检查 |
| R | 基础安全检查 |

## 快速开始

```bash
# 构建
make build

# 扫描目标目录
./bin/go-grepper scan -t /path/to/project -l java

# 指定输出格式和文件
./bin/go-grepper scan -t /path/to/project -l cpp -f json -o results.json

# 查看帮助
./bin/go-grepper scan --help
```

## 主要参数

```
-t, --target <path>          目标目录路径（必选）
-l, --language <lang>        目标语言: cpp|java|csharp|vb|php|plsql|cobol|r（默认: cpp）
-f, --format <fmt>           输出格式: text|json|xml|csv（默认: text）
-o, --output <file>          输出文件路径
-s, --severity <level>       最低报告级别: critical|high|medium|standard|low|info|all（默认: all）
-j, --jobs <n>               并行扫描文件数（默认: CPU 核心数）
-v, --verbose                详细输出模式
```

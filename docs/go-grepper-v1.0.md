
# go-grepper v1.0

## 一、项目概述

### 1.1 目标

将 VCG (Visual Code Grepper) 从 VB.NET WinForms 桌面应用重构为 **纯命令行 Go 语言工具 go-grepper**，保留其核心安全分析逻辑，去除 GUI/可视化相关代码和配置。

### 1.2 重构原则

| 原则 | 说明 |
|------|------|
| **核心逻辑不变** | 所有安全检查规则、双层分析引擎、上下文跟踪机制完整保留 |
| **纯 CLI** | 去除所有 WinForms UI、图表、可视化、拖拽等交互，仅通过命令行参数和标准输出交互 |
| **Go 惯用设计** | 采用 Go 的接口、包组织、并发模型等惯用模式重构 |
| **可扩展性增强** | 利用 Go 接口机制使新增语言支持更加标准化 |
| **配置兼容** | 保持与原有 `.conf` 配置文件格式完全兼容 |
| **重命名** | 工具名称从 VCG 更名为 go-grepper |

### 1.3 技术选型

| 组件 | 选型 | 理由 |
|------|------|------|
| CLI 框架 | `cobra` | Go 生态最成熟的 CLI 框架，支持子命令、flag、自动帮助 |
| 正则引擎 | `regexp` (标准库) | 对应原项目的 `System.Text.RegularExpressions` |
| 日志 | `slog` (标准库) | Go 1.21+ 内置结构化日志 |
| 配置管理 | 自定义解析 (兼容原格式) | 保持 `.conf` 文件格式不变 |
| 输出格式 | `encoding/json`, `encoding/xml`, `encoding/csv` | 标准库即可满足 |
| 并发 | `goroutine` + `sync` | 文件级并行扫描，提升性能 |

---

## 二、项目结构设计

```
go-grepper/
├── cmd/
│   └── go-grepper/
│       └── main.go                  # 程序入口
├── internal/
│   ├── app/
│   │   ├── app.go                   # 应用主逻辑（扫描调度）
│   │   └── options.go               # 命令行参数定义与解析
│   ├── config/
│   │   ├── settings.go              # 应用配置（对应 AppSettings）
│   │   ├── loader.go                # 配置文件加载器（加载 .conf 文件）
│   │   └── badcomments.go           # 可疑注释关键词加载
│   ├── model/
│   │   ├── severity.go              # 严重级别常量（对应 CodeIssue 中的常量）
│   │   ├── issue.go                 # CodeIssue 数据结构
│   │   ├── scan_result.go           # ScanResult 数据结构
│   │   ├── file_data.go             # FileData 数据结构
│   │   ├── code_tracker.go          # CodeTracker 代码状态跟踪器
│   │   ├── results_tracker.go       # ResultsTracker 结果跟踪器
│   │   ├── sync_block.go            # SyncBlock（Java 线程同步块）
│   │   └── pic_var.go               # PICVar（COBOL PIC 变量）
│   ├── scanner/
│   │   ├── scanner.go               # 扫描引擎核心（对应 ScanFiles + ScanLine）
│   │   ├── comment_checker.go       # 注释检查器（对应 CheckComment）
│   │   ├── code_checker.go          # 通用代码检查器（对应 CheckCode，含不安全函数匹配）
│   │   └── file_checker.go          # 文件级检查（对应 CheckFileLevelIssues）
│   ├── checker/
│   │   ├── checker.go               # Checker 接口定义
│   │   ├── cpp_checker.go           # C/C++ 检查器（对应 modCppCheck）
│   │   ├── java_checker.go          # Java 检查器（对应 modJavaCheck）
│   │   ├── csharp_checker.go        # C# 检查器（对应 modCSharpCheck）
│   │   ├── vb_checker.go            # VB 检查器（对应 modVBCheck）
│   │   ├── php_checker.go           # PHP 检查器（对应 modPHPCheck）
│   │   ├── plsql_checker.go         # PL/SQL 检查器（对应 modPlSqlCheck）
│   │   ├── cobol_checker.go         # COBOL 检查器（对应 modCobolCheck）
│   │   └── r_checker.go             # R 检查器（对应 modRCheck）
│   ├── reporter/
│   │   ├── reporter.go              # Reporter 接口定义
│   │   ├── text_reporter.go         # 纯文本输出（对应原 swOutputFile）
│   │   ├── json_reporter.go         # JSON 输出（新增，替代 GUI 展示）
│   │   ├── xml_reporter.go          # XML 输出（对应原 ExportResultsXML）
│   │   ├── csv_reporter.go          # CSV 输出（对应原 ExportResultsCSV）
│   │   └── console_reporter.go      # 控制台实时输出（对应原 Console.WriteLine）
│   └── util/
│       ├── strings.go               # 字符串工具（对应 GetVarName, GetLastItem, GetFirstItem）
│       └── file.go                  # 文件工具（文件遍历、类型过滤）
├── configs/
│   ├── badcomments.conf             # 直接复用原配置文件
│   ├── cppfunctions.conf
│   ├── javafunctions.conf
│   ├── csfunctions.conf
│   ├── vbfunctions.conf
│   ├── phpfunctions.conf
│   ├── plsqlfunctions.conf
│   ├── cobolfunctions.conf
│   └── rfunctions.conf
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## 三、核心模块设计

### 3.1 命令行接口设计 (`cmd/grepper/main.go` + `internal/app/options.go`)

**对应原模块**：`modMain.ParseArgs()` + `frmMain` 中的控制台模式逻辑

```
// 命令行用法设计
go-grepper scan [flags]

// 必选参数
  -t, --target <path>          目标目录路径

// 可选参数
  -l, --language <lang>        目标语言: cpp|java|csharp|vb|php|plsql|cobol|r (默认: cpp)
  -e, --extensions <exts>      自定义文件扩展名，逗号分隔 (如: .c,.h,.cpp)
  -s, --severity <level>       最低报告级别: critical|high|medium|standard|low|info|all (默认: all)
  -o, --output <file>          输出文件路径
  -f, --format <fmt>           输出格式: text|json|xml|csv (默认: text)
      --config-dir <dir>       自定义配置文件目录
      --config-only            仅检查配置文件中的不安全函数，跳过语义分析
      --android                启用 Android 特定检查 (仅 Java)
      --cobol-start-col <n>    COBOL 起始列号 (默认: 7)
      --cobol-zos              启用 z/OS CICS 检查 (仅 COBOL)
      --include-signed         启用有符号/无符号比较检查 (仅 C/C++, Beta)
  -v, --verbose                详细输出模式
  -j, --jobs <n>               并行扫描文件数 (默认: CPU核心数)
  -h, --help                   显示帮助
      --version                显示版本
```

**Options 结构体**：

```go
// internal/app/options.go
package app

type Options struct {
    Target        string   // 目标目录路径
    Language      string   // 语言类型
    Extensions    []string // 文件扩展名
    Severity      int      // 最低报告级别
    OutputFile    string   // 输出文件
    OutputFormat  string   // 输出格式
    ConfigDir     string   // 配置目录
    ConfigOnly    bool     // 仅配置检查
    IsAndroid     bool     // Android 检查
    COBOLStartCol int      // COBOL 起始列
    IsZOS         bool     // z/OS 模式
    IncludeSigned bool     // 有符号比较检查
    Verbose       bool     // 详细模式
    Jobs          int      // 并行数
}
```

### 3.2 应用配置 (`internal/config/settings.go`)

**对应原模块**：`Models/AppSettings.vb`

```go
// internal/config/settings.go
package config

// Language 语言类型常量
const (
    LangCPP    = iota // 0 - C/C++
    LangJava          // 1 - Java
    LangSQL           // 2 - PL/SQL
    LangCSharp        // 3 - C#
    LangVB            // 4 - VB
    LangPHP           // 5 - PHP
    LangCOBOL         // 6 - COBOL
    LangR             // 7 - R
)

// LanguageConfig 每种语言的配置
type LanguageConfig struct {
    Name               string   // 语言名称
    DefaultSuffixes    []string // 默认文件后缀
    ConfigFile         string   // 不安全函数配置文件名
    SingleLineComment  string   // 单行注释符
    AltLineComment     string   // 备选单行注释符（VB='、PHP=#）
    BlockStartComment  string   // 块注释开始符
    BlockEndComment    string   // 块注释结束符
    CaseSensitive      bool     // 函数匹配是否大小写敏感
}

// Settings 全局应用配置
type Settings struct {
    Language        int
    LangConfig      LanguageConfig
    FileSuffixes    []string
    BadFunctions    []BadFunction    // 从 .conf 加载的不安全函数列表
    BadComments     []string         // 从 badcomments.conf 加载的可疑注释关键词
    OutputLevel     int              // 输出级别过滤
    ConfigOnly      bool             // 仅配置检查模式
    IsAndroid       bool             // Android 检查
    COBOLStartCol   int              // COBOL 起始列
    IsZOS           bool             // z/OS 模式
    IncludeSigned   bool             // 有符号比较检查
}

// BadFunction 不安全函数定义（对应原 CodeIssue 在配置加载中的用途）
type BadFunction struct {
    Name        string
    Description string
    Severity    int
}

// 预定义各语言配置映射表
var LanguageConfigs = map[int]LanguageConfig{
    LangCPP: {
        Name: "C/C++", DefaultSuffixes: []string{".cpp", ".hpp", ".c", ".h"},
        ConfigFile: "cppfunctions.conf",
        SingleLineComment: "//", BlockStartComment: "/*", BlockEndComment: "*/",
        CaseSensitive: true,
    },
    LangJava: {
        Name: "Java", DefaultSuffixes: []string{".java", ".jsp", ".jspf", "web.xml", "config.xml"},
        ConfigFile: "javafunctions.conf",
        SingleLineComment: "//", BlockStartComment: "/*", BlockEndComment: "*/",
        CaseSensitive: true,
    },
    // ... 其他语言类似
}
```

### 3.3 严重级别与问题模型 (`internal/model/`)

**对应原模块**：`Models/CodeIssue.vb` + `Models/ScanResult.vb`

```go
// internal/model/severity.go
package model

const (
    SeverityCritical     = 1
    SeverityHigh         = 2
    SeverityMedium       = 3
    SeverityStandard     = 4
    SeverityLow          = 5
    SeverityInfo         = 6
    SeverityPossiblySafe = 7
)

func SeverityName(level int) string {
    switch level {
    case SeverityCritical:     return "Critical"
    case SeverityHigh:         return "High"
    case SeverityMedium:       return "Medium"
    case SeverityStandard:     return "Standard"
    case SeverityLow:          return "Low"
    case SeverityInfo:         return "Suspicious Comment"
    case SeverityPossiblySafe: return "Potential Issue"
    default:                   return "Standard"
    }
}
```

```go
// internal/model/scan_result.go
package model

// ScanResult 单条扫描结果（对应原 ScanResult 类）
type ScanResult struct {
    Title        string `json:"title" xml:"Title"`
    Description  string `json:"description" xml:"Description"`
    FileName     string `json:"file_name" xml:"FileName"`
    LineNumber   int    `json:"line_number" xml:"LineNumber"`
    CodeLine     string `json:"code_line" xml:"CodeLine"`
    Severity     int    `json:"severity" xml:"Severity"`
    SeverityDesc string `json:"severity_desc" xml:"SeverityDesc"`
}
```

### 3.4 代码状态跟踪器 (`internal/model/code_tracker.go`)

**对应原模块**：`Models/CodeTracker.vb`（66KB，项目中最大的模型文件）

这是实现**跨行上下文分析**的核心。按语言拆分为嵌套结构体：

```go
// internal/model/code_tracker.go
package model

// CodeTracker 代码状态跟踪器（每个文件一个实例）
type CodeTracker struct {
    // === 通用状态 ===
    HasValidator     bool
    HasVulnSQLString bool
    SQLStatements    []string

    // === C/C++ 专用 ===
    CPP CPPTracker

    // === Java 专用 ===
    Java JavaTracker

    // === C# 专用 ===
    CSharp CSharpTracker

    // === PHP 专用 ===
    PHP PHPTracker

    // === COBOL 专用 ===
    COBOL COBOLTracker

    // === PL/SQL 专用 ===
    PLSQL PLSQLTracker
}

// CPPTracker C/C++ 状态跟踪
type CPPTracker struct {
    MemAssign     map[string]string // malloc/new 分配跟踪 → 对应 dicMemAssign
    Buffers       map[string]int    // 缓冲区大小跟踪 → 对应 dicBuffer
    Integers      map[string]int    // 整数变量跟踪 → 对应 dicInteger
    Unsigned      map[string]bool   // 无符号变量跟踪 → 对应 dicUnsigned
    UserVariables []string          // 用户控制变量 → 对应 UserVariables
    InDestructor  bool              // 是否在析构函数内
}

// JavaTracker Java 状态跟踪
type JavaTracker struct {
    IsServlet          bool
    ServletName        string
    ServletNames       []string
    ImplementsClone    bool
    IsSerialize        bool
    IsDeserialize      bool
    HasXXEEnabled      bool
    IsFileOpen         bool
    FileOpenLine       int
    HasTry             bool
    HasResourceRelease bool
    HasFinalize        bool
    SyncBlocks         []SyncBlock   // 同步块跟踪
    GetterSetters      []string      // getter/setter 方法
    HttpReqVariables   []string      // HTTP 请求变量
}

// CSharpTracker C# 状态跟踪
type CSharpTracker struct {
    InputVariables []string
    CookieValues   []string
    AspLabels      []string
    InUnsafeBlock  bool
}

// PHPTracker PHP 状态跟踪
type PHPTracker struct {
    HasDisableFunctions bool
    HasRegisterGlobals  bool
}

// COBOLTracker COBOL 状态跟踪
type COBOLTracker struct {
    ProgramID string
    PICs      map[string]PICVar // PIC 变量字典
    InCICS    bool
    InSQL     bool
}

// PLSQLTracker PL/SQL 状态跟踪
type PLSQLTracker struct {
    HasOracleEncrypt    bool
    IsAutonomous        bool
    InView              bool
}

// Reset 重置文件级状态（每扫描新文件时调用）
func (ct *CodeTracker) Reset() { /* ... */ }

// ResetProjectLevel 重置项目级状态（C/C++ 的内存字典等）
func (ct *CodeTracker) ResetProjectLevel() { /* ... */ }
```

### 3.5 结果跟踪器 (`internal/model/results_tracker.go`)

**对应原模块**：`Models/ResultsTracker.vb`

```go
// internal/model/results_tracker.go
package model

import "sync"

// ResultsTracker 扫描结果跟踪器（线程安全）
type ResultsTracker struct {
    mu sync.Mutex

    Results []ScanResult // 所有扫描结果

    // 全局统计
    FileCount              int
    OverallCommentCount    int64
    OverallCodeCount       int64
    OverallWhitespaceCount int64
    OverallLineCount       int64
    OverallFixMeCount      int64
    OverallBadFuncCount    int64

    // 当前文件统计
    CommentCount    int64
    CodeCount       int64
    WhitespaceCount int64
    LineCount       int64
    FixMeCount      int64
    BadFuncCount    int64
}

func (rt *ResultsTracker) AddResult(result ScanResult) { /* 加锁添加 */ }
func (rt *ResultsTracker) Reset() { /* 重置所有计数器 */ }
func (rt *ResultsTracker) ResetFileCounters() { /* 重置文件级计数器 */ }
```

### 3.6 语言检查器接口 (`internal/checker/checker.go`)

**对应原模块**：`Modules/mod*Check.vb` 系列（8 个语言检查模块）

这是重构的**核心抽象**，将原来的 `Select Case` 分发改为接口多态：

```go
// internal/checker/checker.go
package checker

import "github.com/didebughu/go-grepper/internal/model"

// Checker 语言特定安全检查器接口
type Checker interface {
    // CheckCode 对单行代码执行语言特定的安全检查
    CheckCode(codeLine string, fileName string, tracker *model.CodeTracker, reporter IssueReporter)

    // CheckFileLevelIssues 文件扫描完成后执行文件级检查
    CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter)

    // Language 返回支持的语言标识
    Language() int
}

// IssueReporter 问题报告回调接口（解耦检查器与结果收集）
// 对应原来各检查模块中直接调用 frmMain.ListCodeIssue() 的方式
type IssueReporter interface {
    ReportIssue(title, description, fileName string, severity int, codeLine string, lineNumber int)
    ReportMemoryIssue(issues map[string]string)
}
```

**各语言检查器实现示例**（以 Java 为例）：

```go
// internal/checker/java_checker.go
package checker

import "github.com/didebughu/go-grepper/internal/model"

type JavaChecker struct {
    IsAndroid         bool
    IsInnerClassCheck bool
    IsFinalizeCheck   bool
}

func (c *JavaChecker) Language() int { return config.LangJava }

func (c *JavaChecker) CheckCode(codeLine string, fileName string,
    tracker *model.CodeTracker, reporter IssueReporter) {
    // 完整保留原 modJavaCheck.CheckJavaCode 中的所有检查逻辑：
    c.checkServlet(codeLine, fileName, tracker, reporter)
    c.checkSQLiValidation(codeLine, fileName, tracker, reporter)
    c.checkXSSValidation(codeLine, fileName, tracker, reporter)
    c.checkRunTime(codeLine, fileName, tracker, reporter)
    c.checkIsHttps(codeLine, fileName, tracker, reporter)
    c.checkClone(codeLine, fileName, tracker, reporter)
    c.checkSerialize(codeLine, fileName, tracker, reporter)
    c.identifyServlets(codeLine, tracker)
    c.checkModifiers(codeLine, fileName, tracker, reporter)
    c.checkThreadIssues(codeLine, fileName, tracker, reporter)
    c.checkUnsafeTempFiles(codeLine, fileName, tracker, reporter)
    c.checkPrivileged(codeLine, fileName, tracker, reporter)
    c.checkRequestDispatcher(codeLine, fileName, tracker, reporter)
    c.checkXXEExpansion(codeLine, fileName, tracker, reporter)
    c.checkOverflow(codeLine, fileName, tracker, reporter)
    c.checkResourceRelease(codeLine, fileName, tracker, reporter)

    if c.IsInnerClassCheck {
        c.checkInnerClasses(codeLine, fileName, tracker, reporter)
    }
    if c.IsAndroid {
        c.checkAndroidStaticCrypto(codeLine, fileName, tracker, reporter)
        c.checkAndroidIntent(codeLine, fileName, tracker, reporter)
    }
}

func (c *JavaChecker) CheckFileLevelIssues(fileName string,
    tracker *model.CodeTracker, reporter IssueReporter) {
    // 对应原 CheckFileLevelIssues 中 Java 部分
    if tracker.Java.ImplementsClone {
        reporter.ReportIssue("Class Implements Public 'clone' Method",
            "...", fileName, model.SeverityMedium, "", 0)
    }
    // ... 其他文件级检查
}
```

**检查器注册工厂**：

```go
// internal/checker/registry.go
package checker

func NewChecker(language int, settings *config.Settings) Checker {
    switch language {
    case config.LangCPP:    return &CPPChecker{IncludeSigned: settings.IncludeSigned}
    case config.LangJava:   return &JavaChecker{IsAndroid: settings.IsAndroid}
    case config.LangCSharp: return &CSharpChecker{}
    case config.LangVB:     return &VBChecker{}
    case config.LangPHP:    return &PHPChecker{}
    case config.LangSQL:    return &PLSQLChecker{}
    case config.LangCOBOL:  return &COBOLChecker{StartCol: settings.COBOLStartCol, IsZOS: settings.IsZOS}
    case config.LangR:      return &RChecker{}
    default:                return &CPPChecker{}
    }
}
```

### 3.7 扫描引擎 (`internal/scanner/scanner.go`)

**对应原模块**：`frmMain.ScanFiles()` + `frmMain.ScanLine()` + `modMain.CheckCode()`

这是整个工具的**调度中枢**：

```go
// internal/scanner/scanner.go
package scanner

import (
    "bufio"
    "os"
    "strings"
    "sync"
    "github.com/didebughu/go-grepper/internal/checker"
    "github.com/didebughu/go-grepper/internal/config"
    "github.com/didebughu/go-grepper/internal/model"
)

// Scanner 扫描引擎
type Scanner struct {
    settings       *config.Settings
    checker        checker.Checker
    codeChecker    *CodeChecker      // 通用不安全函数匹配
    commentChecker *CommentChecker   // 注释检查
    results        *model.ResultsTracker
    jobs           int               // 并行数
}

// NewScanner 创建扫描引擎
func NewScanner(settings *config.Settings, jobs int) *Scanner {
    return &Scanner{
        settings:       settings,
        checker:        checker.NewChecker(settings.Language, settings),
        codeChecker:    NewCodeChecker(settings),
        commentChecker: NewCommentChecker(settings),
        results:        &model.ResultsTracker{},
        jobs:           jobs,
    }
}

// Scan 执行扫描（主入口）
func (s *Scanner) Scan(files []string) *model.ResultsTracker {
    s.results.Reset()

    // 使用 worker pool 并行扫描文件
    fileCh := make(chan string, len(files))
    var wg sync.WaitGroup

    for i := 0; i < s.jobs; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for file := range fileCh {
                s.scanFile(file)
            }
        }()
    }

    for _, f := range files {
        fileCh <- f
    }
    close(fileCh)
    wg.Wait()

    return s.results
}

// scanFile 扫描单个文件（对应原 ScanFiles 中的内层循环）
func (s *Scanner) scanFile(filePath string) {
    tracker := &model.CodeTracker{}
    tracker.Reset()

    reporter := &resultReporter{results: s.results}

    file, err := os.Open(filePath)
    if err != nil { return }
    defer file.Close()

    sc := bufio.NewScanner(file)
    lineNum := 0
    inBlockComment := false

    for sc.Scan() {
        lineNum++
        line := sc.Text()

        // COBOL 起始列处理
        if s.settings.Language == config.LangCOBOL && s.settings.COBOLStartCol > 1 {
            if s.settings.COBOLStartCol > len(line) {
                line = ""
            } else {
                line = line[s.settings.COBOLStartCol-1:]
            }
        }

        if len(strings.TrimSpace(line)) == 0 {
            // 空白行
            s.results.IncrWhitespace()
            continue
        }

        // 注释/代码分离逻辑（对应原 ScanLine）
        code, comment, nowInBlock := s.splitLine(line, inBlockComment)
        inBlockComment = nowInBlock

        // 检查注释
        if len(comment) > 0 {
            s.results.IncrComment()
            s.commentChecker.Check(comment, filePath, lineNum, reporter)
        }

        // 检查代码
        if len(code) > 0 {
            s.results.IncrCode()
            // 第一层：不安全函数匹配
            s.codeChecker.Check(code, filePath, lineNum, reporter)
            // 第二层：语言特定深度检查
            if !s.settings.ConfigOnly {
                s.checker.CheckCode(code, filePath, tracker, reporter)
                // 硬编码密码检查（通用）
                checkHardcodedPassword(code, filePath, lineNum, reporter)
            }
        }
    }

    // 文件级检查
    if !s.settings.ConfigOnly {
        s.checker.CheckFileLevelIssues(filePath, tracker, reporter)
    }

    s.results.IncrFileCount()
}
```

### 3.8 通用代码检查器 (`internal/scanner/code_checker.go`)

**对应原模块**：`modMain.CheckCode()` 中的不安全函数匹配部分

```go
// internal/scanner/code_checker.go
package scanner

import (
    "regexp"
    "strings"
    "github.com/didebughu/go-grepper/internal/config"
)

// CodeChecker 通用不安全函数检查器（基于配置文件）
type CodeChecker struct {
    settings *config.Settings
    patterns []*compiledPattern // 预编译的正则模式
}

type compiledPattern struct {
    regex    *regexp.Regexp
    funcName string
    desc     string
    severity int
}

// NewCodeChecker 创建并预编译所有不安全函数的正则模式
func NewCodeChecker(settings *config.Settings) *CodeChecker {
    cc := &CodeChecker{settings: settings}
    for _, bf := range settings.BadFunctions {
        // 对应原逻辑：添加 \b 词边界（仅当不含空格和点号时）
        pattern := bf.Name
        if !containsWhitespace(pattern) && !strings.Contains(pattern, ".") {
            pattern = `\b` + regexp.QuoteMeta(pattern) + `\b`
        }
        re, err := regexp.Compile(pattern)
        if err != nil { continue }
        cc.patterns = append(cc.patterns, &compiledPattern{
            regex: re, funcName: bf.Name, desc: bf.Description, severity: bf.Severity,
        })
    }
    return cc
}

// Check 检查代码行中的不安全函数
func (cc *CodeChecker) Check(codeLine, fileName string, lineNum int, reporter IssueReporter) {
    checkLine := codeLine
    // PL/SQL 大小写不敏感
    if cc.settings.Language == config.LangSQL {
        checkLine = strings.ToUpper(codeLine)
    }
    for _, p := range cc.patterns {
        if p.regex.MatchString(checkLine) {
            reporter.ReportIssue(p.funcName, p.desc, fileName, p.severity, codeLine, lineNum)
        }
    }
}
```

### 3.9 输出报告器 (`internal/reporter/`)

**对应原模块**：`frmMain` 中的 `WriteResult`、`ExportResultsXML`、`ExportResultsCSV` 等

```go
// internal/reporter/reporter.go
package reporter

import "github.com/didebughu/go-grepper/internal/model"

// Reporter 结果输出接口
type Reporter interface {
    // WriteResults 输出所有扫描结果
    WriteResults(results *model.ResultsTracker) error
    // WriteSummary 输出统计摘要
    WriteSummary(results *model.ResultsTracker) error
}

// NewReporter 根据格式创建对应的 Reporter
func NewReporter(format string, outputPath string, minSeverity, maxSeverity int) (Reporter, error) {
    switch format {
    case "json": return NewJSONReporter(outputPath, minSeverity, maxSeverity)
    case "xml":  return NewXMLReporter(outputPath, minSeverity, maxSeverity)
    case "csv":  return NewCSVReporter(outputPath, minSeverity, maxSeverity)
    case "text": return NewTextReporter(outputPath, minSeverity, maxSeverity)
    default:     return NewTextReporter(outputPath, minSeverity, maxSeverity)
    }
}
```

**控制台实时输出**（扫描过程中）：

```go
// internal/reporter/console_reporter.go
package reporter

import (
    "fmt"
    "os"
    "github.com/didebughu/go-grepper/internal/model"
)

// ConsoleReporter 控制台实时输出（对应原 LogInfo/LogVerbose）
type ConsoleReporter struct {
    Verbose bool
}

func (cr *ConsoleReporter) ReportProgress(fileName string, current, total int) {
    fmt.Fprintf(os.Stderr, "\r[%d/%d] Scanning: %s", current, total, fileName)
}

func (cr *ConsoleReporter) ReportIssue(result model.ScanResult) {
    if cr.Verbose {
        fmt.Fprintf(os.Stderr, "[%s] %s - %s:%d\n",
            model.SeverityName(result.Severity), result.Title,
            result.FileName, result.LineNumber)
    }
}
```

---

## 四、原模块到新模块的映射关系

| 原 VB.NET 模块 | Go 新模块 | 说明 |
|---|---|---|
| `Models/AppSettings.vb` | `internal/config/settings.go` | 去除 GUI 相关字段（颜色、RTB分组等） |
| `Models/CodeIssue.vb` | `internal/model/severity.go` + `internal/model/issue.go` | 拆分为严重级别常量和问题结构 |
| `Models/ScanResult.vb` | `internal/model/scan_result.go` | 去除 `IsChecked`/`CheckColour` 等 GUI 字段 |
| `Models/CodeTracker.vb` | `internal/model/code_tracker.go` | 按语言拆分为嵌套结构体 |
| `Models/ResultsTracker.vb` | `internal/model/results_tracker.go` | 添加 `sync.Mutex` 支持并发 |
| `Models/FileData.vb` | `internal/model/file_data.go` | 保留统计字段 |
| `Models/FileGroup.vb` | 移除 | GUI 分组展示专用，CLI 不需要 |
| `Models/IssueGroup.vb` | 移除 | GUI 分组展示专用，CLI 不需要 |
| `Models/SyncBlock.vb` | `internal/model/sync_block.go` | 保留（Java 线程安全检查需要） |
| `Models/PICVar.vb` | `internal/model/pic_var.go` | 保留（COBOL 检查需要） |
| `Modules/modMain.vb` | `internal/app/app.go` + `internal/scanner/code_checker.go` + `internal/config/loader.go` | 拆分为应用调度、代码检查、配置加载 |
| `Modules/modCppCheck.vb` | `internal/checker/cpp_checker.go` | 实现 `Checker` 接口 |
| `Modules/modJavaCheck.vb` | `internal/checker/java_checker.go` | 实现 `Checker` 接口 |
| `Modules/modCSharpCheck.vb` | `internal/checker/csharp_checker.go` | 实现 `Checker` 接口 |
| `Modules/modVBCheck.vb` | `internal/checker/vb_checker.go` | 实现 `Checker` 接口 |
| `Modules/modPHPCheck.vb` | `internal/checker/php_checker.go` | 实现 `Checker` 接口 |
| `Modules/modPlSqlCheck.vb` | `internal/checker/plsql_checker.go` | 实现 `Checker` 接口 |
| `Modules/modCobolCheck.vb` | `internal/checker/cobol_checker.go` | 实现 `Checker` 接口 |
| `Modules/modRCheck.vb` | `internal/checker/r_checker.go` | 实现 `Checker` 接口 |
| `Modules/modLogger.vb` | `slog` 标准库 | 使用 Go 内置结构化日志 |
| `Modules/modNativeMethods.vb` | 移除 | Windows 控制台 API，Go 不需要 |
| `Forms/frmMain.vb` (ScanFiles) | `internal/scanner/scanner.go` | 提取扫描循环逻辑 |
| `Forms/frmMain.vb` (ScanLine) | `internal/scanner/scanner.go` (splitLine) | 注释/代码分离 |
| `Forms/frmMain.vb` (CheckComment) | `internal/scanner/comment_checker.go` | 注释安全检查 |
| `Forms/frmMain.vb` (ListCodeIssue) | `internal/checker/checker.go` (IssueReporter) | 抽象为接口回调 |
| `Forms/frmMain.vb` (Export*) | `internal/reporter/*.go` | 各格式输出器 |
| `Forms/frmMain.vb` (其他 GUI) | 移除 | 所有 GUI 交互代码 |
| `Forms/frmOptions.vb` | 移除 | 选项通过 CLI flags 设置 |
| `Forms/frmBreakdown.vb` | 移除 | 可视化图表 |
| `Forms/frmFilter.vb` | 移除 | 通过 `--severity` flag 替代 |
| `Forms/frmSort.vb` | 移除 | 通过输出后处理替代 |
| `Forms/其他窗体` | 移除 | 所有 GUI 窗体 |
| `Config/*.conf` | `configs/*.conf` | 直接复用，格式不变 |

---

## 五、关键设计决策

### 5.1 解耦检查器与结果收集

**原设计问题**：所有语言检查模块直接调用 `frmMain.ListCodeIssue()`，与 UI 强耦合。

**新设计**：引入 `IssueReporter` 接口，检查器通过接口回调报告问题，由扫描引擎注入具体实现。

```
原: modJavaCheck → frmMain.ListCodeIssue() → UI ListView
新: JavaChecker  → IssueReporter.ReportIssue() → ResultsTracker → Reporter
```

### 5.2 并发扫描

**原设计**：单线程逐文件扫描，通过 `Application.DoEvents()` 防止 GUI 卡死。

**新设计**：使用 goroutine worker pool 并行扫描文件，`ResultsTracker` 加 `sync.Mutex` 保证线程安全。注意 `CodeTracker` 是文件级的，每个 goroutine 独立持有，无需加锁。

```
文件列表 → fileCh channel → N 个 worker goroutine → 各自持有 CodeTracker → 共享 ResultsTracker(加锁)
```

### 5.3 正则预编译

**原设计**：每行代码都重新构建正则表达式匹配不安全函数。

**新设计**：在 `NewCodeChecker` 时一次性预编译所有不安全函数的正则模式，扫描时直接使用编译后的 `*regexp.Regexp`，大幅提升性能。

### 5.4 配置文件嵌入

使用 Go 1.16+ 的 `embed` 特性将默认配置文件嵌入二进制：

```go
//go:embed configs/*.conf
var DefaultConfigs embed.FS
```

用户可通过 `--config-dir` 覆盖默认配置。

### 5.5 去除的功能清单

| 去除的功能 | 原位置 | 理由 |
|---|---|---|
| WinForms GUI 窗体 | `Forms/` 全部 | 纯 CLI 工具不需要 |
| 饼图/可视化图表 | `frmBreakdown` | CLI 不需要图表 |
| 拖拽文件 | `frmMain.DragDrop` | CLI 不需要 |
| Notepad++ 打开文件 | `modMain.LaunchNPP` | CLI 不需要 |
| 注册表读写 | `frmMain.GetSetting/SaveSetting` | Go 跨平台，不依赖 Windows 注册表 |
| ListView 颜色标记 | `ScanResult.CheckColour` | GUI 专用 |
| 结果分组视图 | `IssueGroup`/`FileGroup` | GUI 专用分组展示 |
| XML/CSV 结果导入 | `ImportResultsXML/CSV` | CLI 工具不需要重新加载结果到 GUI |
| 进度条 | `frmLoading` | 用控制台进度指示替代 |

---

## 六、各语言检查器详细检查项清单

以下是每个语言检查器需要完整移植的检查项：

### 6.1 C/C++ (`cpp_checker.go`)

| 检查函数 | 检查内容 |
|---|---|
| `TrackVarAssignments` | malloc/new 与 free/delete 匹配，固定值 malloc |
| `TrackUserVarAssignments` | argv、getenv、注册表等用户控制变量跟踪 |
| `CheckBuffer` | 缓冲区大小跟踪与溢出检测 |
| `CheckDestructorThrow` | 析构函数中抛出异常 |
| `CheckRace` | 竞态条件与 TOCTOU 漏洞 |
| `CheckPrintF` | printf 格式化字符串漏洞 |
| `CheckUnsafeTempFiles` | 临时文件使用静态/明显文件名 |
| `CheckReallocFailure` | realloc 失败后的 free 处理 |
| `CheckUnsafeSafe` | "安全"函数返回值的不安全使用 |
| `CheckCmdInjection` | 命令注入 |
| `CheckSigned` (Beta) | 有符号/无符号整数比较 |

### 6.2 Java (`java_checker.go`)

| 检查函数 | 检查内容 |
|---|---|
| `CheckServlet` | Servlet 识别与 Thread.sleep 检查 |
| `CheckSQLiValidation` | SQL 注入 |
| `CheckXSSValidation` | XSS |
| `CheckRunTime` | Runtime.exec 使用 |
| `CheckIsHttps` | HTTP/HTTPS URL 检查 |
| `CheckClone` | 不安全的 clone 实现 |
| `CheckSerialize` | 序列化/反序列化安全 |
| `IdentifyServlets` | Servlet 实例化跟踪 |
| `CheckModifiers` | 公共变量检查 |
| `CheckThreadIssues` | 线程安全管理 |
| `CheckUnsafeTempFiles` | 临时文件安全 |
| `CheckPrivileged` | 权限提升 |
| `CheckRequestDispatcher` | 请求分发器控制 |
| `CheckXXEExpansion` | XXE 扩展 |
| `CheckOverflow` | 整数溢出 |
| `CheckResourceRelease` | 资源释放 (try-finally) |
| `CheckInnerClasses` | 内部类 (可选) |
| `CheckAndroidStaticCrypto` | Android 静态加密 (可选) |
| `CheckAndroidIntent` | Android Intent (可选) |

### 6.3 C# (`csharp_checker.go`)

| 检查函数 | 检查内容 |
|---|---|
| `IdentifyLabels` | ASP Label 标识 |
| `CheckInputValidation` | .NET 输入验证 |
| `CheckSQLInjection` | SQL 注入 |
| `CheckXSS` | XSS |
| `CheckSecureStorage` | SecureString 使用 |
| `CheckIntOverflow` | 整数溢出 |
| `CheckLogDisplay` | 日志数据清洗 |
| `CheckFileRace` | 竞态条件/TOCTOU |
| `CheckSerialization` | 序列化安全 |
| `CheckHTTPRedirect` | HTTP 重定向安全 |
| `CheckRandomisation` | 随机数安全 |
| `CheckSAML2Validation` | SAML2 实现 |
| `CheckUnsafeTempFiles` | 临时文件安全 |
| `CheckUnsafeCode` | unsafe 指令 |
| `CheckThreadIssues` | 线程安全 |
| `CheckExecutable` | 命令执行 |
| `CheckWebConfig` | web.config 安全配置 |

### 6.4 PHP (`php_checker.go`)

| 检查函数 | 检查内容 |
|---|---|
| `CheckSQLInjection` | SQL 注入 |
| `CheckXSS` | XSS |
| `CheckLogDisplay` | 日志数据清洗 |
| `CheckRandomisation` | 随机数安全 |
| `CheckFileValidation` | 文件验证 |
| `CheckFileInclusion` | 文件包含 |
| `CheckExecutable` | 命令执行 |
| `CheckBackTick` | 反引号命令执行 |
| `CheckRegisterGlobals` | register_globals |
| `CheckParseStr` | parse_str 安全 |
| `CheckPhpIni` | php.ini 配置检查 |

### 6.5 其他语言

- **VB** (`vb_checker.go`)：保留 `modVBCheck` 中的所有检查
- **PL/SQL** (`plsql_checker.go`)：Oracle 加密、自治事务、视图安全、动态 SQL
- **COBOL** (`cobol_checker.go`)：PIC 变量安全、CICS API、SQL 注入、PROGRAM-ID
- **R** (`r_checker.go`)：保留 `modRCheck` 中的所有检查

---

## 七、输出格式设计

### 7.1 控制台文本输出（默认）

```
=== go-grepper Scan Results ===
Target: /path/to/project
Language: Java
Files scanned: 42

[CRITICAL] Potential SQL Injection
  File: /path/to/UserDAO.java:156
  Description: The application appears to allow SQL injection via a pre-prepared dynamic SQL statement.
  Code: String query = "SELECT * FROM users WHERE id=" + userId;

[HIGH] Comment Appears to Contain Password
  File: /path/to/Config.java:23
  Description: The comment appears to include a password.
  Code: // password=admin123

--- Summary ---
Total files: 42
Total lines: 12,345 (Code: 8,901 | Comments: 2,344 | Whitespace: 1,100)
Issues found: 15 (Critical: 2 | High: 3 | Medium: 5 | Standard: 3 | Low: 2)
```

### 7.2 JSON 输出

```json
{
  "metadata": {
    "target": "/path/to/project",
    "language": "Java",
    "scan_time": "2024-01-01T12:00:00Z",
    "version": "3.0.0"
  },
  "summary": {
    "files_scanned": 42,
    "total_lines": 12345,
    "code_lines": 8901,
    "comment_lines": 2344,
    "whitespace_lines": 1100,
    "issues_count": {
      "critical": 2,
      "high": 3,
      "medium": 5,
      "standard": 3,
      "low": 2
    }
  },
  "results": [
    {
      "title": "Potential SQL Injection",
      "description": "...",
      "file_name": "/path/to/UserDAO.java",
      "line_number": 156,
      "code_line": "String query = ...",
      "severity": 1,
      "severity_desc": "Critical"
    }
  ]
}
```

### 7.3 XML 输出（兼容原格式）

保持与原 VCG XML 导出格式兼容。

### 7.4 CSV 输出

```
Severity,Title,Description,File,Line,Code
Critical,Potential SQL Injection,...,/path/to/UserDAO.java,156,"String query = ..."
```

---

## 八、实施计划

### Phase 1：基础框架（预计 3 天）

- [ ] 初始化 Go 项目，配置 `go.mod`
- [ ] 实现 CLI 参数解析（`cobra`）
- [ ] 实现配置加载（`config/`）：`.conf` 文件解析、`badcomments.conf` 解析
- [ ] 实现数据模型（`model/`）：所有结构体定义
- [ ] 实现工具函数（`util/`）：字符串处理、文件遍历

### Phase 2：扫描引擎（预计 3 天）

- [ ] 实现扫描引擎核心（`scanner/scanner.go`）：文件遍历、注释/代码分离
- [ ] 实现通用代码检查器（`scanner/code_checker.go`）：不安全函数匹配
- [ ] 实现注释检查器（`scanner/comment_checker.go`）
- [ ] 实现文件级检查器（`scanner/file_checker.go`）
- [ ] 实现 `Checker` 接口和注册工厂

### Phase 3：语言检查器移植（预计 8 天，每语言约 1 天）

- [ ] C/C++ 检查器（最复杂，含内存跟踪）
- [ ] Java 检查器（最大，798 行，含 Servlet/线程/Android）
- [ ] C# 检查器（662 行，含 ASP.NET 特定检查）
- [ ] PHP 检查器（378 行，含 php.ini 检查）
- [ ] R 检查器
- [ ] COBOL 检查器（含 PIC 变量和 CICS）
- [ ] PL/SQL 检查器
- [ ] VB 检查器（最简单）

### Phase 4：输出与测试（预计 3 天）

- [ ] 实现 Text/JSON/XML/CSV 四种输出格式
- [ ] 并发扫描实现与调优
- [ ] 单元测试（每个检查器的关键检查项）
- [ ] 集成测试（使用原项目自身代码作为测试目标）
- [ ] 编写 `Makefile` 和 `README.md`

### 总计预估：约 17 个工作日

---

## 九、退出码设计

| 退出码 | 含义 |
|---|---|
| 0 | 扫描完成，未发现问题 |
| 1 | 扫描完成，发现安全问题 |
| 2 | 参数错误 |
| 3 | 目标路径不存在或无法访问 |
| 4 | 配置文件加载失败 |
| 5 | 输出文件写入失败 |

---

## 十、与原版的功能对比

| 功能 | 原 VCG (VB.NET) | go-grepper | 说明 |
|---|---|---|---|
| 8 种语言安全检查 | ✅ | ✅ | 完整保留 |
| 不安全函数配置匹配 | ✅ | ✅ | 完整保留，预编译优化 |
| 语言特定深度分析 | ✅ | ✅ | 完整保留 |
| 跨行上下文跟踪 | ✅ | ✅ | 完整保留 |
| 注释安全检查 | ✅ | ✅ | 完整保留 |
| 文件级检查 | ✅ | ✅ | 完整保留 |
| 7 级严重性 | ✅ | ✅ | 完整保留 |
| .conf 配置文件 | ✅ | ✅ | 格式兼容 |
| 命令行模式 | ✅ | ✅ | 增强（更多参数） |
| GUI 模式 | ✅ | ❌ | 移除 |
| 可视化图表 | ✅ | ❌ | 移除 |
| XML/CSV 导入 | ✅ | ❌ | 移除 |
| JSON 输出 | ❌ | ✅ | 新增 |
| 并行扫描 | ❌ | ✅ | 新增 |
| 跨平台 | ❌ (Windows) | ✅ | Go 天然跨平台 |
| 单二进制分发 | ❌ | ✅ | Go 静态编译 |
| 配置嵌入 | ❌ | ✅ | embed.FS |

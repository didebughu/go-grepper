package config

// Profile 配置文件结构（对应 .go-grepper.yaml）
type Profile struct {
	Language []string `yaml:"language"`

	Rules struct {
		Enable            []string `yaml:"enable"`
		Disable           []string `yaml:"disable"`
		DisableCategories []string `yaml:"disable-categories"`
	} `yaml:"rules"`

	Severity string `yaml:"severity"`

	Extensions      []string `yaml:"extensions"`
	ExcludeDirs     []string `yaml:"exclude-dirs"`
	ExcludePatterns []string `yaml:"exclude-patterns"`

	Output struct {
		Format string `yaml:"format"`
		File   string `yaml:"file"`
	} `yaml:"output"`

	Scan struct {
		ConfigOnly bool `yaml:"config-only"`
		Jobs       int  `yaml:"jobs"`
		Verbose    bool `yaml:"verbose"`
	} `yaml:"scan"`

	Java struct {
		Android bool `yaml:"android"`
	} `yaml:"java"`

	CPP struct {
		IncludeSigned bool `yaml:"include-signed"`
	} `yaml:"cpp"`

	COBOL struct {
		StartCol int  `yaml:"start-col"`
		ZOS      bool `yaml:"zos"`
	} `yaml:"cobol"`
}

// DefaultProfile 返回默认配置
func DefaultProfile() *Profile {
	p := &Profile{}
	p.Language = nil
	p.Severity = ""
	p.Output.Format = ""
	p.COBOL.StartCol = 0
	p.ExcludeDirs = nil
	return p
}

// DefaultConfigContent 返回默认配置文件内容
func DefaultConfigContent() string {
	return `# go-grepper 配置文件
# 文件名: .go-grepper.yaml

# ============================================================
# 扫描语言配置
# ============================================================
language:                         # 目标语言列表（为空则扫描所有语言）: cpp|java|csharp|vb|php|plsql|cobol|r
#  - cpp
#  - java

# ============================================================
# 规则配置
# ============================================================
rules:
  # 方式一：启用指定规则（白名单模式，仅运行列出的规则）
  # 当 enable 非空时，仅启用列出的规则，其他规则全部禁用
  enable: []

  # 方式二：禁用指定规则（黑名单模式，禁用列出的规则，其他全部启用）
  # 当 enable 为空时，disable 生效
  disable: []
  #  - "JAVA-INTOV-001"
  #  - "GEN-COMMENT-001"

  # 按类别批量禁用
  disable-categories: []
  #  - "COMMENT"
  #  - "RAND"

# ============================================================
# 严重级别过滤
# ============================================================
severity: all                     # 最低报告级别: critical|high|medium|standard|low|info|all

# ============================================================
# 文件过滤配置
# ============================================================
extensions: []

exclude-dirs:
  - "vendor"
  - "node_modules"
  - ".git"
  - "build"
  - "dist"
  - "target"
  - "bin"
  - "out"
  - "third_party"
  - "testdata"

exclude-patterns: []
#  - "*_test.java"
#  - "*.generated.java"

# ============================================================
# 输出配置
# ============================================================
output:
  format: text                    # 输出格式: text|json|xml|csv
  file: ""                        # 输出文件路径（为空则输出到 stdout）

# ============================================================
# 扫描行为配置
# ============================================================
scan:
  config-only: false
  jobs: 0                         # 并行扫描数（0 = 自动）
  verbose: false

# ============================================================
# 语言特定配置
# ============================================================
java:
  android: false

cpp:
  include-signed: false

cobol:
  start-col: 7
  zos: false
`
}

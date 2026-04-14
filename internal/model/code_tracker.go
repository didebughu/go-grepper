package model

// CodeTracker 代码状态跟踪器（每个文件一个实例）
// 对应原 CodeTracker.vb（66KB，项目中最大的模型文件）
// 实现跨行上下文分析的核心
type CodeTracker struct {
	// === 通用状态 ===
	HasValidator     bool     // 是否有验证器
	HasVulnSQLString bool     // 是否有脆弱的SQL字符串
	SQLStatements    []string // SQL语句列表

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
	IsServlet          bool        // 是否为 Servlet
	ServletName        string      // Servlet 名称
	ServletNames       []string    // Servlet 名称列表
	ImplementsClone    bool        // 是否实现 clone
	IsSerialize        bool        // 是否实现序列化
	IsDeserialize      bool        // 是否实现反序列化
	HasXXEEnabled      bool        // 是否启用 XXE
	IsFileOpen         bool        // 是否打开文件
	FileOpenLine       int         // 文件打开行号
	HasTry             bool        // 是否有 try 块
	HasResourceRelease bool        // 是否有资源释放
	HasFinalize        bool        // 是否有 finalize
	SyncBlocks         []SyncBlock // 同步块跟踪
	GetterSetters      []string    // getter/setter 方法
	HttpReqVariables   []string    // HTTP 请求变量
}

// CSharpTracker C# 状态跟踪
type CSharpTracker struct {
	InputVariables []string // 输入变量
	CookieValues   []string // Cookie 值
	AspLabels      []string // ASP Label 标识
	InUnsafeBlock  bool     // 是否在 unsafe 块内
}

// PHPTracker PHP 状态跟踪
type PHPTracker struct {
	HasDisableFunctions bool // 是否禁用函数
	HasRegisterGlobals  bool // 是否注册全局变量
}

// COBOLTracker COBOL 状态跟踪
type COBOLTracker struct {
	ProgramID string            // PROGRAM-ID
	PICs      map[string]PICVar // PIC 变量字典
	InCICS    bool              // 是否在 CICS 中
	InSQL     bool              // 是否在 SQL 中
}

// PLSQLTracker PL/SQL 状态跟踪
type PLSQLTracker struct {
	HasOracleEncrypt bool // 是否有 Oracle 加密
	IsAutonomous     bool // 是否自治事务
	InView           bool // 是否在视图中
}

// Reset 重置文件级状态（每扫描新文件时调用）
func (ct *CodeTracker) Reset() {
	ct.HasValidator = false
	ct.HasVulnSQLString = false
	ct.SQLStatements = nil

	// 重置 C/C++ 状态
	ct.CPP = CPPTracker{
		MemAssign: make(map[string]string),
		Buffers:   make(map[string]int),
		Integers:  make(map[string]int),
		Unsigned:  make(map[string]bool),
	}

	// 重置 Java 状态
	ct.Java = JavaTracker{}

	// 重置 C# 状态
	ct.CSharp = CSharpTracker{}

	// 重置 PHP 状态
	ct.PHP = PHPTracker{}

	// 重置 COBOL 状态
	ct.COBOL = COBOLTracker{
		PICs: make(map[string]PICVar),
	}

	// 重置 PL/SQL 状态
	ct.PLSQL = PLSQLTracker{}
}

// ResetProjectLevel 重置项目级状态（C/C++ 的内存字典等跨文件保留）
func (ct *CodeTracker) ResetProjectLevel() {
	ct.CPP.MemAssign = make(map[string]string)
}

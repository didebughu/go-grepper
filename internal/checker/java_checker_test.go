package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/model"
)

// ==================== checkServlet 测试 ====================

func TestJava_CheckServlet_ExtendsHttpServlet(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkServlet("public class MyServlet extends HttpServlet {", "MyServlet.java", 10, tracker, reporter)

	if !tracker.Java.IsServlet {
		t.Errorf("应标记为 Servlet")
	}
	if tracker.Java.ServletName != "MyServlet" {
		t.Errorf("Servlet 名称应为 MyServlet，实际: %s", tracker.Java.ServletName)
	}
}

func TestJava_CheckServlet_ThreadSleepInServlet(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkServlet("public class MyServlet extends HttpServlet {", "MyServlet.java", 10, tracker, reporter)
	checker.checkServlet("  Thread.sleep(1000);", "MyServlet.java", 20, tracker, reporter)

	if !reporter.hasIssueWithTitle("Thread.sleep()") {
		t.Errorf("应检测到 Servlet 中的 Thread.sleep，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSQLiValidation 测试 ====================

func TestJava_CheckSQLi_DynamicSQL(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLiValidation(`  rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);`, "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到动态 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityCritical) {
		t.Errorf("SQL 注入应为 Critical 级别")
	}
}

func TestJava_CheckSQLi_PreparedDynamicSQL(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 先构建动态 SQL
	checker.checkSQLiValidation(`  String sql = "SELECT * FROM users WHERE id=" + userId;`, "Test.java", 5, tracker, reporter)
	reporter.Issues = nil

	// 然后执行
	checker.checkSQLiValidation(`  rs = stmt.executeQuery(sql);`, "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到预准备的动态 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_CheckSQLi_WithValidator(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.HasValidator = true

	checker.checkSQLiValidation(`  rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);`, "Test.java", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("有验证器时不应报告 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_CheckSQLi_WithSanitize(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLiValidation(`  rs = stmt.executeQuery(sanitize(input));`, "Test.java", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("SQL Injection") {
		t.Errorf("使用 sanitize 后不应报告 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkXSSValidation 测试 ====================

func TestJava_CheckXSS_JSPGetParameter(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSSValidation(`<%= request.getParameter("name") %>`, "page.jsp", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential XSS") {
		t.Errorf("应检测到 JSP 中的 XSS，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_CheckXSS_JSPSessionAttribute(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSSValidation(`<%= session.getAttribute("user") %>`, "page.jsp", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential XSS") {
		t.Errorf("应检测到 JSP session 变量的 XSS，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_CheckXSS_HttpServletRequestTracking(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXSSValidation("  public void doGet(HttpServletRequest req, HttpServletResponse resp) {", "Test.java", 5, tracker, reporter)

	if len(tracker.Java.HttpReqVariables) == 0 {
		t.Errorf("应跟踪 HttpServletRequest 变量")
	}
}

func TestJava_CheckXSS_HttpReqGetParameter(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.Java.HttpReqVariables = append(tracker.Java.HttpReqVariables, "req")

	checker.checkXSSValidation(`  String name = req.getParameter("name");`, "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Poor Input Validation") {
		t.Errorf("应检测到未验证的 HttpServletRequest 使用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkRunTime 测试 ====================

func TestJava_CheckRunTime_ExecFromVariable(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRunTime("  Runtime.getRuntime().exec(cmd);", "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Gets Path from Variable") {
		t.Errorf("应检测到 Runtime.exec 使用变量路径，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_CheckRunTime_ExecWithLiteral(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkRunTime(`  Runtime.getRuntime().exec("ls -la");`, "Test.java", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("Gets Path from Variable") {
		t.Errorf("使用字面量的 exec 不应报告变量路径问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkIsHttps 测试 ====================

func TestJava_CheckIsHttps_HTTPConnection(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()

	checker.checkIsHttps(`  URLConnection conn = new URL("HTTP://example.com").openConnection();`, "Test.java", 10, reporter)

	if !reporter.hasIssueWithTitle("URL request sent over HTTP") {
		t.Errorf("应检测到 HTTP 请求，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkClone 测试 ====================

func TestJava_CheckClone_PublicClone(t *testing.T) {
	checker := &JavaChecker{}
	tracker := newTracker()

	checker.checkClone("  public Object clone() {", tracker)

	if !tracker.Java.ImplementsClone {
		t.Errorf("应标记实现了 clone")
	}
}

func TestJava_CheckClone_CloneNotSupported(t *testing.T) {
	checker := &JavaChecker{}
	tracker := newTracker()

	checker.checkClone("  public Object clone() {", tracker)
	checker.checkClone("    throw new java.lang.CloneNotSupportedException();", tracker)

	if tracker.Java.ImplementsClone {
		t.Errorf("抛出 CloneNotSupportedException 后不应标记 clone")
	}
}

// ==================== checkSerialize 测试 ====================

func TestJava_CheckSerialize_WriteObject(t *testing.T) {
	checker := &JavaChecker{}
	tracker := newTracker()

	checker.checkSerialize("  private void writeObject(ObjectOutputStream out) {", tracker)

	if !tracker.Java.IsSerialize {
		t.Errorf("应标记实现了序列化")
	}
}

func TestJava_CheckSerialize_ReadObject(t *testing.T) {
	checker := &JavaChecker{}
	tracker := newTracker()

	checker.checkSerialize("  private void readObject(ObjectInputStream in) {", tracker)

	if !tracker.Java.IsDeserialize {
		t.Errorf("应标记实现了反序列化")
	}
}

func TestJava_CheckSerialize_ThrowIOException(t *testing.T) {
	checker := &JavaChecker{}
	tracker := newTracker()

	checker.checkSerialize("  private void writeObject(ObjectOutputStream out) {", tracker)
	checker.checkSerialize("    throw new java.io.IOException();", tracker)

	if tracker.Java.IsSerialize {
		t.Errorf("抛出 IOException 后不应标记序列化")
	}
}

// ==================== checkModifiers 测试 ====================

func TestJava_CheckModifiers_PublicVariable(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkModifiers("  public String userName;", "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Public Variable") {
		t.Errorf("应检测到公共变量，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_CheckModifiers_PublicStaticVariable(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkModifiers("  public static String APP_NAME;", "Test.java", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("Public Variable") {
		t.Errorf("public static 变量不应报告，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUnsafeTempFiles 测试 ====================

func TestJava_CheckUnsafeTempFiles_HardcodedTemp(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()

	checker.checkUnsafeTempFiles(`  File f = new File("/tmp/myapp.dat");`, "Test.java", 10, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Temporary File") {
		t.Errorf("应检测到不安全的临时文件，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkXXEExpansion 测试 ====================

func TestJava_CheckXXE_JAXBWithSecureFalse(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXXEExpansion("import javax.xml.bind.JAXB;", "Test.java", 1, tracker, reporter)
	checker.checkXXEExpansion("  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);", "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("XML Entity Expansion Enabled") {
		t.Errorf("应检测到 XXE 启用，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_CheckXXE_JAXBWithSecureTrue(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkXXEExpansion("import javax.xml.bind.JAXB;", "Test.java", 1, tracker, reporter)
	checker.checkXXEExpansion("  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);", "Test.java", 10, tracker, reporter)

	if reporter.hasIssueWithTitle("XML Entity Expansion Enabled") {
		t.Errorf("设置 secure=true 不应报告 XXE，实际报告: %s", reporter.dumpIssues())
	}
	if tracker.Java.HasXXEEnabled {
		t.Errorf("设置 secure=true 后应清除 XXE 标记")
	}
}

// ==================== checkOverflow 测试 ====================

func TestJava_CheckOverflow_IntArithmetic(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkOverflow("  int result = a + b;", "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Operation on Primitive Data Type") {
		t.Errorf("应检测到原始类型运算，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkResourceRelease 测试 ====================

func TestJava_CheckResourceRelease_FileOutputWithoutFinally(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkResourceRelease("  FileOutputStream fos = new FileOutputStream(file);", 10, tracker)

	if !tracker.Java.IsFileOpen {
		t.Errorf("应标记文件已打开")
	}

	checker.CheckFileLevelIssues("Test.java", tracker, reporter)

	if !reporter.hasIssueWithTitle("Failure To Release Resources") {
		t.Errorf("应检测到资源未释放，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_CheckResourceRelease_FileOutputWithFinally(t *testing.T) {
	checker := &JavaChecker{}
	tracker := newTracker()

	checker.checkResourceRelease("  FileOutputStream fos = new FileOutputStream(file);", 10, tracker)
	checker.checkResourceRelease("  try {", 11, tracker)
	checker.checkResourceRelease("  } finally { fos.close();", 15, tracker)

	if tracker.Java.IsFileOpen {
		t.Errorf("finally 中关闭后不应标记文件打开")
	}
}

// ==================== checkAndroidStaticCrypto 测试 ====================

func TestJava_CheckAndroid_StaticCryptoKey(t *testing.T) {
	checker := &JavaChecker{IsAndroid: true}
	reporter := newMockReporter()

	checker.checkAndroidStaticCrypto(`  byte[] encrypted = CryptoAPI.encrypt("myKey", data);`, "Test.java", 10, reporter)

	if !reporter.hasIssueWithTitle("Static Crypto Keys") {
		t.Errorf("应检测到静态加密密钥，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckFileLevelIssues 测试 ====================

func TestJava_FileLevelIssues_Clone(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.Java.ImplementsClone = true

	checker.CheckFileLevelIssues("Test.java", tracker, reporter)

	if !reporter.hasIssueWithTitle("clone") {
		t.Errorf("应报告 clone 实现问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_FileLevelIssues_Serialization(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.Java.IsSerialize = true

	checker.CheckFileLevelIssues("Test.java", tracker, reporter)

	if !reporter.hasIssueWithTitle("Serialization") {
		t.Errorf("应报告序列化问题，实际报告: %s", reporter.dumpIssues())
	}
}

func TestJava_FileLevelIssues_Deserialization(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.Java.IsDeserialize = true

	checker.CheckFileLevelIssues("Test.java", tracker, reporter)

	if !reporter.hasIssueWithTitle("Deserialization") {
		t.Errorf("应报告反序列化问题，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSQLiValidation 补充测试 ====================

// 测试变量被 sanitize 后再使用不应误报 JAVA-SQLI-002
func TestJava_CheckSQLi_SanitizedVariableNotFalsePositive(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 第一步：追踪到 sql 变量
	checker.checkSQLiValidation(`  String sql = "SELECT * FROM users WHERE id=" + userId;`, "Test.java", 5, tracker, reporter)
	reporter.Issues = nil

	// 第二步：对 sql 变量进行 sanitize 清理
	checker.checkSQLiValidation(`  sql = sanitize(sql);`, "Test.java", 6, tracker, reporter)

	// 第三步：使用已清理的 sql 变量执行查询
	checker.checkSQLiValidation(`  rs = stmt.executeQuery(sql);`, "Test.java", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("变量被 sanitize 后不应报告 JAVA-SQLI-002，实际报告: %s", reporter.dumpIssues())
	}
	if tracker.HasVulnSQLString {
		t.Errorf("所有 SQL 变量被清理后 HasVulnSQLString 应为 false")
	}
}

// 测试变量名子串不应误报（如变量名 "sql" 不应匹配 "resultSql"）
func TestJava_CheckSQLi_VariableSubstringNoFalsePositive(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 追踪变量名为 "sql"
	checker.checkSQLiValidation(`  String sql = "SELECT * FROM users WHERE id=" + userId;`, "Test.java", 5, tracker, reporter)
	reporter.Issues = nil

	// 使用的变量名是 "resultSql"，不应匹配 "sql"
	checker.checkSQLiValidation(`  rs = stmt.executeQuery(resultSql);`, "Test.java", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("变量名子串不应触发 JAVA-SQLI-002，实际报告: %s", reporter.dumpIssues())
	}
}

// 测试使用 prepareStatement 的 SQLI-001 场景
func TestJava_CheckSQLi_PrepareStatementDynamic(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLiValidation(`  PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name='" + name + "'");`, "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到 prepareStatement 中的动态 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

// 测试不含引号或不含 + 的安全调用不应报告
func TestJava_CheckSQLi_SafeCallNoReport(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 使用参数化查询，不含 " 和 +
	checker.checkSQLiValidation(`  rs = stmt.executeQuery(preparedSQL);`, "Test.java", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("安全的参数化调用不应报告 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

// 测试 encode 也能触发 sanitize 过滤
func TestJava_CheckSQLi_EncodeFiltersSQLi(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSQLiValidation(`  rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + encode(userId));`, "Test.java", 10, tracker, reporter)

	if len(reporter.Issues) > 0 {
		t.Errorf("使用 encode 后不应报告 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

// 测试 validate 也能触发 sanitize 过滤并移除已追踪变量
func TestJava_CheckSQLi_ValidateRemovesTrackedVar(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 追踪 sql 变量
	checker.checkSQLiValidation(`  String sql = "SELECT * FROM users WHERE id=" + userId;`, "Test.java", 5, tracker, reporter)

	if len(tracker.SQLStatements) != 1 || tracker.SQLStatements[0] != "sql" {
		t.Errorf("应追踪到变量 sql，实际: %v", tracker.SQLStatements)
	}

	// validate 清理 sql 变量
	checker.checkSQLiValidation(`  sql = validate(sql);`, "Test.java", 6, tracker, reporter)

	if len(tracker.SQLStatements) != 0 {
		t.Errorf("validate 后应移除 sql 变量，实际: %v", tracker.SQLStatements)
	}
}

// 测试多个 SQL 变量中只移除被 sanitize 的那个
func TestJava_CheckSQLi_SanitizeRemovesOnlyMatchedVar(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 追踪两个变量
	checker.checkSQLiValidation(`  String sql1 = "SELECT * FROM users WHERE id=" + userId;`, "Test.java", 5, tracker, reporter)
	checker.checkSQLiValidation(`  String sql2 = "SELECT * FROM orders WHERE id=" + orderId;`, "Test.java", 6, tracker, reporter)

	if len(tracker.SQLStatements) != 2 {
		t.Errorf("应追踪到 2 个变量，实际: %v", tracker.SQLStatements)
	}

	// 只清理 sql1
	checker.checkSQLiValidation(`  sql1 = sanitize(sql1);`, "Test.java", 7, tracker, reporter)

	if len(tracker.SQLStatements) != 1 || tracker.SQLStatements[0] != "sql2" {
		t.Errorf("应只保留 sql2，实际: %v", tracker.SQLStatements)
	}

	// HasVulnSQLString 应仍为 true（还有 sql2）
	if !tracker.HasVulnSQLString {
		t.Errorf("仍有未清理的 SQL 变量，HasVulnSQLString 应为 true")
	}
}

// 测试使用 Spring JdbcTemplate query 方法的 SQLI-002 场景
func TestJava_CheckSQLi_SpringJdbcTemplateQuery(t *testing.T) {
	checker := &JavaChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	// 追踪 sql 变量
	checker.checkSQLiValidation(`  String sql = "SELECT * FROM users WHERE name='" + name + "'";`, "Test.java", 5, tracker, reporter)
	reporter.Issues = nil

	// 使用 Spring JdbcTemplate 执行
	checker.checkSQLiValidation(`  List<User> users = jdbcTemplate.query(sql, rowMapper);`, "Test.java", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Potential SQL Injection") {
		t.Errorf("应检测到 Spring JdbcTemplate 中的 SQL 注入，实际报告: %s", reporter.dumpIssues())
	}
}

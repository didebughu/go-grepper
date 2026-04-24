package checker

import (
	"regexp"
	"slices"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// JavaChecker Java 安全检查器（对应原 modJavaCheck）
type JavaChecker struct {
	IsAndroid         bool // 是否启用 Android 检查
	IsInnerClassCheck bool // 是否检查内部类
	IsFinalizeCheck   bool // 是否检查 finalize
}

func (c *JavaChecker) Language() int { return config.LangJava }

// 预编译正则表达式
var (
	// CheckServlet
	reJavaServlet = regexp.MustCompile(`(extends\s+HttpServlet|implements\s+Servlet)`)

	// CheckSQLiValidation
	reJavaSQLExec  = regexp.MustCompile(`\S*\.(prepareStatement|executeQuery|query|queryForObject|queryForList|queryForInt|queryForMap|update|getQueryString|createNativeQuery|createQuery)\s*\(`)
	reJavaSanitize = regexp.MustCompile(`(?i)(validate|encode|sanitize)`)

	// SQL 语句结构匹配：检测 SELECT...FROM...WHERE / UPDATE...SET...WHERE / DELETE...FROM...WHERE 中的拼接
	reJavaSQLStructConcat = regexp.MustCompile(`(?i)(?:select|update|delete|insert)\s+.*(?:from|set|into).*(?:where|values)\s+\w+\s*=[^"']*(?:"|').*(?:\+|%s)`)
	// 检测 String.format 拼接 SQL
	reJavaSQLStringFormat = regexp.MustCompile(`(?i)String\.format\s*\(\s*"[^"]*(?:select|update|delete|insert)[^"]*(?:where|values)[^"]*%s`)
	// 检测 .concat() 拼接
	reJavaSQLConcat = regexp.MustCompile(`(?i)(?:\.concat\s*\().*(?:select|update|delete|insert)`)
	// 检测注释行（排除误报）
	reJavaCommentLine = regexp.MustCompile(`^\s*(?://|/\*|\*)`)
	// 检测日志行（排除误报）
	reJavaLogLine = regexp.MustCompile(`(?i)\b(?:log|logger|LOG|LOGGER)\s*\.\s*(?:debug|info|warn|error|trace)\s*\(`)

	// CheckXSSValidation
	reJavaGetParam    = regexp.MustCompile(`\s*\S*\s*={1}?\s*\S*\s*\brequest\b\.\bgetParameter\b`)
	reJavaJSPGetParam = regexp.MustCompile(`<%=\s*\w+\.getParameter\s*\(`)
	reJavaJSPSession  = regexp.MustCompile(`<%=\s*\S*\bsession\b\.\bgetAttribute\b\s*\(`)
	reJavaJSPEscXML   = regexp.MustCompile(`<c:\bout\b\s*\S*\s*=\s*['"]\s*\$\{\s*\S*\}\s*['"]\s*\bescapeXML\b\s*=\s*['"]\bfalse\b['"]\s*/>`)

	// CheckClone
	reJavaClone = regexp.MustCompile(`\bpublic\b\s+\w+\s+\bclone\b\s*\(`)

	// CheckModifiers
	reJavaPublicClass = regexp.MustCompile(`\bpublic\b\s+\bclass\b`)

	// CheckUnsafeTempFiles
	reJavaTempFile = regexp.MustCompile(`\bnew\b\s+File\s*\(\s*"*\S*(temp|tmp)\S*"\s*\)`)

	// CheckXXEExpansion
	reJavaJAXBImport = regexp.MustCompile(`import\s+javax\.xml\.bind\.JAXB\s*;`)
	reJavaXXEFalse   = regexp.MustCompile(`\(\s*(XMLConstants\.FEATURE_SECURE_PROCESSING|XMLInputFactory\.SUPPORT_DTD)\s*,\s*false\s*\)`)
	reJavaXXETrue    = regexp.MustCompile(`\(\s*(XMLConstants\.FEATURE_SECURE_PROCESSING|XMLInputFactory\.SUPPORT_DTD)\s*,\s*true\s*\)`)

	// CheckOverflow
	reJavaPrimitive = regexp.MustCompile(`\b(short|int|long)\b\s+\w+\s*(=|;)`)

	// CheckResourceRelease
	reJavaFileOutput = regexp.MustCompile(`\bnew\b\s+\bFileOutputStream\b\s*\(`)

	// CheckAndroid
	reAndroidCrypto = regexp.MustCompile(`CryptoAPI\.(encrypt|decrypt)\s*\("\w+"\s*,`)
	reAndroidIntent = regexp.MustCompile(`\bIntent\b\s+\w+\s*=\s*new\s+Intent\s*\(\s*\)`)

	// CheckPrivileged
	reJavaDoPriv       = regexp.MustCompile(`\bAccessController\b\.\bdoPrivileged\b`)
	reJavaPublicMethod = regexp.MustCompile(`\bpublic\b\s+\w+\s+\w+\s*\w*\s*\(`)

	// CheckRequestDispatcher
	reJavaReqDisp = regexp.MustCompile(`\.\bgetRequestDispatcher\b\s*\(`)

	// Synchronized
	reJavaSyncObj   = regexp.MustCompile(`\bsynchronized\b\s*\(\s*\w+\s*\)`)
	reJavaSyncBlock = regexp.MustCompile(`\bsynchronized\b\s*\S*\s*\S*\s*\(`)
)

func (c *JavaChecker) CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	lowerFile := strings.ToLower(fileName)

	// 检查 Struts 验证器
	if !tracker.HasValidator && strings.HasSuffix(lowerFile, ".xml") &&
		strings.Contains(strings.ToLower(codeLine), "<plug-in") && strings.Contains(strings.ToLower(codeLine), ".validator") {
		tracker.HasValidator = true
	}

	c.checkServlet(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkSQLiValidation(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkXSSValidation(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkRunTime(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkIsHttps(codeLine, fileName, lineNumber, reporter)
	c.checkClone(codeLine, tracker)
	c.checkSerialize(codeLine, tracker)
	c.checkModifiers(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkUnsafeTempFiles(codeLine, fileName, lineNumber, reporter)
	c.checkXXEExpansion(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkOverflow(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkResourceRelease(codeLine, lineNumber, tracker)

	if c.IsAndroid {
		c.checkAndroidStaticCrypto(codeLine, fileName, lineNumber, reporter)
	}
}

func (c *JavaChecker) CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.Java.ImplementsClone {
		reporter.ReportIssue("JAVA-SERIAL-001", "Class Implements Public 'clone' Method",
			"Cloning allows an attacker to instantiate a class without running any of the class constructors by deploying hostile code in the JVM.",
			fileName, model.SeverityMedium, "", 0)
	}
	if tracker.Java.IsSerialize {
		reporter.ReportIssue("JAVA-SERIAL-002", "Class Implements Serialization",
			"Serialization can be used to save objects (and their state) when the JVM is switched off. The process flattens the object, saving it as a stream of bytes, allowing an attacker to view the inner state of an object and potentially view private attributes.",
			fileName, model.SeverityMedium, "", 0)
	}
	if tracker.Java.IsDeserialize {
		reporter.ReportIssue("JAVA-SERIAL-003", "Class Implements Deserialization",
			"Deserialization allows the creation of an object from a stream of bytes, allowing the instantiation of a legitimate class without calling its constructor. This behaviour can be abused by an attacker to instantiate or replicate an object's state.",
			fileName, model.SeverityMedium, "", 0)
	}
	if tracker.Java.HasXXEEnabled {
		reporter.ReportIssue("JAVA-CONF-001", "XML Entity Expansion",
			"The class Uses JAXB and may allow XML entity expansion, which can render the application vulnerable to the use of XML bombs.",
			fileName, model.SeverityStandard, "", 0)
	}
	if tracker.Java.IsFileOpen {
		reporter.ReportIssue("JAVA-RESRC-001", "Failure To Release Resources In All Cases",
			"There appears to be no 'finally' block to release resources if an exception occurs, potentially resulting in DoS conditions from excessive resource consumption.",
			fileName, model.SeverityMedium, "", tracker.Java.FileOpenLine)
		if !tracker.Java.HasTry {
			reporter.ReportIssue("JAVA-RESRC-002", "FileStream Opened Without Exception Handling",
				"There appears to be no 'try' block to safely open the filestream, potentially resulting in server-side exceptions.",
				fileName, model.SeverityMedium, "", tracker.Java.FileOpenLine)
		}
	}
	if !tracker.Java.HasResourceRelease {
		reporter.ReportIssue("JAVA-RESRC-001", "Failure To Release Resources In All Cases",
			"There appears to be no release of resources in the 'finally' block, potentially resulting in DoS conditions from excessive resource consumption.",
			fileName, model.SeverityMedium, "", tracker.Java.FileOpenLine)
	}
}

// checkServlet 检查 Servlet 相关问题
func (c *JavaChecker) checkServlet(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if !tracker.Java.IsServlet && reJavaServlet.MatchString(codeLine) {
		tracker.Java.IsServlet = true
		parts := reJavaServlet.Split(codeLine, 2)
		servletName := util.GetLastItem(parts[0], " ")
		if servletName != "" {
			tracker.Java.ServletName = servletName
			found := false
			for _, n := range tracker.Java.ServletNames {
				if n == servletName {
					found = true
					break
				}
			}
			if !found {
				tracker.Java.ServletNames = append(tracker.Java.ServletNames, servletName)
			}
		}
	}

	if tracker.Java.IsServlet && strings.Contains(codeLine, "Thread.sleep") {
		reporter.ReportIssue("JAVA-MISC-001", "Use of Thread.sleep() within a Java servlet",
			"The use of Thread.sleep() within Java servlets is discouraged.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	}
}

// checkSQLiValidation 检查 SQL 注入
func (c *JavaChecker) checkSQLiValidation(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.HasValidator {
		return
	}

	// 排除注释行和日志行，减少误报
	trimmedLine := strings.TrimSpace(codeLine)
	if reJavaCommentLine.MatchString(trimmedLine) || reJavaLogLine.MatchString(codeLine) {
		return
	}

	lowerLine := strings.ToLower(codeLine)

	// 检测风险 SQL 拼接字符串并追踪变量
	// 策略1：正则匹配 SQL 语句结构（SELECT/UPDATE/DELETE/INSERT...WHERE）中的拼接
	// 策略2：关键字匹配（sql/query/hql/jpql 等变量名 + 字符串拼接特征）
	isRiskySQLConcat := false

	// 策略1：SQL 结构匹配 —— 直接检测 SQL 语句中 WHERE/VALUES 子句的拼接
	if reJavaSQLStructConcat.MatchString(codeLine) {
		isRiskySQLConcat = true
	}

	// 策略2：String.format 拼接 SQL
	if !isRiskySQLConcat && reJavaSQLStringFormat.MatchString(codeLine) {
		isRiskySQLConcat = true
	}

	// 策略3：.concat() 拼接 SQL
	if !isRiskySQLConcat && reJavaSQLConcat.MatchString(codeLine) && strings.Contains(codeLine, "\"") {
		isRiskySQLConcat = true
	}

	// 策略4：传统关键字匹配（保留兼容性，但增加更严格的约束）
	// 要求变量名或赋值左侧包含 sql/query/hql/jpql 等关键字
	if !isRiskySQLConcat && strings.Contains(codeLine, "=") && strings.Contains(codeLine, "\"") && strings.Contains(codeLine, "+") {
		// 提取赋值左侧部分进行关键字匹配，避免右侧字符串内容干扰
		eqIdx := strings.Index(codeLine, "=")
		if eqIdx > 0 {
			leftPart := strings.ToLower(codeLine[:eqIdx])
			if strings.Contains(leftPart, "sql") || strings.Contains(leftPart, "query") ||
				strings.Contains(leftPart, "hql") || strings.Contains(leftPart, "jpql") {
				isRiskySQLConcat = true
			}
		}
	}

	// 策略5：+= 拼接追加 SQL 片段（如 sql += " WHERE id=" + id）
	if !isRiskySQLConcat && strings.Contains(codeLine, "+=") && strings.Contains(codeLine, "\"") {
		if strings.Contains(lowerLine, "where") || strings.Contains(lowerLine, "and ") ||
			strings.Contains(lowerLine, "or ") || strings.Contains(lowerLine, "set ") {
			isRiskySQLConcat = true
		}
	}

	if isRiskySQLConcat {
		varName := util.GetVarName(codeLine, false)
		tracker.HasVulnSQLString = true
		if regexp.MustCompile(`^[a-zA-Z0-9_]*$`).MatchString(varName) {
			found := slices.Contains(tracker.SQLStatements, varName)
			if !found {
				tracker.SQLStatements = append(tracker.SQLStatements, varName)
			}
		}
	}

	if reJavaSanitize.MatchString(codeLine) {
		// 如果当前行包含 sanitize/validate/encode 等清理操作，
		// 需要从已追踪的 SQL 变量列表中移除被清理的变量
		for i := len(tracker.SQLStatements) - 1; i >= 0; i-- {
			if strings.Contains(codeLine, tracker.SQLStatements[i]) {
				tracker.SQLStatements = append(tracker.SQLStatements[:i], tracker.SQLStatements[i+1:]...)
			}
		}
		if len(tracker.SQLStatements) == 0 {
			tracker.HasVulnSQLString = false
		}
		return
	}

	if reJavaSQLExec.MatchString(codeLine) {
		// 匹配 " 符号说明语句中有字符串字面量，匹配 + 号匹配拼接
		if strings.Contains(codeLine, "\"") && strings.Contains(codeLine, "+") {
			reporter.ReportIssue("JAVA-SQLI-001", "Potential SQL Injection",
				"The application appears to allow SQL injection via dynamic SQL statements.",
				fileName, model.SeverityCritical, codeLine, lineNumber)
		} else if tracker.HasVulnSQLString {
			for _, sqlVar := range tracker.SQLStatements {
				// 使用单词边界匹配，避免变量名子串误报
				// 例如变量名 "sql" 不应匹配 "resultSql" 或注释中的 "sql"
				// regexp.QuoteMeta 对字符串中所有正则表达式的元字符进行转义，使其在正则表达式中被当作普通字面量字符来匹配。
				reVarMatch := regexp.MustCompile(`\b` + regexp.QuoteMeta(sqlVar) + `\b`)
				if reVarMatch.MatchString(codeLine) {
					reporter.ReportIssue("JAVA-SQLI-002", "Potential SQL Injection",
						"The application appears to allow SQL injection via a pre-prepared dynamic SQL statement.",
						fileName, model.SeverityCritical, codeLine, lineNumber)
					break
				}
			}
		}
	}
}

// checkXSSValidation 检查 XSS 漏洞
func (c *JavaChecker) checkXSSValidation(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.HasValidator {
		return
	}

	lowerFile := strings.ToLower(fileName)

	// 识别 HttpServletRequest 变量
	if strings.Contains(codeLine, "HttpServletRequest ") && !strings.Contains(codeLine, "import ") {
		parts := strings.SplitN(codeLine, "HttpServletRequest ", 2)
		varName := strings.TrimSpace(parts[1])
		if varName != "" {
			sepParts := regexp.MustCompile(`[,;=\s+]`).Split(varName, 2)
			varName = strings.TrimSpace(sepParts[0])
			if varName != "" {
				for i, v := range tracker.Java.HttpReqVariables {
					if v == varName {
						_ = i
						return
					}
				}
				tracker.Java.HttpReqVariables = append(tracker.Java.HttpReqVariables, varName)
			}
		}
	}

	// JSP 中的 getParameter
	if strings.HasSuffix(lowerFile, ".jsp") && reJavaGetParam.MatchString(codeLine) {
		varName := util.GetVarName(codeLine, true)
		if regexp.MustCompile(`^[a-zA-Z0-9_]*$`).MatchString(varName) {
			tracker.Java.GetterSetters = append(tracker.Java.GetterSetters, varName)
		}
	}

	// JSP 中直接输出 getParameter
	if strings.HasSuffix(lowerFile, ".jsp") && reJavaJSPGetParam.MatchString(codeLine) {
		reporter.ReportIssue("JAVA-XSS-001", "Potential XSS",
			"The application appears to reflect a HTTP request parameter to the screen with no apparent validation or sanitisation.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}

	// 检查 HttpRequest 变量使用
	for _, reqVar := range tracker.Java.HttpReqVariables {
		if strings.Contains(codeLine, reqVar) {
			if reJavaSanitize.MatchString(codeLine) {
				// 已清理
				continue
			}
			if strings.Contains(codeLine, "getCookies") || strings.Contains(codeLine, "getHeader") ||
				strings.Contains(codeLine, "getQueryString") || strings.Contains(codeLine, "getParameter") ||
				strings.Contains(codeLine, "getRequestUR") {
				if strings.HasSuffix(lowerFile, ".jsp") {
					reporter.ReportIssue("JAVA-XSS-002", "Potential XSS",
						"The application appears to use data contained in the HttpServletRequest without validation or sanitisation.",
						fileName, model.SeverityHigh, codeLine, lineNumber)
				} else {
					reporter.ReportIssue("JAVA-INPUT-001", "Poor Input Validation",
						"The application appears to use data contained in the HttpServletRequest without validation or sanitisation.",
						fileName, model.SeverityHigh, codeLine, lineNumber)
				}
			}
		}
	}

	// JSP session 变量
	if strings.HasSuffix(lowerFile, ".jsp") && reJavaJSPSession.MatchString(codeLine) {
		reporter.ReportIssue("JAVA-XSS-003", "Potential XSS",
			"The JSP displays a session variable directly to the screen.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}

	// JSP escapeXML=false
	if strings.HasSuffix(lowerFile, ".jsp") && reJavaJSPEscXML.MatchString(codeLine) {
		reporter.ReportIssue("JAVA-XSS-004", "Potential XSS",
			"The JSP displays application data without applying XML encoding.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

// checkRunTime 检查 Runtime.exec
func (c *JavaChecker) checkRunTime(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if strings.Contains(codeLine, "Runtime.") {
		// 标记 Runtime 使用
	}

	if (strings.Contains(codeLine, ".exec ") || strings.Contains(codeLine, ".exec(")) && !strings.Contains(codeLine, "\"") {
		reporter.ReportIssue("JAVA-CMDI-001", "java.lang.Runtime.exec Gets Path from Variable",
			"The pathname used in the call appears to be loaded from a variable. Check the code manually to ensure that malicious filenames cannot be submitted by an attacker.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

// checkIsHttps 检查 HTTP 安全
func (c *JavaChecker) checkIsHttps(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if strings.Contains(codeLine, "URLConnection") && strings.Contains(codeLine, "HTTP:") {
		reporter.ReportIssue("JAVA-NET-001", "URL request sent over HTTP:",
			"The URL used in the HTTP request appears to be unencrypted. Check the code manually to ensure that sensitive data is not being submitted.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	} else if (strings.Contains(codeLine, "URLConnection(") || strings.Contains(codeLine, "URLConnection (")) && !strings.Contains(codeLine, "\"") {
		reporter.ReportIssue("JAVA-NET-002", "URL Request Gets Path from Variable",
			"The URL used in the HTTP request appears to be loaded from a variable. Check the code manually to ensure that malicious URLs cannot be submitted by an attacker.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	}
}

// checkClone 检查克隆实现
func (c *JavaChecker) checkClone(codeLine string, tracker *model.CodeTracker) {
	if reJavaClone.MatchString(codeLine) {
		tracker.Java.ImplementsClone = true
	}
	if tracker.Java.ImplementsClone && strings.Contains(codeLine, "throw new java.lang.CloneNotSupportedException") {
		tracker.Java.ImplementsClone = false
	}
}

// checkSerialize 检查序列化
func (c *JavaChecker) checkSerialize(codeLine string, tracker *model.CodeTracker) {
	if strings.Contains(codeLine, " writeObject") {
		tracker.Java.IsSerialize = true
	}
	if strings.Contains(codeLine, " readObject") {
		tracker.Java.IsDeserialize = true
	}

	if tracker.Java.IsSerialize && strings.Contains(codeLine, "throw new java.io.IOException") {
		tracker.Java.IsSerialize = false
	}
	if tracker.Java.IsDeserialize && strings.Contains(codeLine, "throw new java.io.IOException") {
		tracker.Java.IsDeserialize = false
	}
}

// checkModifiers 检查访问修饰符
func (c *JavaChecker) checkModifiers(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if strings.Contains(codeLine, "public ") && strings.Contains(codeLine, ";") &&
		!strings.Contains(codeLine, "{") && !strings.Contains(codeLine, "abstract ") &&
		!strings.Contains(codeLine, "class ") && !strings.Contains(codeLine, "static ") {
		varName := util.GetVarName(codeLine, false)
		if regexp.MustCompile(`^[a-zA-Z0-9_]*$`).MatchString(varName) {
			reporter.ReportIssue("JAVA-PRIV-001", "Class Contains Public Variable: "+varName,
				"The class variable may be accessed and modified by other classes without the use of getter/setter methods. It is considered unsafe to have public fields or methods in a class unless required.",
				fileName, model.SeverityStandard, codeLine, lineNumber)
		}
	} else if c.IsFinalizeCheck && strings.Contains(codeLine, "public ") && strings.Contains(codeLine, "class ") && !strings.Contains(codeLine, "final ") {
		reporter.ReportIssue("JAVA-PRIV-002", "Public Class Not Declared as Final",
			"The class is not declared as final as per OWASP recommendations. Non-Final classes can allow an attacker to extend a class in a malicious manner.",
			fileName, model.SeverityPossiblySafe, codeLine, lineNumber)
	}
}

// checkUnsafeTempFiles 检查不安全的临时文件
func (c *JavaChecker) checkUnsafeTempFiles(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reJavaTempFile.MatchString(codeLine) {
		reporter.ReportIssue("JAVA-TMPF-001", "Unsafe Temporary File Allocation",
			"The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition or a symbolic link attack.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkXXEExpansion 检查 XXE 扩展
func (c *JavaChecker) checkXXEExpansion(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if !tracker.Java.HasXXEEnabled && reJavaJAXBImport.MatchString(codeLine) {
		tracker.Java.HasXXEEnabled = true
	}

	if tracker.Java.HasXXEEnabled && reJavaXXEFalse.MatchString(codeLine) {
		reporter.ReportIssue("JAVA-CONF-001", "XML Entity Expansion Enabled",
			"The FEATURE_SECURE_PROCESSING attribute is set to false which can render the application vulnerable to the use of XML bombs.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if tracker.Java.HasXXEEnabled && reJavaXXETrue.MatchString(codeLine) {
		tracker.Java.HasXXEEnabled = false
	}
}

// checkOverflow 检查整数溢出
func (c *JavaChecker) checkOverflow(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reJavaPrimitive.MatchString(codeLine) {
		// 标记存在原始类型
	}

	if (strings.Contains(codeLine, "+") || strings.Contains(codeLine, "-") || strings.Contains(codeLine, "*")) &&
		reJavaPrimitive.MatchString(codeLine) {
		reporter.ReportIssue("JAVA-INTOV-001", "Operation on Primitive Data Type",
			"The code appears to be carrying out a mathematical operation on a primitive data type. In some circumstances this can result in an overflow and unexpected behaviour.",
			fileName, model.SeverityLow, codeLine, lineNumber)
	}
}

// checkResourceRelease 检查资源释放
func (c *JavaChecker) checkResourceRelease(codeLine string, lineNumber int, tracker *model.CodeTracker) {
	if !tracker.Java.IsFileOpen && reJavaFileOutput.MatchString(codeLine) {
		tracker.Java.IsFileOpen = true
		tracker.Java.HasResourceRelease = false
		tracker.Java.FileOpenLine = lineNumber
	}

	if tracker.Java.IsFileOpen && strings.Contains(codeLine, "try") {
		tracker.Java.HasTry = true
	} else if tracker.Java.IsFileOpen && strings.Contains(codeLine, "finally") {
		tracker.Java.IsFileOpen = false
		if strings.Contains(codeLine, ".close(") {
			tracker.Java.HasResourceRelease = true
		}
	}
}

// checkAndroidStaticCrypto 检查 Android 静态加密
func (c *JavaChecker) checkAndroidStaticCrypto(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reAndroidCrypto.MatchString(codeLine) {
		reporter.ReportIssue("JAVA-CRYPTO-001", "Static Crypto Keys in Use",
			"The application appears to be using static crypto keys. The absence of secure key storage may allow unauthorised decryption of data.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

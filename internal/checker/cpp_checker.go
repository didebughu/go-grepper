package checker

import (
	"regexp"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// CPPChecker C/C++ 安全检查器（对应原 modCppCheck）
type CPPChecker struct {
	IncludeSigned bool // 是否包含有符号/无符号比较检查（Beta）
}

func (c *CPPChecker) Language() int { return config.LangCPP }

// 预编译正则表达式
var (
	// TrackVarAssignments
	reMallocFixed = regexp.MustCompile(`\b(malloc|xmalloc)\b\s*\(\s*\d+\s*\)`)
	reMallocCall  = regexp.MustCompile(`\bmalloc\b`)
	reNewCall     = regexp.MustCompile(`\bnew\b`)
	reFreeCall    = regexp.MustCompile(`\bfree\b`)
	reDeleteCall  = regexp.MustCompile(`\bdelete\b`)

	// TrackUserVarAssignments
	reArgvAssign     = regexp.MustCompile(`\w+\s*=\s*\bargv\b\s*\[`)
	reEnvAssign      = regexp.MustCompile(`\w+\s*=\s*\b(getenv|GetPrivateProfileString|GetPrivateProfileInt)\b\s*\(`)
	reRegistryAssign = regexp.MustCompile(`\w+\s*=\s*Registry::\w+->OpenSubKey`)

	// CheckBuffer
	reIntType      = regexp.MustCompile(`\b(short|int|long|uint16|uint32|size_t|UINT|INT|LONG)\b`)
	reCharBuffer   = regexp.MustCompile(`\b(char|TCHAR|BYTE)\b`)
	reStrCopyFuncs = regexp.MustCompile(`\b(strcpy|strlcpy|strcat|strlcat|strncpy|strncat|sprintf|memcpy|memmove)\b`)

	// CheckSigned
	reUnsignedType   = regexp.MustCompile(`\b(unsigned|UNSIGNED|size_t|uint16|uint32)\b`)
	reTemplateAngle1 = regexp.MustCompile(`<\s*\w+\s*>`)
	reTemplateAngle2 = regexp.MustCompile(`<\s*\w+\s+\w+\s*>`)

	// CheckUnsafeSafe
	reSafeFuncAssign = regexp.MustCompile(`\w+\s*=\s*\b(snprintf|strlcpy|strlcat|strlprintf|std_strlcpy|std_strlcat|std_strlprintf)\b`)

	// CheckDestructorThrow
	reDestructor = regexp.MustCompile(`(::~|::\s+~|\s+~)`)

	// CheckRace
	reLstatCall = regexp.MustCompile(`\b(lstat|stat)\b\s*[\( ]`)

	// CheckPrintF
	rePrintfVuln = regexp.MustCompile(`\bprintf\b\s*\(\s*\w+\s*\)`)

	// CheckUnsafeTempFiles
	reCppTempFile = regexp.MustCompile(`=\s*(_open|open|fopen|opendir)\s*\(\s*"*\S*(temp|tmp)\S*"\s*,\s*\S*\s*\)`)

	// CheckReallocFailure
	reReallocCall  = regexp.MustCompile(`\brealloc\b\s*\(`)
	reReallocSplit = regexp.MustCompile(`=\s*\brealloc\b\s*\(`)
	reBreakReturn  = regexp.MustCompile(`\b(break|return|exit)\b`)

	// CheckCmdInjection
	reSysCall   = regexp.MustCompile(`\b(system|popen|execlp)\b\s*\(`)
	reSysGetenv = regexp.MustCompile(`\b(system|popen|execlp)\b\s*\(\s*\bgetenv\b`)
	reSysStrcat = regexp.MustCompile(`\b(system|popen|execlp)\b\s*\(\s*\b(strcat|strncat)\b`)
)

func (c *CPPChecker) CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	c.trackVarAssignments(codeLine, fileName, lineNumber, tracker, reporter)
	c.trackUserVarAssignments(codeLine, tracker)
	c.checkBuffer(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkDestructorThrow(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkRace(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkPrintF(codeLine, fileName, lineNumber, reporter)
	c.checkUnsafeTempFiles(codeLine, fileName, lineNumber, reporter)
	c.checkReallocFailure(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkUnsafeSafe(codeLine, fileName, lineNumber, reporter)
	c.checkCmdInjection(codeLine, fileName, lineNumber, tracker, reporter)

	if c.IncludeSigned {
		c.checkSigned(codeLine, fileName, lineNumber, tracker, reporter)
	}
}

func (c *CPPChecker) CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter) {
	// 检查未释放的内存分配
	if len(tracker.CPP.MemAssign) > 0 {
		reporter.ReportMemoryIssue(tracker.CPP.MemAssign)
	}
}

// trackVarAssignments 跟踪 malloc/new 和 free/delete 的匹配
func (c *CPPChecker) trackVarAssignments(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if strings.Contains(codeLine, "malloc ") || strings.Contains(codeLine, "malloc(") {
		// 跟踪 malloc 分配
		c.addMalloc(codeLine, tracker)

		// 检查使用固定值而非变量类型大小的 malloc
		if reMallocFixed.MatchString(codeLine) {
			reporter.ReportIssue("CPP-BUFOV-001", "malloc( ) Using Fixed Value Instead of Variable Type Size",
				"The code uses a fixed value for malloc instead of the variable type size which is dependent on the platform (e.g. sizeof(int) instead of '4'). This can result in too much or too little memory being assigned with unpredictable results such as performance impact, overflows or memory corruption.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}

	if strings.Contains(codeLine, "new ") || strings.Contains(codeLine, "new(") {
		c.addNew(codeLine, tracker)
	}

	if strings.Contains(codeLine, "free ") || strings.Contains(codeLine, "free(") {
		c.addFree(codeLine, tracker)
	}
	if strings.Contains(codeLine, "delete ") || strings.Contains(codeLine, "delete(") {
		c.addDelete(codeLine, tracker)
	}
}

// addMalloc 记录 malloc 分配
func (c *CPPChecker) addMalloc(codeLine string, tracker *model.CodeTracker) {
	if strings.Contains(codeLine, "=") {
		parts := strings.SplitN(codeLine, "=", 2)
		varName := util.GetLastItem(parts[0], " ")
		varName = strings.TrimLeft(varName, "*")
		varName = strings.TrimSpace(varName)
		if varName != "" {
			tracker.CPP.MemAssign[varName] = "malloc"
		}
	}
}

// addNew 记录 new 分配
func (c *CPPChecker) addNew(codeLine string, tracker *model.CodeTracker) {
	if strings.Contains(codeLine, "=") {
		parts := strings.SplitN(codeLine, "=", 2)
		varName := util.GetLastItem(parts[0], " ")
		varName = strings.TrimLeft(varName, "*")
		varName = strings.TrimSpace(varName)
		if varName != "" {
			tracker.CPP.MemAssign[varName] = "new"
		}
	}
}

// addFree 记录 free 释放
func (c *CPPChecker) addFree(codeLine string, tracker *model.CodeTracker) {
	if strings.Contains(codeLine, "(") {
		parts := strings.SplitN(codeLine, "(", 2)
		if len(parts) > 1 {
			varName := util.GetFirstItem(parts[1], ")")
			varName = strings.TrimLeft(varName, "*")
			varName = strings.TrimSpace(varName)
			if varName != "" {
				delete(tracker.CPP.MemAssign, varName)
			}
		}
	}
}

// addDelete 记录 delete 释放
func (c *CPPChecker) addDelete(codeLine string, tracker *model.CodeTracker) {
	// delete 可能是 delete ptr 或 delete(ptr)
	if strings.Contains(codeLine, "(") {
		parts := strings.SplitN(codeLine, "(", 2)
		if len(parts) > 1 {
			varName := util.GetFirstItem(parts[1], ")")
			varName = strings.TrimLeft(varName, "*")
			varName = strings.TrimSpace(varName)
			if varName != "" {
				delete(tracker.CPP.MemAssign, varName)
			}
		}
	} else if reDeleteCall.MatchString(codeLine) {
		parts := regexp.MustCompile(`\bdelete\b\s+`).Split(codeLine, 2)
		if len(parts) > 1 {
			varName := util.GetFirstItem(parts[1], ";")
			varName = strings.TrimLeft(varName, "*")
			varName = strings.TrimSpace(varName)
			if varName != "" {
				delete(tracker.CPP.MemAssign, varName)
			}
		}
	}
}

// trackUserVarAssignments 跟踪用户控制的变量
func (c *CPPChecker) trackUserVarAssignments(codeLine string, tracker *model.CodeTracker) {
	var varName string

	if reArgvAssign.MatchString(codeLine) || reEnvAssign.MatchString(codeLine) || reRegistryAssign.MatchString(codeLine) {
		parts := strings.SplitN(codeLine, "=", 2)
		varName = util.GetLastItem(parts[0], " ")
	}

	if varName != "" {
		for _, v := range tracker.CPP.UserVariables {
			if v == varName {
				return
			}
		}
		tracker.CPP.UserVariables = append(tracker.CPP.UserVariables, varName)
	}
}

// checkBuffer 跟踪缓冲区大小并检查溢出
func (c *CPPChecker) checkBuffer(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	// 跟踪整数变量
	if strings.Contains(codeLine, "=") && !strings.Contains(codeLine, "==") &&
		!strings.Contains(codeLine, "*") && !strings.Contains(codeLine, "[") &&
		reIntType.MatchString(codeLine) {
		c.addInteger(codeLine, tracker)
	} else if regexp.MustCompile(`\s*\w+\s*=`).MatchString(codeLine) && !strings.Contains(codeLine, "==") {
		parts := strings.SplitN(codeLine, "=", 2)
		varName := util.GetLastItem(parts[0], " ")
		if _, ok := tracker.CPP.Integers[varName]; ok {
			c.addInteger(codeLine, tracker)
		}
	}

	// 跟踪固定缓冲区
	if reCharBuffer.MatchString(codeLine) && strings.Contains(codeLine, "[") && strings.Contains(codeLine, "]") {
		c.addBuffer(codeLine, tracker)
	}
	if reCharBuffer.MatchString(codeLine) && strings.Contains(codeLine, "*") {
		c.addCharStar(codeLine, tracker)
	}

	// 检查 strcpy 等函数的潜在缓冲区溢出
	if reStrCopyFuncs.MatchString(codeLine) {
		c.checkOverflow(codeLine, fileName, lineNumber, tracker, reporter)
	}
}

// addInteger 添加整数变量跟踪
func (c *CPPChecker) addInteger(codeLine string, tracker *model.CodeTracker) {
	if !strings.Contains(codeLine, "=") {
		return
	}
	parts := strings.SplitN(codeLine, "=", 2)
	varName := util.GetLastItem(parts[0], " ")
	value := strings.TrimSpace(parts[1])
	value = strings.TrimRight(value, ";")
	value = strings.TrimSpace(value)
	if varName != "" {
		tracker.CPP.Integers[varName] = 0 // 简化处理，仅记录存在
	}
}

// addBuffer 添加缓冲区跟踪
func (c *CPPChecker) addBuffer(codeLine string, tracker *model.CodeTracker) {
	if !strings.Contains(codeLine, "[") {
		return
	}
	parts := strings.SplitN(codeLine, "[", 2)
	varName := util.GetLastItem(parts[0], " ")
	if len(parts) > 1 && strings.Contains(parts[1], "]") {
		sizeStr := strings.SplitN(parts[1], "]", 2)[0]
		sizeStr = strings.TrimSpace(sizeStr)
		// 简化处理
		if varName != "" {
			tracker.CPP.Buffers[varName] = len(sizeStr)
		}
	}
}

// addCharStar 添加 char* 跟踪
func (c *CPPChecker) addCharStar(codeLine string, tracker *model.CodeTracker) {
	if strings.Contains(codeLine, "*") {
		parts := strings.SplitN(codeLine, "*", 2)
		if len(parts) > 1 {
			varName := util.GetFirstItem(parts[1], " ")
			varName = strings.TrimRight(varName, ";=,)")
			varName = strings.TrimSpace(varName)
			if varName != "" {
				tracker.CPP.Buffers[varName] = 0 // char* 大小未知
			}
		}
	}
}

// checkOverflow 检查缓冲区溢出
func (c *CPPChecker) checkOverflow(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	// 简化的溢出检查：检查目标缓冲区是否在跟踪列表中
	for bufName := range tracker.CPP.Buffers {
		if strings.Contains(codeLine, bufName) {
			reporter.ReportIssue("CPP-BUFOV-002", "Potential Buffer Overflow",
				"The code appears to copy data into a fixed-size buffer '"+bufName+"'. Check that the source data will not exceed the buffer size.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
			return
		}
	}
}

// checkSigned 检查有符号/无符号比较
func (c *CPPChecker) checkSigned(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	// 识别无符号整数
	if reUnsignedType.MatchString(codeLine) {
		if strings.Contains(codeLine, "=") && !strings.Contains(codeLine, "==") {
			parts := strings.SplitN(codeLine, "=", 2)
			varName := util.GetLastItem(parts[0], " ")
			if varName != "" {
				tracker.CPP.Unsigned[varName] = true
			}
		}
	}

	// 检查有符号/无符号比较
	if (strings.Contains(codeLine, "==") || strings.Contains(codeLine, "!=") ||
		strings.Contains(codeLine, "<") || strings.Contains(codeLine, ">")) &&
		!strings.Contains(codeLine, "->") && !strings.Contains(codeLine, ">>") &&
		!strings.Contains(codeLine, "<<") && !strings.Contains(codeLine, "<>") &&
		!reTemplateAngle1.MatchString(codeLine) && !reTemplateAngle2.MatchString(codeLine) {

		if c.checkSignedComp(codeLine, tracker) {
			reporter.ReportIssue("CPP-SIGN-001", "Signed/Unsigned Comparison",
				"The code appears to compare a signed numeric value with an unsigned numeric value. This behaviour can return unexpected results as negative numbers will be forcibly cast to large positive numbers.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
		}
	}
}

// checkSignedComp 检查是否存在有符号/无符号比较
func (c *CPPChecker) checkSignedComp(codeLine string, tracker *model.CodeTracker) bool {
	// 简化检查：查看比较运算符两侧是否有一个是无符号变量
	for varName := range tracker.CPP.Unsigned {
		if strings.Contains(codeLine, varName) {
			return true
		}
	}
	return false
}

// checkUnsafeSafe 检查"安全"函数返回值的不安全使用
func (c *CPPChecker) checkUnsafeSafe(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reSafeFuncAssign.MatchString(codeLine) {
		reporter.ReportIssue("CPP-MISC-001", "Potential Misuse of Safe Function",
			"The code appears to assign the return value of a 'safe' function to a variable. This value represents the amount of bytes that the function attempted to write, not the amount actually written. Any use of this value for pointer arithmetic or similar operations may result in memory corruption.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

// checkDestructorThrow 检查析构函数中的异常抛出
func (c *CPPChecker) checkDestructorThrow(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	// 检查是否进入/退出析构函数
	if !tracker.CPP.InDestructor && reDestructor.MatchString(codeLine) && !strings.Contains(codeLine, ";") {
		tracker.CPP.InDestructor = true
	}

	// 检查析构函数中的异常
	if tracker.CPP.InDestructor {
		if strings.Contains(codeLine, "throw") {
			reporter.ReportIssue("CPP-RESRC-001", "Exception Throw in Destructor",
				"Throwing an exception causes an exit from the function and should not be carried out in a class destructor as it prevents memory from being safely deallocated. If the destructor is being called due to an exception thrown elsewhere in the application this will result in unexpected termination of the application with possible loss or corruption of data.",
				fileName, model.SeverityStandard, codeLine, lineNumber)
		}
		// 简化的花括号跟踪：遇到 } 退出析构函数
		if strings.Contains(codeLine, "}") && !strings.Contains(codeLine, "{") {
			tracker.CPP.InDestructor = false
		}
	}
}

// checkRace 检查 TOCTOU 竞态条件
func (c *CPPChecker) checkRace(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reLstatCall.MatchString(codeLine) && !strings.Contains(codeLine, "fopen") && !strings.Contains(codeLine, "opendir") {
		tracker.CPP.Buffers["__toctou_check__"] = lineNumber
	} else if _, ok := tracker.CPP.Buffers["__toctou_check__"]; ok {
		if strings.Contains(codeLine, "fopen") || strings.Contains(codeLine, "opendir") {
			checkLine := tracker.CPP.Buffers["__toctou_check__"]
			distance := lineNumber - checkLine
			if distance > 1 {
				reporter.ReportIssue("CPP-RACE-001", "Potential TOCTOU (Time Of Check, Time Of Use) Vulnerability",
					"The lstat()/stat() check occurs before fopen() is called. The longer the time between the check and the fopen(), the greater the likelihood that the check will no longer be valid.",
					fileName, model.SeverityStandard, codeLine, lineNumber)
			}
			delete(tracker.CPP.Buffers, "__toctou_check__")
		}
	}
}

// checkPrintF 检查 printf 格式字符串漏洞
func (c *CPPChecker) checkPrintF(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if rePrintfVuln.MatchString(codeLine) && !strings.Contains(codeLine, ",") && !strings.Contains(codeLine, "\"") {
		reporter.ReportIssue("CPP-MISC-002", "Possible printf( ) Format String Vulnerability",
			"The call to printf appears to be printing a variable directly to standard output. Check whether this variable can be controlled or altered by the user to determine whether a format string vulnerability exists.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	}
}

// checkUnsafeTempFiles 检查不安全的临时文件
func (c *CPPChecker) checkUnsafeTempFiles(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reCppTempFile.MatchString(codeLine) {
		reporter.ReportIssue("CPP-TMPF-001", "Unsafe Temporary File Allocation",
			"The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition (an attacker creates a file with the same name between the application's creation and attempted usage) or a symbolic link attack where an attacker creates a symbolic link at the temporary file location.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkReallocFailure 检查 realloc 失败时的内存泄漏
func (c *CPPChecker) checkReallocFailure(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reReallocCall.MatchString(codeLine) {
		parts := reReallocSplit.Split(codeLine, 2)
		if len(parts) < 2 {
			return
		}

		dest := util.GetLastItem(parts[0], " ")
		dest = strings.TrimLeft(dest, "*")
		dest = strings.TrimSpace(dest)

		src := util.GetFirstItem(parts[1], ",")
		src = strings.TrimLeft(src, "*")
		src = strings.TrimSpace(src)

		if dest != "" && dest == src {
			reporter.ReportIssue("CPP-MEMLK-002", "Dangerous Use of realloc( )",
				"The source and destination buffers are the same. A failure to resize the buffer will set the pointer to NULL, possibly causing unpredictable behaviour.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

// checkCmdInjection 检查命令注入
func (c *CPPChecker) checkCmdInjection(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if !reSysCall.MatchString(codeLine) {
		return
	}

	// 检查是否使用了用户控制的变量
	found := false
	for _, varName := range tracker.CPP.UserVariables {
		if strings.Contains(codeLine, varName) {
			reporter.ReportIssue("CPP-CMDI-001", "User Controlled Variable Used on System Command Line",
				"The application appears to allow the use of an unvalidated user-controlled variable ["+varName+"] when executing a system command.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
			found = true
			break
		}
	}

	if !found && reSysGetenv.MatchString(codeLine) {
		reporter.ReportIssue("CPP-CMDI-002", "Application Variable Used on System Command Line",
			"The application appears to allow the use of an unvalidated system variable when executing a system command.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if !found && ((!strings.Contains(codeLine, "\"")) ||
		(strings.Contains(codeLine, "\"") && strings.Contains(codeLine, "+")) ||
		reSysStrcat.MatchString(codeLine)) {
		reporter.ReportIssue("CPP-CMDI-002", "Application Variable Used on System Command Line",
			"The application appears to allow the use of an unvalidated variable when executing a system command. Carry out a manual check to determine whether the variable is user-controlled.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

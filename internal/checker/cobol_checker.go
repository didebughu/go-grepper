package checker

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// COBOLChecker COBOL 安全检查器（对应原 modCobolCheck）
type COBOLChecker struct {
	StartCol int  // COBOL 起始列号
	IsZOS    bool // 是否启用 z/OS CICS 检查
}

func (c *COBOLChecker) Language() int { return config.LangCOBOL }

// 预编译正则表达式
var (
	// CheckIdentificationDivision
	reProgramIDDot  = regexp.MustCompile(`PROGRAM-ID\.\s+\w+`)
	reProgramID     = regexp.MustCompile(`PROGRAM-ID\s+\w+`)
	reProgramIDWord = regexp.MustCompile(`\bPROGRAM-ID\b`)

	// TrackVarAssignments
	rePICVar    = regexp.MustCompile(`[\w-]+\s+\bPIC\b`)
	reFillerPIC = regexp.MustCompile(`\bFILLER\b\s+\bPIC\b`)
	reAccept    = regexp.MustCompile(`\bACCEPT\b\s+\w+`)
	reCompute   = regexp.MustCompile(`\bCOMPUTE\b\s+\w+\s*=\s*\w+`)

	// CheckCICS
	reEndExec    = regexp.MustCompile(`\bEND\b-\bEXEC\b\s*\.`)
	reExecCICS   = regexp.MustCompile(`\bEXEC\b\s+\bCICS\b`)
	reCICSSend   = regexp.MustCompile(`\s+\bSEND\b\s+`)
	reCICSUnsafe = regexp.MustCompile(`\s+(ACCEPT|LOSE|DELETE|DISPLAY\s+UPON\s+CONSOLE|DISPLAY\s+UPON\s+SYSPUNCH|MERGE|OPEN|READ|RERUN|REWRITE|START|WRITE)\s+`)

	// CheckSQL
	reExecSQL = regexp.MustCompile(`\bEXEC\b\s+\bSQL\b`)

	// CheckBuffer
	reMoveToVar = regexp.MustCompile(`\bMOVE\b\s+[\w-]+\s+\bTO\b\s+[\w-]+`)

	// CheckSigned
	reCOBOLUnsigned = regexp.MustCompile(`\bUNSIGNED\b`)
	rePICSigned     = regexp.MustCompile(`[\w-]+\s+\bPIC\b\s+S`)
	rePICNumeric    = regexp.MustCompile(`[\w-]+\s+\bPIC\b\s+9`)

	// CheckFileAccess
	reCOBOLOpen = regexp.MustCompile(`\bOPEN\b\s+\w+`)

	// CheckLogDisplay
	reCOBOLLog = regexp.MustCompile(`(?i)(logerror|logger|logging|\blog\b)`)

	// CheckFileRace
	reCOBOLFileCheck = regexp.MustCompile(`\bCALL\b\s+'CBL_CHECK_FILE_EXIST'`)
	reCOBOLOpenStmt  = regexp.MustCompile(`\bOPEN\b`)

	// CheckRandomisation
	reCOBOLRandom   = regexp.MustCompile(`\bRANDOM\b`)
	reCOBOLIsRandom = regexp.MustCompile(`\bIS\b\s+\bRANDOM\b`)

	// CheckUnsafeTempFiles
	reCOBOLTempFile = regexp.MustCompile(`(?i)\bOPEN\b\s+\w+\s+\S*temp`)

	// CheckDynamicCall
	reCOBOLStaticCall  = regexp.MustCompile(`\bCALL\b\s+('|")\w+('|")\s+\bUSING\b`)
	reCOBOLDynamicCall = regexp.MustCompile(`\bCALL\b\s+\w+\s+\bUSING\b`)

	// 密码管理
	reCOBOLPassword = regexp.MustCompile(`(LOWER|UPPER)-CASE\s*\(\S*(Password|password|PASSWORD|pwd|PWD|passwd|PASSWD)`)
)

func (c *COBOLChecker) CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	c.checkIdentificationDivision(codeLine, fileName, lineNumber, tracker, reporter)
	c.trackVarAssignments(codeLine, tracker)
	c.checkCICS(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkSQL(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkBuffer(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkSigned(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkFileAccess(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkLogDisplay(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkFileRace(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkRandomisation(codeLine, fileName, lineNumber, reporter)
	c.checkUnsafeTempFiles(codeLine, fileName, lineNumber, reporter)
	c.checkDynamicCall(codeLine, fileName, lineNumber, tracker, reporter)

	if reCOBOLPassword.MatchString(codeLine) {
		reporter.ReportIssue("COBOL-PASSWD-001", "Unsafe Password Management",
			"The application appears to handle passwords in a case-insensitive manner. This can greatly increase the likelihood of successful brute-force and/or dictionary attacks.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

func (c *COBOLChecker) CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.COBOL.ProgramID == "" {
		reporter.ReportIssue("COBOL-MISC-001", "File Has No PROGRAM-ID",
			"The file does not appear to include a PROGRAM-ID. The lack of a properly formatted identification division can make code more difficult to read and maintain.",
			fileName, model.SeverityLow, "", 0)
	}
}

// checkIdentificationDivision 检查 PROGRAM-ID
func (c *COBOLChecker) checkIdentificationDivision(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.COBOL.ProgramID == "" && (reProgramIDDot.MatchString(codeLine) || reProgramID.MatchString(codeLine)) {
		var parts []string
		if reProgramIDDot.MatchString(codeLine) {
			parts = regexp.MustCompile(`PROGRAM-ID\.\s+`).Split(codeLine, 2)
		} else {
			parts = regexp.MustCompile(`PROGRAM-ID\s+`).Split(codeLine, 2)
		}

		if len(parts) < 2 {
			return
		}

		id := util.GetFirstItem(parts[1], " ")
		id = strings.Trim(id, ".")
		tracker.COBOL.ProgramID = id

		// 检查文件名是否匹配 PROGRAM-ID
		base := filepath.Base(fileName)
		ext := filepath.Ext(base)
		nameNoExt := strings.TrimSuffix(base, ext)

		if !strings.EqualFold(nameNoExt, tracker.COBOL.ProgramID) {
			if strings.Contains(tracker.COBOL.ProgramID, ".") && strings.EqualFold(base, tracker.COBOL.ProgramID) {
				reporter.ReportIssue("COBOL-MISC-003", "PROGRAM-ID Includes File Extension",
					"The PROGRAM-ID is the filename plus its extension. This is a slight violation of convention as the filename should be based on the PROGRAM-ID, not the reverse.",
					fileName, model.SeverityLow, codeLine, lineNumber)
			} else {
				reporter.ReportIssue("COBOL-MISC-002", "Filename Does Not Match PROGRAM-ID",
					"The filename does not match PROGRAM-ID which can make code more difficult to read and maintain.",
					fileName, model.SeverityLow, codeLine, lineNumber)
			}
		}
	} else if tracker.COBOL.ProgramID != "" && reProgramIDWord.MatchString(codeLine) {
		reporter.ReportIssue("COBOL-MISC-004", "Multiple Use of PROGRAM-ID",
			"The code has more than one PROGRAM-ID which can make code more difficult to read and maintain (Original ID:"+tracker.COBOL.ProgramID+").",
			fileName, model.SeverityLow, codeLine, lineNumber)
	}
}

// trackVarAssignments 跟踪变量赋值
func (c *COBOLChecker) trackVarAssignments(codeLine string, tracker *model.CodeTracker) {
	if rePICVar.MatchString(codeLine) && !reFillerPIC.MatchString(codeLine) {
		c.addPIC(codeLine, tracker)
	} else if reAccept.MatchString(codeLine) {
		parts := regexp.MustCompile(`\bACCEPT\b`).Split(codeLine, 2)
		if len(parts) > 1 {
			temp := strings.TrimRight(parts[1], ".")
			varName := util.GetFirstItem(temp, " ")
			if regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(varName) {
				// 简化：使用 PICs 字典记录输入变量
				if _, exists := tracker.COBOL.PICs[varName]; !exists {
					tracker.COBOL.PICs[varName] = model.PICVar{VarName: varName, Length: 0}
				}
			}
		}
	}
}

// addPIC 添加 PIC 变量
func (c *COBOLChecker) addPIC(codeLine string, tracker *model.CodeTracker) {
	parts := regexp.MustCompile(`\s+\bPIC\b\s+`).Split(strings.TrimSpace(codeLine), 2)
	if len(parts) < 2 {
		return
	}

	varName := util.GetLastItem(parts[0], " ")
	desc := util.GetFirstItem(parts[1], " ")
	desc = strings.Trim(desc, ".")

	if varName == "" || desc == "" {
		return
	}

	pic := model.PICVar{VarName: varName}

	if rePICSigned.MatchString(codeLine) {
		pic.IsSigned = true
		pic.IsNumeric = true
	} else if rePICNumeric.MatchString(codeLine) {
		pic.IsNumeric = true
	}

	if len(desc) > 1 {
		if strings.Contains(desc, "(") {
			inner := util.GetLastItem(desc, "(")
			if strings.Contains(inner, ")") {
				lenStr := util.GetFirstItem(inner, ")")
				// 简化处理
				pic.Length = len(lenStr)
			}
		} else {
			pic.Length = len(desc)
		}
	} else {
		pic.Length = 1
	}

	tracker.COBOL.PICs[varName] = pic
}

// checkCICS 检查 CICS 交互
func (c *COBOLChecker) checkCICS(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if !c.IsZOS {
		return
	}

	if tracker.COBOL.InCICS {
		if reEndExec.MatchString(codeLine) {
			tracker.COBOL.InCICS = false
		} else if reCICSSend.MatchString(codeLine) {
			reporter.ReportIssue("COBOL-CMDI-001", "Redirection of Output From CICS Application",
				"The code appears to send output to an external CICS application. Manually check to ensure that no privacy violation is occurring.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
		} else if reCICSUnsafe.MatchString(codeLine) {
			reporter.ReportIssue("COBOL-CMDI-002", "Use of Unsafe Command within CICS",
				"The code appears to use a command which is unsafe when running under CICS (See IBM references).",
				fileName, model.SeverityStandard, codeLine, lineNumber)
		}
	} else {
		if reExecCICS.MatchString(codeLine) {
			tracker.COBOL.InCICS = true
		}
	}
}

// checkSQL 检查 SQL 注入
func (c *COBOLChecker) checkSQL(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if tracker.COBOL.InSQL {
		if reEndExec.MatchString(codeLine) {
			tracker.COBOL.InSQL = false
		} else {
			// 检查输入变量是否在 SQL 中使用
			for picName := range tracker.COBOL.PICs {
				if strings.Contains(codeLine, picName) {
					reporter.ReportIssue("COBOL-SQLI-001", "User Controlled Variable Used within SQL Statement",
						"The code appears to allow the use of a variable from JCL or user input, when executing a SQL statement: "+picName+". Manually check to ensure the parameter is used safely.",
						fileName, model.SeverityHigh, codeLine, lineNumber)
					break
				}
			}
		}
	} else {
		if reExecSQL.MatchString(codeLine) {
			tracker.COBOL.InSQL = true
		}
	}
}

// checkBuffer 检查缓冲区溢出
func (c *COBOLChecker) checkBuffer(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reMoveToVar.MatchString(codeLine) {
		parts := regexp.MustCompile(`\s+\bTO\b\s+`).Split(codeLine, 2)
		if len(parts) < 2 {
			return
		}
		srcVar := util.GetLastItem(parts[0], " ")
		dstVar := util.GetFirstItem(parts[1], " ")
		dstVar = strings.Trim(dstVar, ".")

		if srcVar != "" && dstVar != "" {
			srcPIC, srcOK := tracker.COBOL.PICs[srcVar]
			dstPIC, dstOK := tracker.COBOL.PICs[dstVar]
			if srcOK && dstOK && srcPIC.Length > dstPIC.Length {
				reporter.ReportIssue("COBOL-BUFOV-001", "PIC Length Mismatch",
					"The code appears to copy a PIC variable to a destination that is shorter than the source PIC. This can cause unexpected behaviour or results.",
					fileName, model.SeverityHigh, codeLine, lineNumber)
			}
		}
	}
}

// checkSigned 检查有符号/无符号比较
func (c *COBOLChecker) checkSigned(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reMoveToVar.MatchString(codeLine) {
		parts := regexp.MustCompile(`\s+\bTO\b\s+`).Split(codeLine, 2)
		if len(parts) < 2 {
			return
		}
		srcVar := util.GetLastItem(parts[0], " ")
		dstVar := util.GetFirstItem(parts[1], " ")
		dstVar = strings.Trim(dstVar, ".")

		if srcVar != "" && dstVar != "" {
			srcPIC, srcOK := tracker.COBOL.PICs[srcVar]
			dstPIC, dstOK := tracker.COBOL.PICs[dstVar]
			if srcOK && dstOK {
				if srcPIC.IsSigned && !dstPIC.IsSigned {
					reporter.ReportIssue("COBOL-SIGN-001", "PIC Sign Mismatch",
						"The code appears to copy a PIC variable to a destination PIC variable but only one of them is signed. This can cause unexpected behaviour or results.",
						fileName, model.SeverityHigh, codeLine, lineNumber)
				} else if !srcPIC.IsNumeric && dstPIC.IsNumeric {
					reporter.ReportIssue("COBOL-SIGN-002", "PIC Mismatch",
						"The code appears to copy an alphanumeric PIC variable to a numeric PIC variable. This can cause a loss of sign for types intended to be signed numeric, and unexpected behaviour or results.",
						fileName, model.SeverityHigh, codeLine, lineNumber)
				}
			}
		}
	}
}

// checkFileAccess 检查文件访问
func (c *COBOLChecker) checkFileAccess(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reCOBOLOpen.MatchString(codeLine) {
		for picName := range tracker.COBOL.PICs {
			if regexp.MustCompile(`\bOPEN\b\s+\w*` + regexp.QuoteMeta(picName)).MatchString(codeLine) {
				reporter.ReportIssue("COBOL-FILE-001", "User Controlled File/Directory Name",
					"The code uses a user-controlled value when opening a file/directory. Manually inspect the code to ensure safe usage.",
					fileName, model.SeverityLow, codeLine, lineNumber)
				break
			}
		}
	}
}

// checkLogDisplay 检查日志输出
func (c *COBOLChecker) checkLogDisplay(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	lowerLine := strings.ToLower(codeLine)

	if regexp.MustCompile(`(?i)(validate|encode|sanitize|sanitise)`).MatchString(codeLine) && !strings.Contains(lowerLine, "password") {
		return
	}

	if reCOBOLLog.MatchString(codeLine) && strings.Contains(lowerLine, "password") {
		logIdx := strings.Index(lowerLine, "log")
		pwIdx := strings.Index(lowerLine, "password")
		if logIdx < pwIdx {
			reporter.ReportIssue("COBOL-LOG-001", "Application Appears to Log User Passwords",
				"The application appears to write user passwords to logfiles creating a risk of credential theft.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
		}
	} else if reCOBOLLog.MatchString(codeLine) {
		for picName := range tracker.COBOL.PICs {
			if strings.Contains(codeLine, picName) {
				reporter.ReportIssue("COBOL-LOG-002", "Unsanitized Data Written to Logs",
					"The application appears to write unsanitized data to its logfiles. If logs are viewed by a browser-based application this exposes risk of XSS attacks.",
					fileName, model.SeverityMedium, codeLine, lineNumber)
				break
			}
		}
	}
}

// checkFileRace 检查 TOCTOU 竞态条件
func (c *COBOLChecker) checkFileRace(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reCOBOLFileCheck.MatchString(codeLine) {
		tracker.COBOL.InSQL = false // 复用标记
		// 使用特殊 PIC 记录 TOCTOU 状态
		tracker.COBOL.PICs["__toctou__"] = model.PICVar{Length: lineNumber}
	} else if _, ok := tracker.COBOL.PICs["__toctou__"]; ok {
		if reCOBOLOpenStmt.MatchString(codeLine) {
			checkLine := tracker.COBOL.PICs["__toctou__"].Length
			distance := lineNumber - checkLine
			if distance > 1 {
				reporter.ReportIssue("COBOL-RACE-001", "Potential TOCTOU (Time Of Check, Time Of Use) Vulnerability",
					"The check for the file's existence occurs before the file/directory is accessed. The longer the time between the check and the OPEN call, the greater the likelihood that the check will no longer be valid.",
					fileName, model.SeverityStandard, codeLine, lineNumber)
			}
			delete(tracker.COBOL.PICs, "__toctou__")
		}
	}
}

// checkRandomisation 检查随机数安全
func (c *COBOLChecker) checkRandomisation(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reCOBOLRandom.MatchString(codeLine) && !reCOBOLIsRandom.MatchString(codeLine) &&
		!strings.Contains(codeLine, "-RANDOM") && !strings.Contains(codeLine, "RANDOM-") {
		reporter.ReportIssue("COBOL-RAND-001", "Use of Deterministic Pseudo-Random Values",
			"The code appears to use the RANDOM function. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	}
}

// checkUnsafeTempFiles 检查不安全的临时文件
func (c *COBOLChecker) checkUnsafeTempFiles(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reCOBOLTempFile.MatchString(codeLine) {
		reporter.ReportIssue("COBOL-TMPF-001", "Unsafe Temporary File Allocation",
			"The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkDynamicCall 检查动态函数调用
func (c *COBOLChecker) checkDynamicCall(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reCOBOLStaticCall.MatchString(codeLine) {
		// 静态调用，检查用户输入参数
		for picName := range tracker.COBOL.PICs {
			if strings.Contains(codeLine, picName) {
				reporter.ReportIssue("COBOL-CMDI-005", "User Controlled Variable Used as Parameter for Application Call",
					"The code appears to allow the use of an unvalidated user-controlled variable when executing an application call: "+picName+". Manually check to ensure the parameter is used safely.",
					fileName, model.SeverityLow, codeLine, lineNumber)
			}
		}
	} else if reCOBOLDynamicCall.MatchString(codeLine) {
		// 动态函数调用
		found := false
		for picName := range tracker.COBOL.PICs {
			if regexp.MustCompile(`\bCALL\b\s+` + regexp.QuoteMeta(picName) + `\s+\bUSING\b`).MatchString(codeLine) {
				reporter.ReportIssue("COBOL-CMDI-003", "User Controlled Variable From JCL Used for Dynamic Function Call",
					"The code appears to allow the use of an unvalidated user-controlled variable when executing a dynamic application call.",
					fileName, model.SeverityHigh, codeLine, lineNumber)
				found = true
				break
			}
		}
		if !found {
			reporter.ReportIssue("COBOL-CMDI-004", "Dynamic Function Call",
				"The code appears to allow the use of an unvalidated variable when executing a dynamic application call. Carry out a manual check to determine whether the variable is user-controlled.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

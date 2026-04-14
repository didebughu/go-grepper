package checker

import (
	"regexp"
	"strings"

	"github.com/didebughu/go-grepper/internal/config"
	"github.com/didebughu/go-grepper/internal/model"
	"github.com/didebughu/go-grepper/internal/util"
)

// RChecker R 安全检查器（对应原 modRCheck）
type RChecker struct{}

func (c *RChecker) Language() int { return config.LangR }

// 预编译正则表达式
var (
	// TrackRegistryUse
	reRRegistry = regexp.MustCompile(`\w+\s*<-\s*\breadRegistry\b`)

	// CheckExcel
	reRExcelVar = regexp.MustCompile(`\w+\s*<-\s*\b(read_excel|read_excelx|read_xlsx)\b\s*\(`)
	reRExcelUse = regexp.MustCompile(`\b(read_excel|read_excelx|read_xlsx)\b\s*\(`)

	// CheckRDatasets
	reRData = regexp.MustCompile(`\bdata\b\s*\(`)
	reRLoad = regexp.MustCompile(`\bload\b\s*\(`)
	reRSave = regexp.MustCompile(`\bsave\b\s*\(`)

	// CheckWebInteraction
	reRHTTPVar    = regexp.MustCompile(`\w+\s*<-\s*\b(paste|paste0)\b\s*\("\b(http|ftp)\b://`)
	reRHTTPDirect = regexp.MustCompile(`\w+\s*<-\s*"\b(http|ftp)\b://`)
	reRHtmlTab    = regexp.MustCompile(`\w+\s*<-\s*\bhtmltab\b\s*\(`)
	reRReadHTML   = regexp.MustCompile(`\w+\s*<-\s*\bread_html\b\s*\(`)
	reRReadNet    = regexp.MustCompile(`\bread\b\.(table|csv|csv2|delim|delim2|fwf)\b\s*\("\b(http|https|ftp)`)
	reRWriteNet   = regexp.MustCompile(`\bwrite\b\.(table|csv|csv2|delim|delim2|fwf)\b\s*\(\s*\w+\s*,\s*"\b(http|https|ftp)`)

	// CheckDatabase
	reRODBCConnect = regexp.MustCompile(`\w+\s*<-\s*\bodbcConnect\b\s*\(`)
	reRDBConnect   = regexp.MustCompile(`\w+\s*<-\s*\bdbConnect\b\s*\(`)

	// CheckXMLJSON
	reRFromJSON = regexp.MustCompile(`\bfromJSON\b\s*\(`)
	reRXMLParse = regexp.MustCompile(`\b(xmlToDataFrame|xmlTreeParse|xmlRoot)\b\s*\(`)
	reRWriteXML = regexp.MustCompile(`\bwrite\b\.xml\b\s*\(`)

	// CheckSerialization
	reRReadRDS = regexp.MustCompile(`\breadRDS\b\s*\(`)
	reRSaveRDS = regexp.MustCompile(`\bsaveRDS\b\s*\(`)

	// CheckFileAccess
	reRReadFile    = regexp.MustCompile(`\bread\b\.(table|csv|csv2|delim|delim2|fwf)\b\s*\(`)
	reRReadFileVar = regexp.MustCompile(`\w+\s*<-\s*\bread\b\.`)
	reRCatPipe     = regexp.MustCompile(`\bcat\b\s*\(.*,\s*\bfile\b\s*=\s*"\|\w+`)
	reRCatFile     = regexp.MustCompile(`\bcat\b\s*\(.*,\s*\bfile\b\s*=`)

	// CheckClipboardAccess
	reRClipboard = regexp.MustCompile(`\bfile\b\s*=\s*"\bclipboard\b"`)
	reRPbpaste   = regexp.MustCompile(`\bpipe\b\s*\("\bpbpaste\b"\)`)

	// CheckFileOutput
	reRWriteFile = regexp.MustCompile(`\bwrite\b\.(table|csv|csv2|delim|delim2|fwf)\b\s*\(`)
	reRWriteTemp = regexp.MustCompile(`(?i)\b(table|csv|csv2|delim|delim2|fwf)\b\s*\(\s*\w+\s*,\s*"(C:\\\\temp|C:\\\\tmp|C:/temp|C:/tmp|/tmp)`)

	// CheckFileRace
	reRFileExists = regexp.MustCompile(`\bfile\b\.\bexists\b\s*\(`)
	reRReadWrite  = regexp.MustCompile(`\b(read|write)\b\.\b(table|csv)\b\s*\(`)

	// CheckSystemInteraction
	reRCommand   = regexp.MustCompile(`\b(command|command2|shell)\b\s*\(`)
	reRGetenv    = regexp.MustCompile(`\bSys\b\.\bgetenv\b\s*\(`)
	reRGetenvVar = regexp.MustCompile(`\w+\s*<-\s*\w+`)

	// CheckUserInteraction
	reRReadlineEq  = regexp.MustCompile(`\w+\s*=\s*\breadline\b\s*\(`)
	reRReadlineArr = regexp.MustCompile(`\w+\s*<-\s*\breadline\b\s*\(`)
	reRReadline    = regexp.MustCompile(`\breadline\b\s*\(`)

	// CheckRandomisation
	reRSetSeed = regexp.MustCompile(`\bset\b\.\bseed\b\s*\([0-9]+\)`)
	reRRunif   = regexp.MustCompile(`\brunif\b\s*\(`)

	// CheckUnsafeTempFiles
	reRSetWdTemp    = regexp.MustCompile(`(?i)\bsetwd\b\s*\("(C:\\\\temp|C:\\\\tmp|C:/temp|C:/tmp|/tmp)`)
	reRFilePathTemp = regexp.MustCompile(`(?i)\bfile\b\.\bpath\b\s*\("(C:\\\\temp|C:\\\\tmp|C:/temp|C:/tmp|/tmp)`)
)

func (c *RChecker) CheckCode(codeLine string, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	c.trackRegistryUse(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkExcel(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkRDatasets(codeLine, fileName, lineNumber, reporter)
	c.checkWebInteraction(codeLine, fileName, lineNumber, reporter)
	c.checkDatabase(codeLine, fileName, lineNumber, reporter)
	c.checkXMLJSON(codeLine, fileName, lineNumber, reporter)
	c.checkSerialization(codeLine, fileName, lineNumber, reporter)
	c.checkFileAccess(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkClipboardAccess(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkFileOutput(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkFileRace(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkSystemInteraction(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkUserInteraction(codeLine, fileName, lineNumber, tracker, reporter)
	c.checkRandomisation(codeLine, fileName, lineNumber, reporter)
	c.checkUnsafeTempFiles(codeLine, fileName, lineNumber, reporter)
}

func (c *RChecker) CheckFileLevelIssues(fileName string, tracker *model.CodeTracker, reporter IssueReporter) {
	// R 语言没有特定的文件级检查
}

// trackRegistryUse 跟踪注册表使用
func (c *RChecker) trackRegistryUse(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reRRegistry.MatchString(codeLine) {
		parts := strings.SplitN(codeLine, "<-", 2)
		varName := util.GetLastItem(parts[0], " ")
		c.addUserVar(varName, tracker)

		reporter.ReportIssue("R-DATA-001", "Registry Value Stored in Variable",
			"The code reads a registry value into a variable. If this input is subsequently used without sanitisation, it may result in unintended behaviour.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkExcel 检查 Excel 交互
func (c *RChecker) checkExcel(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reRExcelVar.MatchString(codeLine) {
		reporter.ReportIssue("R-DATA-002", "Excel Data Stored in Vector/Variable",
			"The code reads the content of an Excel file into a variable. If this input is subsequently used without sanitisation, it may result in unintended behaviour.",
			fileName, model.SeverityMedium, codeLine, lineNumber)

		parts := strings.SplitN(codeLine, "<-", 2)
		varName := util.GetLastItem(parts[0], " ")
		c.addUserVar(varName, tracker)
	} else if reRExcelUse.MatchString(codeLine) {
		reporter.ReportIssue("R-DATA-003", "Use of Excel File",
			"The code reads the content of an Excel file. If this input is subsequently used without sanitisation, it may result in unintended behaviour.",
			fileName, model.SeverityLow, codeLine, lineNumber)
	}
}

// checkRDatasets 检查 R 数据集
func (c *RChecker) checkRDatasets(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reRData.MatchString(codeLine) {
		reporter.ReportIssue("R-DATA-004", "Data Imported from Package",
			"The code imports an R dataset from a package. This input is in the control of the package provider/modifier.",
			fileName, model.SeverityInfo, codeLine, lineNumber)
	} else if reRLoad.MatchString(codeLine) {
		reporter.ReportIssue("R-DATA-005", "Data Imported from R Dataset",
			"The code imports an R dataset from the local system. Note that load() overwrites existing objects with the same names without giving any warnings.",
			fileName, model.SeverityLow, codeLine, lineNumber)
	} else if reRSave.MatchString(codeLine) {
		reporter.ReportIssue("R-DATA-006", "Data Saved to R Dataset",
			"The code saves data objects to an RData file. Any sensitive data in the file may be exposed to a third party.",
			fileName, model.SeverityLow, codeLine, lineNumber)
	}
}

// checkWebInteraction 检查 Web 交互
func (c *RChecker) checkWebInteraction(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reRHTTPVar.MatchString(codeLine) || reRHTTPDirect.MatchString(codeLine) {
		reporter.ReportIssue("R-NET-001", "Unencrypted Connection",
			"The code connects to a resource using an unencrypted protocol. Any network traffic (including credentials) may be sniffed by a suitably placed attacker.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	} else if reRHtmlTab.MatchString(codeLine) {
		reporter.ReportIssue("R-NET-002", "Data Imported from HTML Table",
			"The code imports data from a table on a web page. Note that data from a public source is reliant on the curation of the provider.",
			fileName, model.SeverityLow, codeLine, lineNumber)
	} else if reRReadHTML.MatchString(codeLine) {
		reporter.ReportIssue("R-NET-003", "HTML Scraped from Web Page",
			"The code scrapes data from a web page. The safety of any data imported from the page is reliant on the provider.",
			fileName, model.SeverityLow, codeLine, lineNumber)
	} else if reRReadNet.MatchString(codeLine) {
		reporter.ReportIssue("R-NET-004", "Data Imported Over Network",
			"The code reads a file from a web location. If an unencrypted protocol is used, any network traffic may be sniffed by a suitably placed attacker.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	} else if reRWriteNet.MatchString(codeLine) {
		reporter.ReportIssue("R-NET-005", "Data Exported Over Network",
			"The code writes a file to a remote location. Any sensitive data may be exposed. If an unencrypted protocol is used, network traffic may be sniffed.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkDatabase 检查数据库交互
func (c *RChecker) checkDatabase(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reRODBCConnect.MatchString(codeLine) || reRDBConnect.MatchString(codeLine) {
		if strings.Contains(strings.ToLower(codeLine), "password") || strings.Contains(strings.ToLower(codeLine), "pwd") {
			reporter.ReportIssue("R-CRYPTO-001", "Database Password Disclosed",
				"The code connects to a database and discloses the password within the source code.",
				fileName, model.SeverityHigh, codeLine, lineNumber)
		}
	}
}

// checkXMLJSON 检查 XML/JSON 处理
func (c *RChecker) checkXMLJSON(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reRFromJSON.MatchString(codeLine) {
		reporter.ReportIssue("R-DATA-007", "JSON Data Imported from File",
			"The code imports JSON data from a file. The data within the file may have been modified.",
			fileName, model.SeverityInfo, codeLine, lineNumber)
	} else if reRXMLParse.MatchString(codeLine) {
		reporter.ReportIssue("R-DATA-008", "XML Data Imported from File",
			"The code imports XML data from a file. The data within the file may have been modified.",
			fileName, model.SeverityInfo, codeLine, lineNumber)
	} else if reRWriteXML.MatchString(codeLine) {
		reporter.ReportIssue("R-DATA-009", "Data Saved to an XML File",
			"The code saves data to an XML file. Any sensitive data in the file may be exposed to a third party.",
			fileName, model.SeverityLow, codeLine, lineNumber)
	}
}

// checkSerialization 检查序列化
func (c *RChecker) checkSerialization(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reRReadRDS.MatchString(codeLine) {
		reporter.ReportIssue("R-SERIAL-001", "Object Deserialization",
			"The code imports objects to be deserialized. This can allow potentially hostile objects to be instantiated directly from data held in the filesystem.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	} else if reRSaveRDS.MatchString(codeLine) {
		reporter.ReportIssue("R-SERIAL-002", "Object Serialized to Disc",
			"The code serializes objects to the file system. Any sensitive data in the file may be exposed to a third party.",
			fileName, model.SeverityStandard, codeLine, lineNumber)
	}
}

// checkFileAccess 检查文件访问
func (c *RChecker) checkFileAccess(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reRReadFile.MatchString(codeLine) {
		if reRReadFileVar.MatchString(codeLine) {
			reporter.ReportIssue("R-FILE-001", "File Input Stored in Vector/Variable",
				"The code reads file input into a variable. If this input is subsequently used without sanitisation, it may result in unintended behaviour.",
				fileName, model.SeverityMedium, codeLine, lineNumber)

			parts := strings.SplitN(codeLine, "<-", 2)
			varName := util.GetLastItem(parts[0], " ")
			c.addUserVar(varName, tracker)
		} else {
			reporter.ReportIssue("R-FILE-002", "External File Input",
				"The code reads file input. If this input is subsequently used without sanitisation, it may result in unintended behaviour.",
				fileName, model.SeverityLow, codeLine, lineNumber)
		}
	} else if reRCatPipe.MatchString(codeLine) {
		reporter.ReportIssue("R-CMDI-001", "Use of System Command Line",
			"The code pipes R data to another application, via the command line. This may create an increased attack surface.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
	} else if reRCatFile.MatchString(codeLine) {
		reporter.ReportIssue("R-FILE-003", "Data Saved to File",
			"The code saves data to an external file. Any sensitive data in the file may be exposed to a third party.",
			fileName, model.SeverityLow, codeLine, lineNumber)
	}
}

// checkClipboardAccess 检查剪贴板访问
func (c *RChecker) checkClipboardAccess(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reRClipboard.MatchString(codeLine) || reRPbpaste.MatchString(codeLine) {
		if strings.Contains(codeLine, "<-") && strings.Contains(codeLine, "read.") {
			reporter.ReportIssue("R-DATA-010", "Clipboard Content Imported into Vector/Variable",
				"The code reads the content of the clipboard into a variable. This input is reliant on safe behaviour by the user.",
				fileName, model.SeverityMedium, codeLine, lineNumber)

			parts := strings.SplitN(codeLine, "<-", 2)
			varName := util.GetLastItem(parts[0], " ")
			c.addUserVar(varName, tracker)
		} else {
			reporter.ReportIssue("R-DATA-011", "Use of Clipboard Content",
				"The code reads content from the clipboard. This input is reliant on safe behaviour by the user.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

// checkFileOutput 检查文件输出
func (c *RChecker) checkFileOutput(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reRWriteFile.MatchString(codeLine) {
		if reRWriteTemp.MatchString(codeLine) {
			reporter.ReportIssue("R-TMPF-001", "Unsafe Temporary Directory Use",
				"The application appears to write to a file in the 'temp' folder. Since this folder is accessible by all users, any files stored there cannot be guaranteed to be safe.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		} else {
			// 检查用户控制的路径
			for _, v := range tracker.CPP.UserVariables {
				if strings.Contains(codeLine, v) {
					reporter.ReportIssue("R-FILE-005", "Use of User-Controlled Path",
						"The code writes data to a file path that appears to be a user-controlled variable.",
						fileName, model.SeverityMedium, codeLine, lineNumber)
					break
				}
			}
		}

		reporter.ReportIssue("R-FILE-004", "Unsafe File Write",
			"The application appears to write to a file without verifying that it already exists. This may result in an accidental overwrite of data.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkFileRace 检查 TOCTOU 竞态条件
func (c *RChecker) checkFileRace(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reRFileExists.MatchString(codeLine) && !reRReadWrite.MatchString(codeLine) {
		// 标记文件检查
		tracker.CPP.Buffers["__r_toctou__"] = lineNumber
	} else if _, ok := tracker.CPP.Buffers["__r_toctou__"]; ok {
		if reRReadWrite.MatchString(codeLine) {
			checkLine := tracker.CPP.Buffers["__r_toctou__"]
			distance := lineNumber - checkLine
			if distance > 1 {
				reporter.ReportIssue("R-RACE-001", "Potential TOCTOU (Time Of Check, Time Of Use) Vulnerability",
					"The file.exists() check occurs before the file is accessed. The longer the time between the check and any read/write, the greater the likelihood that the check will no longer be valid.",
					fileName, model.SeverityStandard, codeLine, lineNumber)
			}
			delete(tracker.CPP.Buffers, "__r_toctou__")
		}
	}
}

// checkSystemInteraction 检查系统交互
func (c *RChecker) checkSystemInteraction(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	if reRCommand.MatchString(codeLine) {
		parts := regexp.MustCompile(`\b(command|command2|shell)\b\s*\(`).Split(codeLine, 2)
		right := ""
		if len(parts) > 1 {
			right = strings.TrimSpace(parts[1])
		}

		found := false
		if right != "" {
			for _, v := range tracker.CPP.UserVariables {
				if strings.Contains(right, v) {
					reporter.ReportIssue("R-CMDI-002", "Use of System Shell/Command",
						"The code runs a command on the underlying operating system, and also appears to use a user-controlled variable in conjunction with the command.",
						fileName, model.SeverityHigh, codeLine, lineNumber)
					found = true
					break
				}
			}
		}
		if !found {
			reporter.ReportIssue("R-CMDI-003", "Use of System Shell/Command",
				"The code runs a command on the underlying operating system. This may create an increased attack surface.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	} else if reRGetenv.MatchString(codeLine) {
		if reRGetenvVar.MatchString(codeLine) && strings.Contains(codeLine, "<-") {
			parts := strings.SplitN(codeLine, "<-", 2)
			varName := util.GetLastItem(parts[0], " ")
			c.addUserVar(varName, tracker)
			reporter.ReportIssue("R-MISC-001", "Use of Environment Variable",
				"The code assigns an environment variable to one of the code's internal variables. As the original value is accessible to external sources, it may be modified by an attacker.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		} else {
			reporter.ReportIssue("R-MISC-001", "Use of Environment Variable",
				"The code makes use of an environment variable. As this variable is accessible to external sources, it may be modified by an attacker.",
				fileName, model.SeverityMedium, codeLine, lineNumber)
		}
	}
}

// checkUserInteraction 检查用户交互
func (c *RChecker) checkUserInteraction(codeLine, fileName string, lineNumber int, tracker *model.CodeTracker, reporter IssueReporter) {
	var varName string

	if reRReadlineEq.MatchString(codeLine) {
		reporter.ReportIssue("R-INPUT-001", "Direct Input From User",
			"The code requests direct input from the user, via the command line, and assigns it to a variable.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
		parts := strings.SplitN(codeLine, "=", 2)
		varName = util.GetLastItem(parts[0], " ")
	} else if reRReadlineArr.MatchString(codeLine) {
		reporter.ReportIssue("R-INPUT-001", "Direct Input From User",
			"The code requests direct input from the user, via the command line, and assigns it to a variable.",
			fileName, model.SeverityHigh, codeLine, lineNumber)
		parts := strings.SplitN(codeLine, "<-", 2)
		varName = util.GetLastItem(parts[0], " ")
	} else if reRReadline.MatchString(codeLine) {
		reporter.ReportIssue("R-INPUT-002", "Direct Input From User",
			"The code requests direct input from the user, via the command line.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}

	if varName != "" {
		c.addUserVar(varName, tracker)
	}
}

// checkRandomisation 检查随机数安全
func (c *RChecker) checkRandomisation(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reRSetSeed.MatchString(codeLine) {
		reporter.ReportIssue("R-RAND-001", "Repeatable Pseudo-Random Values",
			"The code appears to set a numeric seed value. The resulting values are repeatable and will be the same for any machine, each time the code is run.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	} else if reRRunif.MatchString(codeLine) {
		reporter.ReportIssue("R-RAND-002", "Repeatable Pseudo-Random Values",
			"The code uses the runif() (random uniform) function. The resulting values are repeatable and will be the same each time the code is run from any machine using the same seed value.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// checkUnsafeTempFiles 检查不安全的临时文件
func (c *RChecker) checkUnsafeTempFiles(codeLine, fileName string, lineNumber int, reporter IssueReporter) {
	if reRSetWdTemp.MatchString(codeLine) {
		reporter.ReportIssue("R-TMPF-001", "Unsafe Temporary Directory Use",
			"The application appears to set its working directory to the 'temp' folder. Since this folder is accessible by all users, any files stored there cannot be guaranteed to be safe.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	} else if reRFilePathTemp.MatchString(codeLine) {
		reporter.ReportIssue("R-TMPF-001", "Unsafe Temporary Directory Use",
			"The application appears to set a file path to the 'temp' folder. Since this folder is accessible by all users, any files stored there cannot be guaranteed to be safe.",
			fileName, model.SeverityMedium, codeLine, lineNumber)
	}
}

// addUserVar 添加用户控制的变量
func (c *RChecker) addUserVar(varName string, tracker *model.CodeTracker) {
	if varName == "" {
		return
	}
	for _, v := range tracker.CPP.UserVariables {
		if v == varName {
			return
		}
	}
	tracker.CPP.UserVariables = append(tracker.CPP.UserVariables, varName)
}

package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/model"
)

// ==================== trackRegistryUse 测试 ====================

func TestR_TrackRegistryUse(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.trackRegistryUse("  regVal <- readRegistry(\"HKLM\\\\Software\\\\MyApp\")", "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Registry Value Stored in Variable") {
		t.Errorf("应检测到注册表值存储，实际报告: %s", reporter.dumpIssues())
	}
	if len(tracker.CPP.UserVariables) == 0 {
		t.Errorf("应跟踪注册表变量")
	}
}

// ==================== checkExcel 测试 ====================

func TestR_CheckExcel_ReadExcelVar(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkExcel("  data <- read_excel(\"data.xlsx\")", "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Excel Data Stored in Vector") {
		t.Errorf("应检测到 Excel 数据存储到变量，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckExcel_ReadExcelDirect(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkExcel("  read_excel(\"data.xlsx\")", "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Use of Excel File") {
		t.Errorf("应检测到 Excel 文件使用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkRDatasets 测试 ====================

func TestR_CheckRDatasets_Data(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkRDatasets("  data(iris)", "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Data Imported from Package") {
		t.Errorf("应检测到包数据导入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckRDatasets_Load(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkRDatasets("  load(\"mydata.RData\")", "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Data Imported from R Dataset") {
		t.Errorf("应检测到 R 数据集导入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckRDatasets_Save(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkRDatasets("  save(mydata, file=\"output.RData\")", "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Data Saved to R Dataset") {
		t.Errorf("应检测到 R 数据集保存，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkWebInteraction 测试 ====================

func TestR_CheckWebInteraction_HTTPConnection(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkWebInteraction(`  url <- paste("http://example.com/api", param)`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Unencrypted Connection") {
		t.Errorf("应检测到未加密连接，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckWebInteraction_HtmlTab(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkWebInteraction(`  data <- htmltab("https://example.com/table")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Data Imported from HTML Table") {
		t.Errorf("应检测到 HTML 表格导入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckWebInteraction_ReadHTML(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkWebInteraction(`  page <- read_html("https://example.com")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("HTML Scraped from Web Page") {
		t.Errorf("应检测到 HTML 抓取，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckWebInteraction_ReadNet(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkWebInteraction(`  data <- read.csv("http://example.com/data.csv")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Data Imported Over Network") {
		t.Errorf("应检测到网络数据导入，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkDatabase 测试 ====================

func TestR_CheckDatabase_PasswordDisclosed(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkDatabase(`  con <- dbConnect(MySQL(), user="root", password="secret")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Database Password Disclosed") {
		t.Errorf("应检测到数据库密码泄露，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckDatabase_ODBCConnect(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkDatabase(`  con <- odbcConnect("mydsn", uid="user", pwd="pass")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Database Password Disclosed") {
		t.Errorf("应检测到 ODBC 密码泄露，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkXMLJSON 测试 ====================

func TestR_CheckXMLJSON_FromJSON(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkXMLJSON(`  data <- fromJSON("data.json")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("JSON Data Imported") {
		t.Errorf("应检测到 JSON 导入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckXMLJSON_XMLParse(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkXMLJSON(`  doc <- xmlTreeParse("data.xml")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("XML Data Imported") {
		t.Errorf("应检测到 XML 导入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckXMLJSON_WriteXML(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkXMLJSON(`  write.xml(data, "output.xml")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Data Saved to an XML File") {
		t.Errorf("应检测到 XML 保存，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSerialization 测试 ====================

func TestR_CheckSerialization_ReadRDS(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkSerialization(`  obj <- readRDS("data.rds")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Object Deserialization") {
		t.Errorf("应检测到反序列化，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckSerialization_SaveRDS(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkSerialization(`  saveRDS(obj, "data.rds")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Object Serialized") {
		t.Errorf("应检测到序列化，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkFileAccess 测试 ====================

func TestR_CheckFileAccess_ReadCSVVar(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileAccess(`  data <- read.csv("input.csv")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("File Input Stored in Vector") {
		t.Errorf("应检测到文件输入存储到变量，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckFileAccess_CatPipe(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileAccess(`  cat(data, file="|sort")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("System Command Line") {
		t.Errorf("应检测到 cat 管道命令，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckFileAccess_CatFile(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileAccess(`  cat(data, file="output.txt")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Data Saved to File") {
		t.Errorf("应检测到数据保存到文件，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkClipboardAccess 测试 ====================

func TestR_CheckClipboardAccess_Clipboard(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkClipboardAccess(`  data <- read.csv(file="clipboard")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Clipboard Content Imported") {
		t.Errorf("应检测到剪贴板内容导入，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkFileOutput 测试 ====================

func TestR_CheckFileOutput_WriteCSV(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileOutput(`  write.csv(data, "output.csv")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsafe File Write") {
		t.Errorf("应检测到不安全的文件写入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckFileOutput_WriteTempDir(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileOutput(`  write.csv(data, "/tmp/output.csv")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Temporary Directory") {
		t.Errorf("应检测到不安全的临时目录使用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkFileRace 测试 ====================

func TestR_CheckFileRace_TOCTOU(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkFileRace("  if (file.exists(\"data.csv\")) {", "test.r", 10, tracker, reporter)
	checker.checkFileRace("    # some code", "test.r", 11, tracker, reporter)
	checker.checkFileRace("    data <- read.csv(\"data.csv\")", "test.r", 12, tracker, reporter)

	if !reporter.hasIssueWithTitle("TOCTOU") {
		t.Errorf("应检测到 TOCTOU 竞态条件，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkSystemInteraction 测试 ====================

func TestR_CheckSystemInteraction_Command(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSystemInteraction(`  result <- shell("ls -la")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("System Shell/Command") {
		t.Errorf("应检测到系统命令使用，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckSystemInteraction_CommandWithUserVar(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()
	tracker.CPP.UserVariables = append(tracker.CPP.UserVariables, "userCmd")

	checker.checkSystemInteraction(`  result <- shell(userCmd)`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithSeverity(model.SeverityHigh) {
		t.Errorf("用户控制变量的系统命令应为 High 级别，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckSystemInteraction_Getenv(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkSystemInteraction(`  path <- Sys.getenv("PATH")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Environment Variable") {
		t.Errorf("应检测到环境变量使用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUserInteraction 测试 ====================

func TestR_CheckUserInteraction_ReadlineArrow(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkUserInteraction(`  input <- readline("Enter value: ")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Direct Input From User") {
		t.Errorf("应检测到用户直接输入，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityHigh) {
		t.Errorf("readline 赋值应为 High 级别")
	}
}

func TestR_CheckUserInteraction_ReadlineEqual(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkUserInteraction(`  input = readline("Enter value: ")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Direct Input From User") {
		t.Errorf("应检测到用户直接输入，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckUserInteraction_ReadlineDirect(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	checker.checkUserInteraction(`  readline("Press enter to continue")`, "test.r", 10, tracker, reporter)

	if !reporter.hasIssueWithTitle("Direct Input From User") {
		t.Errorf("应检测到用户直接输入，实际报告: %s", reporter.dumpIssues())
	}
	if !reporter.hasIssueWithSeverity(model.SeverityMedium) {
		t.Errorf("直接 readline 应为 Medium 级别")
	}
}

// ==================== checkRandomisation 测试 ====================

func TestR_CheckRandomisation_SetSeed(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkRandomisation("  set.seed(42)", "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Repeatable Pseudo-Random") {
		t.Errorf("应检测到固定种子，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckRandomisation_Runif(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkRandomisation("  x <- runif(100)", "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Repeatable Pseudo-Random") {
		t.Errorf("应检测到 runif 使用，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== checkUnsafeTempFiles 测试 ====================

func TestR_CheckUnsafeTempFiles_SetWdTemp(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkUnsafeTempFiles(`  setwd("/tmp")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Temporary Directory") {
		t.Errorf("应检测到不安全的临时目录，实际报告: %s", reporter.dumpIssues())
	}
}

func TestR_CheckUnsafeTempFiles_FilePathTemp(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()

	checker.checkUnsafeTempFiles(`  path <- file.path("/tmp", "data.csv")`, "test.r", 10, reporter)

	if !reporter.hasIssueWithTitle("Unsafe Temporary Directory") {
		t.Errorf("应检测到不安全的临时目录路径，实际报告: %s", reporter.dumpIssues())
	}
}

// ==================== CheckCode 集成测试 ====================

func TestR_CheckCode_Integration(t *testing.T) {
	checker := &RChecker{}
	reporter := newMockReporter()
	tracker := newTracker()

	lines := []string{
		`  input <- readline("Enter name: ")`,
		`  set.seed(42)`,
		`  data <- read.csv("http://example.com/data.csv")`,
		`  con <- dbConnect(MySQL(), password="secret")`,
		`  setwd("/tmp")`,
	}

	for i, line := range lines {
		checker.CheckCode(line, "test.r", i+1, tracker, reporter)
	}

	if len(reporter.Issues) < 3 {
		t.Errorf("集成测试应检测到多个问题，实际检测到 %d 个: %s", len(reporter.Issues), reporter.dumpIssues())
	}
}

// ==================== Language 测试 ====================

func TestR_Language(t *testing.T) {
	checker := &RChecker{}
	if checker.Language() != 7 { // config.LangR = 7
		t.Errorf("RChecker 语言应为 7 (R)，实际: %d", checker.Language())
	}
}

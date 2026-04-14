package checker

import "github.com/didebughu/go-grepper/internal/config"

// NewChecker 根据语言类型创建对应的检查器（工厂方法）
func NewChecker(language int, settings *config.Settings) Checker {
	switch language {
	case config.LangCPP:
		return &CPPChecker{IncludeSigned: settings.IncludeSigned}
	case config.LangJava:
		return &JavaChecker{IsAndroid: settings.IsAndroid}
	case config.LangCSharp:
		return &CSharpChecker{}
	case config.LangVB:
		return &VBChecker{}
	case config.LangPHP:
		return &PHPChecker{}
	case config.LangSQL:
		return &PLSQLChecker{}
	case config.LangCOBOL:
		return &COBOLChecker{StartCol: settings.COBOLStartCol, IsZOS: settings.IsZOS}
	case config.LangR:
		return &RChecker{}
	default:
		return &CPPChecker{}
	}
}

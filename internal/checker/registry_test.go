package checker

import (
	"testing"

	"github.com/didebughu/go-grepper/internal/config"
)

func TestNewChecker_CPP(t *testing.T) {
	settings := &config.Settings{IncludeSigned: true}
	c := NewChecker(config.LangCPP, settings)
	if c.Language() != config.LangCPP {
		t.Errorf("应创建 CPP checker，实际语言: %d", c.Language())
	}
	cppChecker, ok := c.(*CPPChecker)
	if !ok {
		t.Fatal("应返回 *CPPChecker 类型")
	}
	if !cppChecker.IncludeSigned {
		t.Errorf("IncludeSigned 应为 true")
	}
}

func TestNewChecker_Java(t *testing.T) {
	settings := &config.Settings{IsAndroid: true}
	c := NewChecker(config.LangJava, settings)
	if c.Language() != config.LangJava {
		t.Errorf("应创建 Java checker，实际语言: %d", c.Language())
	}
	javaChecker, ok := c.(*JavaChecker)
	if !ok {
		t.Fatal("应返回 *JavaChecker 类型")
	}
	if !javaChecker.IsAndroid {
		t.Errorf("IsAndroid 应为 true")
	}
}

func TestNewChecker_CSharp(t *testing.T) {
	settings := &config.Settings{}
	c := NewChecker(config.LangCSharp, settings)
	if c.Language() != config.LangCSharp {
		t.Errorf("应创建 CSharp checker，实际语言: %d", c.Language())
	}
}

func TestNewChecker_VB(t *testing.T) {
	settings := &config.Settings{}
	c := NewChecker(config.LangVB, settings)
	if c.Language() != config.LangVB {
		t.Errorf("应创建 VB checker，实际语言: %d", c.Language())
	}
}

func TestNewChecker_PHP(t *testing.T) {
	settings := &config.Settings{}
	c := NewChecker(config.LangPHP, settings)
	if c.Language() != config.LangPHP {
		t.Errorf("应创建 PHP checker，实际语言: %d", c.Language())
	}
}

func TestNewChecker_SQL(t *testing.T) {
	settings := &config.Settings{}
	c := NewChecker(config.LangSQL, settings)
	if c.Language() != config.LangSQL {
		t.Errorf("应创建 PLSQL checker，实际语言: %d", c.Language())
	}
}

func TestNewChecker_COBOL(t *testing.T) {
	settings := &config.Settings{COBOLStartCol: 7, IsZOS: true}
	c := NewChecker(config.LangCOBOL, settings)
	if c.Language() != config.LangCOBOL {
		t.Errorf("应创建 COBOL checker，实际语言: %d", c.Language())
	}
	cobolChecker, ok := c.(*COBOLChecker)
	if !ok {
		t.Fatal("应返回 *COBOLChecker 类型")
	}
	if cobolChecker.StartCol != 7 {
		t.Errorf("StartCol 应为 7，实际: %d", cobolChecker.StartCol)
	}
	if !cobolChecker.IsZOS {
		t.Errorf("IsZOS 应为 true")
	}
}

func TestNewChecker_R(t *testing.T) {
	settings := &config.Settings{}
	c := NewChecker(config.LangR, settings)
	if c.Language() != config.LangR {
		t.Errorf("应创建 R checker，实际语言: %d", c.Language())
	}
}

func TestNewChecker_Default(t *testing.T) {
	settings := &config.Settings{}
	c := NewChecker(999, settings) // 未知语言
	if c.Language() != config.LangCPP {
		t.Errorf("未知语言应默认创建 CPP checker，实际语言: %d", c.Language())
	}
}

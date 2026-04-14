// Package rule 定义规则注册表和规则管理
package rule

import (
	"sort"
	"strings"
	"sync"
)

// Rule 规则定义
type Rule struct {
	ID          string   // 规则 ID，如 "JAVA-SQLI-001"
	Name        string   // 规则名称（英文）
	Description string   // 规则描述
	Severity    int      // 默认严重级别
	Languages   []string // 适用语言列表
	Category    string   // 规则类别
	Enabled     bool     // 是否默认启用
}

// Registry 规则注册表（全局单例）
type Registry struct {
	mu    sync.RWMutex
	rules map[string]*Rule // key: Rule.ID
}

var globalRegistry = &Registry{
	rules: make(map[string]*Rule),
}

// Register 注册规则
func Register(r *Rule) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.rules[r.ID] = r
}

// Get 获取规则
func Get(id string) (*Rule, bool) {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	r, ok := globalRegistry.rules[id]
	return r, ok
}

// All 获取所有规则（返回副本）
func All() map[string]*Rule {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	result := make(map[string]*Rule, len(globalRegistry.rules))
	for k, v := range globalRegistry.rules {
		result[k] = v
	}
	return result
}

// ListAll 获取所有规则的有序列表
func ListAll() []*Rule {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	result := make([]*Rule, 0, len(globalRegistry.rules))
	for _, r := range globalRegistry.rules {
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

// ListByLanguage 按语言过滤规则
func ListByLanguage(lang string) []*Rule {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	lang = strings.ToLower(lang)
	var result []*Rule
	for _, r := range globalRegistry.rules {
		for _, l := range r.Languages {
			if strings.ToLower(l) == lang || l == "all" {
				result = append(result, r)
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

// IsEnabled 检查规则是否启用（结合配置文件）
func IsEnabled(ruleID string, enabledRules, disabledRules, disabledCategories []string) bool {
	// 如果在禁用列表中，返回 false
	for _, id := range disabledRules {
		if id == ruleID {
			return false
		}
	}

	// 检查类别是否被禁用
	if len(disabledCategories) > 0 {
		if r, ok := Get(ruleID); ok {
			for _, cat := range disabledCategories {
				if strings.EqualFold(r.Category, cat) {
					return false
				}
			}
		}
	}

	// 如果启用列表非空，仅启用列表中的规则
	if len(enabledRules) > 0 {
		for _, id := range enabledRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	// 默认启用
	return true
}

// frontend.go — 前端层（门：Frontend）
// UI框架与仪表盘的统一入口
package frontend

import (
	"context"
	"fmt"
	"sync"
)

// Engine 前端层引擎
type Engine struct {
	mu       sync.RWMutex
	panels   map[string]Panel
	theme    string
	lang     string
}

// Panel 前端面板接口
type Panel interface {
	ID() string
	Title() string
	Render() (string, error) // 返回HTML片段或JSON配置
}

// NewEngine 创建前端引擎
func NewEngine() *Engine {
	return &Engine{
		panels: map[string]Panel{},
		theme:  "default",
		lang:   "zh-CN",
	}
}

// Register 注册面板
func (e *Engine) Register(p Panel) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.panels[p.ID()]; exists {
		return fmt.Errorf("panel %s already registered", p.ID())
	}
	e.panels[p.ID()] = p
	return nil
}

// SetTheme 设置主题
func (e *Engine) SetTheme(t string) { e.theme = t }

// SetLang 设置语言
func (e *Engine) SetLang(l string) { e.lang = l }

// RenderAll 渲染所有面板配置
func (e *Engine) RenderAll() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := map[string]string{}
	for id, p := range e.panels {
		if html, err := p.Render(); err == nil {
			result[id] = html
		}
	}
	return result
}

// DashboardConfig 返回仪表盘配置（供前端框架消费）
func (e *Engine) DashboardConfig() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var panels []map[string]string
	for id, p := range e.panels {
		panels = append(panels, map[string]string{"id": id, "title": p.Title()})
	}
	return map[string]interface{}{
		"theme":   e.theme,
		"lang":    e.lang,
		"panels":  panels,
		"version": "4.9.0",
	}
}

// Start 启动前端服务（占位，实际为静态文件服务或SSR入口）
func (e *Engine) Start(ctx context.Context) error { return nil }

// Stop 停止前端服务
func (e *Engine) Stop(ctx context.Context) error { return nil }

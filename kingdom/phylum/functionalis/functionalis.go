// functionalis.go — 功能层（门：Functionalis）
// 聊天/模型/工具/连接器的统一协调
package functionalis

import (
	"context"
	"fmt"
	"sync"
)

// Engine 功能层引擎
type Engine struct {
	mu         sync.RWMutex
	modules    map[string]Module
	providers  map[string]Provider
}

// Module 功能模块接口
type Module interface {
	ID() string
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// Provider 服务提供方接口
type Provider interface {
	Name() string
	Health() error
}

// NewEngine 创建功能层引擎
func NewEngine() *Engine {
	return &Engine{
		modules:   map[string]Module{},
		providers: map[string]Provider{},
	}
}

// Register 注册功能模块
func (e *Engine) Register(m Module) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.modules[m.ID()]; exists {
		return fmt.Errorf("module %s already registered", m.ID())
	}
	e.modules[m.ID()] = m
	return nil
}

// StartAll 启动所有模块
func (e *Engine) StartAll(ctx context.Context) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var errs []error
	for _, m := range e.modules {
		if err := m.Start(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.ID(), err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// StopAll 停止所有模块
func (e *Engine) StopAll(ctx context.Context) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var errs []error
	for _, m := range e.modules {
		if err := m.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.ID(), err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// List 列出已注册模块
func (e *Engine) List() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []string
	for id := range e.modules {
		result = append(result, id)
	}
	return result
}

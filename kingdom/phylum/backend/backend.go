// backend.go — 后端层（门：Backend）
// API网关与存储的统一入口
package backend

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

// Engine 后端层引擎
type Engine struct {
	mu        sync.RWMutex
	routes    map[string]http.HandlerFunc
	mwChain   []Middleware
	storage   Storage
}

// Middleware HTTP中间件
type Middleware func(http.HandlerFunc) http.HandlerFunc

// Storage 存储抽象
type Storage interface {
	Get(key string) ([]byte, error)
	Set(key string, val []byte) error
	Delete(key string) error
	Keys(prefix string) ([]string, error)
}

// NewEngine 创建后端引擎
func NewEngine(store Storage) *Engine {
	return &Engine{
		routes:  map[string]http.HandlerFunc{},
		mwChain: []Middleware{},
		storage: store,
	}
}

// RegisterRoute 注册路由
func (e *Engine) RegisterRoute(path string, handler http.HandlerFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.routes[path] = handler
}

// Use 添加中间件
func (e *Engine) Use(mw Middleware) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mwChain = append(e.mwChain, mw)
}

// ServeHTTP 实现http.Handler
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.RLock()
	handler, ok := e.routes[r.URL.Path]
	mw := append([]Middleware{}, e.mwChain...)
	e.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	// 应用中间件链
	for i := len(mw) - 1; i >= 0; i-- {
		handler = mw[i](handler)
	}
	handler(w, r)
}

// Storage 获取存储实例
func (e *Engine) Storage() Storage { return e.storage }

// Start 启动后端服务（占位，实际由main.go中的http.Server启动）
func (e *Engine) Start(ctx context.Context) error { return nil }

// Stop 停止后端服务
func (e *Engine) Stop(ctx context.Context) error { return nil }

// Health 健康检查
func (e *Engine) Health() map[string]interface{} {
	return map[string]interface{}{
		"status":    "ok",
		"routes":    len(e.routes),
		"storage":   e.storage != nil,
		"version":   "4.9.0",
	}
}

// MemoryStorage 内存存储实现（默认兜底）
type MemoryStorage struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemoryStorage 创建内存存储
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{data: map[string][]byte{}}
}

func (s *MemoryStorage) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return v, nil
}

func (s *MemoryStorage) Set(key string, val []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = val
	return nil
}

func (s *MemoryStorage) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *MemoryStorage) Keys(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []string
	for k := range s.data {
		if prefix == "" || len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			result = append(result, k)
		}
	}
	return result, nil
}

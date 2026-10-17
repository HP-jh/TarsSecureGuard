// kingdom/taxonomy.go — 动物分类学核心接口
// 界→门→纲→目→科→属→种 七层分类体系
package kingdom

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Rank 分类层级
 type Rank int

const (
	RankKingdom Rank = iota // 界 — TSG系统
	RankPhylum              // 门 — 防护层/功能层/前端/后端
	RankClass               // 纲 — 大类
	RankOrder               // 目 — 子类
	RankFamily              // 科 — 模块族
	RankGenus               // 属 — 具体模块
	RankSpecies             // 种 — 策略实例
)

func (r Rank) String() string {
	switch r {
	case RankKingdom: return "界"
	case RankPhylum:  return "门"
	case RankClass:   return "纲"
	case RankOrder:   return "目"
	case RankFamily:  return "科"
	case RankGenus:   return "属"
	case RankSpecies: return "种"
	default: return "未知"
	}
}

// Taxon 分类单元 — 每个模块/组件都是分类树中的一个节点
 type Taxon struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	LatinName   string            `json:"latin"`
	Rank        Rank              `json:"rank"`
	ParentID    string            `json:"parent_id"`
	Description string            `json:"description"`
	Language    string            `json:"language"`    // go/python/powershell/node/c
	Enabled     bool              `json:"enabled"`
	Required    bool              `json:"required"`    // 用户不可关闭
	UserChoice  bool              `json:"user_choice"` // 用户可自由选择开关
	Meta        map[string]any    `json:"meta"`
	Children    []*Taxon          `json:"children,omitempty"`
	Handler     ModuleHandler     `json:"-"`
}

// ModuleHandler 模块处理器接口
 type ModuleHandler interface {
	Init(ctx context.Context, cfg map[string]any) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Status(ctx context.Context) (ModuleStatus, error)
	UpdateConfig(ctx context.Context, cfg map[string]any) error
}

// ModuleStatus 模块运行状态
 type ModuleStatus struct {
	State      string        `json:"state"`       // running/stopped/error
	Since      time.Time     `json:"since"`
	LastError  string        `json:"last_error,omitempty"`
	Metrics    map[string]any `json:"metrics,omitempty"`
}

// Taxonomy 分类学树 — 整个TSG系统的分类架构
 type Taxonomy struct {
	mu     sync.RWMutex
	root   *Taxon
	index  map[string]*Taxon // ID -> Taxon 快速索引
}

// NewTaxonomy 创建新的分类学树
func NewTaxonomy() *Taxonomy {
	root := &Taxon{
		ID:        "tsg",
		Name:      "TSG系统",
		LatinName: "TarsSecureGuard",
		Rank:      RankKingdom,
		Enabled:   true,
		Required:  true,
		Meta:      map[string]any{"version": "4.9.0"},
	}
	return &Taxonomy{
		root:  root,
		index: map[string]*Taxon{"tsg": root},
	}
}

// Register 注册一个分类单元到树中
func (t *Taxonomy) Register(taxon *Taxon) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if taxon.ID == "" {
		return fmt.Errorf("taxon id is required")
	}
	if _, exists := t.index[taxon.ID]; exists {
		return fmt.Errorf("taxon %s already registered", taxon.ID)
	}

	parent, ok := t.index[taxon.ParentID]
	if !ok {
		return fmt.Errorf("parent %s not found", taxon.ParentID)
	}

	// 校验层级关系
	if taxon.Rank != parent.Rank+1 {
		return fmt.Errorf("invalid rank: %s(%s) cannot be child of %s(%s)",
			taxon.Name, taxon.Rank.String(), parent.Name, parent.Rank.String())
	}

	parent.Children = append(parent.Children, taxon)
	t.index[taxon.ID] = taxon
	return nil
}

// Get 按ID获取分类单元
func (t *Taxonomy) Get(id string) (*Taxon, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	tx, ok := t.index[id]
	return tx, ok
}

// GetByRank 按层级获取所有分类单元
func (t *Taxonomy) GetByRank(rank Rank) []*Taxon {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var result []*Taxon
	for _, tx := range t.index {
		if tx.Rank == rank {
			result = append(result, tx)
		}
	}
	return result
}

// Walk 遍历分类树
func (t *Taxonomy) Walk(fn func(*Taxon) bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	walk(t.root, fn)
}

func walk(tx *Taxon, fn func(*Taxon) bool) bool {
	if !fn(tx) {
		return false
	}
	for _, child := range tx.Children {
		if !walk(child, fn) {
			return false
		}
	}
	return true
}

// Root 获取根节点
func (t *Taxonomy) Root() *Taxon {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.root
}

// Flatten 将树扁平化为列表
func (t *Taxonomy) Flatten() []*Taxon {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*Taxon, 0, len(t.index))
	for _, tx := range t.index {
		result = append(result, tx)
	}
	return result
}

// ToJSON 导出为JSON结构
func (t *Taxonomy) ToJSON() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return taxonToMap(t.root)
}

func taxonToMap(tx *Taxon) map[string]any {
	m := map[string]any{
		"id":          tx.ID,
		"name":        tx.Name,
		"latin":       tx.LatinName,
		"rank":        tx.Rank.String(),
		"rank_level":  int(tx.Rank),
		"description": tx.Description,
		"language":    tx.Language,
		"enabled":     tx.Enabled,
		"required":    tx.Required,
		"user_choice": tx.UserChoice,
		"meta":        tx.Meta,
	}
	if len(tx.Children) > 0 {
		children := make([]map[string]any, len(tx.Children))
		for i, c := range tx.Children {
			children[i] = taxonToMap(c)
		}
		m["children"] = children
	}
	return m
}

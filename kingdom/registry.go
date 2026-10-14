// kingdom/registry.go — 模块注册中心
// 兼容现有 modules.go 注册表，同时支持 Taxonomy 树注册
package kingdom

import (
	"context"
	"fmt"
	"sync"
)

// Registry 全局模块注册中心
type Registry struct {
	mu        sync.RWMutex
	taxonomy  *Taxonomy
	legacyMap map[string]*Taxon
}

// NewRegistry 创建注册中心，预置完整分类树
func NewRegistry() *Registry {
	t := NewTaxonomy()
	r := &Registry{taxonomy: t, legacyMap: map[string]*Taxon{}}
	r.initProtectiva(t)
	r.initFunctionalis(t)
	r.initFrontend(t)
	r.initBackend(t)
	return r
}

func (r *Registry) initProtectiva(t *Taxonomy) {
	protectiva := &Taxon{ID: "phylum_protectiva", Name: "防护层", LatinName: "Protectiva", Rank: RankPhylum, ParentID: "tsg", Description: "统一防护入口，按纲/目/科/属/种细分", Language: "go", Enabled: true, Required: true}
	_ = t.Register(protectiva)

	netsec := &Taxon{ID: "classis_netsecurity", Name: "网络安全", LatinName: "Classis-NetSecurity", Rank: RankClass, ParentID: "phylum_protectiva", Language: "go", Enabled: true, Required: true}
	_ = t.Register(netsec)

	extranet := &Taxon{ID: "ordo_extranet", Name: "外网防护", LatinName: "Ordo-Extranet", Rank: RankOrder, ParentID: "classis_netsecurity", Language: "go", Enabled: true, Required: false, UserChoice: true}
	_ = t.Register(extranet)
	_ = t.Register(&Taxon{ID: "fam_urlblock", Name: "URL拦截", LatinName: "Fam-URLBlock", Rank: RankFamily, ParentID: "ordo_extranet", Language: "go", Enabled: true, UserChoice: true})
	_ = t.Register(&Taxon{ID: "fam_dnsguard", Name: "DNS防护", LatinName: "Fam-DNSGuard", Rank: RankFamily, ParentID: "ordo_extranet", Language: "go", Enabled: true, UserChoice: true})

	mcpscan := &Taxon{ID: "ordo_mcpscan", Name: "MCP安全", LatinName: "Ordo-MCPSecurity", Rank: RankOrder, ParentID: "classis_netsecurity", Language: "go", Enabled: true, Required: false, UserChoice: true}
	_ = t.Register(mcpscan)
	_ = t.Register(&Taxon{ID: "fam_mcpstatic", Name: "MCP静态扫描", LatinName: "Fam-MCPScan-Static", Rank: RankFamily, ParentID: "ordo_mcpscan", Language: "go", Enabled: true, UserChoice: true})
	_ = t.Register(&Taxon{ID: "fam_mcpdynamic", Name: "MCP动态扫描", LatinName: "Fam-MCPScan-Dynamic", Rank: RankFamily, ParentID: "ordo_mcpscan", Language: "python", Enabled: true, UserChoice: true})
	_ = t.Register(&Taxon{ID: "fam_mcpclassify", Name: "MCP自动分类", LatinName: "Fam-MCPCategory", Rank: RankFamily, ParentID: "ordo_mcpscan", Language: "python", Enabled: true, UserChoice: true})
	_ = t.Register(&Taxon{ID: "fam_mcpmatch", Name: "MCP任务匹配", LatinName: "Fam-MCPMatch", Rank: RankFamily, ParentID: "ordo_mcpscan", Language: "go", Enabled: true, UserChoice: true})

	datasec := &Taxon{ID: "classis_datasecurity", Name: "数据安全", LatinName: "Classis-DataSecurity", Rank: RankClass, ParentID: "phylum_protectiva", Language: "go", Enabled: true, Required: true}
	_ = t.Register(datasec)
	_ = t.Register(&Taxon{ID: "ordo_transitencrypt", Name: "传输加密", LatinName: "Ordo-TransitEncrypt", Rank: RankOrder, ParentID: "classis_datasecurity", Language: "go", Enabled: true, UserChoice: true})
	_ = t.Register(&Taxon{ID: "ordo_storageencrypt", Name: "存储加密", LatinName: "Ordo-StorageEncrypt", Rank: RankOrder, ParentID: "classis_datasecurity", Language: "go", Enabled: true, UserChoice: true})
	_ = t.Register(&Taxon{ID: "ordo_piiprotect", Name: "PII防护", LatinName: "Ordo-PIIProtect", Rank: RankOrder, ParentID: "classis_datasecurity", Language: "go", Enabled: true, UserChoice: true})

	appsec := &Taxon{ID: "classis_appsecurity", Name: "应用安全", LatinName: "Classis-AppSecurity", Rank: RankClass, ParentID: "phylum_protectiva", Language: "go", Enabled: true, Required: true}
	_ = t.Register(appsec)
	_ = t.Register(&Taxon{ID: "ordo_waf", Name: "WAF", LatinName: "Ordo-WAF", Rank: RankOrder, ParentID: "classis_appsecurity", Language: "go", Enabled: true, Required: true})
	_ = t.Register(&Taxon{ID: "ordo_semantic", Name: "语义检测", LatinName: "Ordo-SemanticGuard", Rank: RankOrder, ParentID: "classis_appsecurity", Language: "go", Enabled: true, UserChoice: true})
	_ = t.Register(&Taxon{ID: "ordo_rbac", Name: "RBAC", LatinName: "Ordo-RBAC", Rank: RankOrder, ParentID: "classis_appsecurity", Language: "go", Enabled: true, Required: true})

	syssec := &Taxon{ID: "classis_syssecurity", Name: "系统安全", LatinName: "Classis-SysSecurity", Rank: RankClass, ParentID: "phylum_protectiva", Language: "go", Enabled: true, Required: true}
	_ = t.Register(syssec)
	_ = t.Register(&Taxon{ID: "ordo_audit", Name: "审计链", LatinName: "Ordo-AuditChain", Rank: RankOrder, ParentID: "classis_syssecurity", Language: "go", Enabled: true, Required: true})
	_ = t.Register(&Taxon{ID: "ordo_realtime", Name: "实时监控", LatinName: "Ordo-RealtimeMonitor", Rank: RankOrder, ParentID: "classis_syssecurity", Language: "c", Enabled: true, UserChoice: true})
	_ = t.Register(&Taxon{ID: "ordo_dynamicdef", Name: "动态防御", LatinName: "Ordo-DynamicDefense", Rank: RankOrder, ParentID: "classis_syssecurity", Language: "go", Enabled: true, UserChoice: true})
}

func (r *Registry) initFunctionalis(t *Taxonomy) {
	fn := &Taxon{ID: "phylum_functionalis", Name: "功能层", LatinName: "Functionalis", Rank: RankPhylum, ParentID: "tsg", Language: "go", Enabled: true, Required: true}
	_ = t.Register(fn)
	_ = t.Register(&Taxon{ID: "classis_chat", Name: "聊天", LatinName: "Classis-Chat", Rank: RankClass, ParentID: "phylum_functionalis", Language: "go", Enabled: true, Required: true})
	_ = t.Register(&Taxon{ID: "classis_models", Name: "模型", LatinName: "Classis-Models", Rank: RankClass, ParentID: "phylum_functionalis", Language: "go", Enabled: true, Required: true})
	_ = t.Register(&Taxon{ID: "classis_tools", Name: "工具", LatinName: "Classis-Tools", Rank: RankClass, ParentID: "phylum_functionalis", Language: "go", Enabled: true, Required: true})
	_ = t.Register(&Taxon{ID: "classis_connectors", Name: "连接器", LatinName: "Classis-Connectors", Rank: RankClass, ParentID: "phylum_functionalis", Language: "go", Enabled: true, Required: false, UserChoice: true})
}

func (r *Registry) initFrontend(t *Taxonomy) {
	fe := &Taxon{ID: "phylum_frontend", Name: "前端层", LatinName: "Frontend", Rank: RankPhylum, ParentID: "tsg", Language: "node", Enabled: true, Required: true}
	_ = t.Register(fe)
	_ = t.Register(&Taxon{ID: "classis_ui", Name: "UI框架", LatinName: "Classis-UI", Rank: RankClass, ParentID: "phylum_frontend", Language: "node", Enabled: true, Required: true})
	_ = t.Register(&Taxon{ID: "classis_dashboard", Name: "仪表盘", LatinName: "Classis-Dashboard", Rank: RankClass, ParentID: "phylum_frontend", Language: "node", Enabled: true, Required: true})
}

func (r *Registry) initBackend(t *Taxonomy) {
	be := &Taxon{ID: "phylum_backend", Name: "后端层", LatinName: "Backend", Rank: RankPhylum, ParentID: "tsg", Language: "go", Enabled: true, Required: true}
	_ = t.Register(be)
	_ = t.Register(&Taxon{ID: "classis_gateway", Name: "API网关", LatinName: "Classis-Gateway", Rank: RankClass, ParentID: "phylum_backend", Language: "go", Enabled: true, Required: true})
	_ = t.Register(&Taxon{ID: "classis_storage", Name: "存储", LatinName: "Classis-Storage", Rank: RankClass, ParentID: "phylum_backend", Language: "go", Enabled: true, Required: true})
}

func (r *Registry) RegisterHandler(id string, h ModuleHandler) error {
	tx, ok := r.taxonomy.Get(id)
	if !ok {
		return fmt.Errorf("taxon %s not found", id)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	tx.Handler = h
	r.legacyMap[id] = tx
	return nil
}

func (r *Registry) Get(id string) (*Taxon, bool) {
	return r.taxonomy.Get(id)
}

func (r *Registry) Taxonomy() *Taxonomy { return r.taxonomy }

func (r *Registry) Enable(id string) error {
	tx, ok := r.taxonomy.Get(id)
	if !ok {
		return fmt.Errorf("not found: %s", id)
	}
	if tx.Required {
		return fmt.Errorf("%s is required, cannot disable", id)
	}
	tx.Enabled = true
	return nil
}

func (r *Registry) Disable(id string) error {
	tx, ok := r.taxonomy.Get(id)
	if !ok {
		return fmt.Errorf("not found: %s", id)
	}
	if tx.Required {
		return fmt.Errorf("%s is required, cannot disable", id)
	}
	tx.Enabled = false
	return nil
}

func (r *Registry) StartAll(ctx context.Context) error {
	var errs []error
	r.taxonomy.Walk(func(tx *Taxon) bool {
		if tx.Enabled && tx.Handler != nil {
			if err := tx.Handler.Start(ctx); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", tx.ID, err))
			}
		}
		return true
	})
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (r *Registry) StopAll(ctx context.Context) error {
	var errs []error
	r.taxonomy.Walk(func(tx *Taxon) bool {
		if tx.Enabled && tx.Handler != nil {
			if err := tx.Handler.Stop(ctx); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", tx.ID, err))
			}
		}
		return true
	})
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

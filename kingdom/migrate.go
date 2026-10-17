// kingdom/migrate.go — 兼容层：现有 config.json / modules 映射到 Taxonomy
package kingdom

import "encoding/json"

// MigrateFromV4 从 v4.x config.json 迁移到 Taxonomy 状态
// 零破坏：不修改 config.json 格式，只读映射
func (r *Registry) MigrateFromV4(modules map[string]bool, v3cfg, v32cfg, v33cfg, v34cfg, v35cfg, v38cfg json.RawMessage) error {
	for id, enabled := range modules {
		if tx, ok := r.taxonomy.Get(id); ok {
			if !tx.Required {
				tx.Enabled = enabled
			}
		}
	}
	return nil
}

// ToLegacyModules 导出为 v4.x 兼容的 modules map
func (r *Registry) ToLegacyModules() map[string]bool {
	out := map[string]bool{}
	r.taxonomy.Walk(func(tx *Taxon) bool {
		if tx.Rank == RankOrder || tx.Rank == RankFamily {
			out[tx.ID] = tx.Enabled
		}
		return true
	})
	return out
}

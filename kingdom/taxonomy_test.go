package kingdom

import (
	"testing"
)

func TestNewTaxonomy(t *testing.T) {
	tx := NewTaxonomy()
	root := tx.Root()
	if root.ID != "tsg" {
		t.Fatalf("root id = %s, want tsg", root.ID)
	}
	if root.Rank != RankKingdom {
		t.Fatalf("root rank = %v, want Kingdom", root.Rank)
	}
}

func TestTaxonomyRegister(t *testing.T) {
	tx := NewTaxonomy()
	phylum := &Taxon{ID: "phylum_test", Name: "测试门", Rank: RankPhylum, ParentID: "tsg"}
	if err := tx.Register(phylum); err != nil {
		t.Fatalf("register phylum: %v", err)
	}
	got, ok := tx.Get("phylum_test")
	if !ok || got.Name != "测试门" {
		t.Fatal("get phylum failed")
	}
	// 重复注册应报错
	if err := tx.Register(phylum); err == nil {
		t.Fatal("duplicate register should fail")
	}
	// 父节点不存在应报错
	bad := &Taxon{ID: "bad", Name: "Bad", Rank: RankPhylum, ParentID: "nonexist"}
	if err := tx.Register(bad); err == nil {
		t.Fatal("missing parent should fail")
	}
	// 层级跳跃应报错
	skip := &Taxon{ID: "skip", Name: "Skip", Rank: RankClass, ParentID: "tsg"}
	if err := tx.Register(skip); err == nil {
		t.Fatal("rank skip should fail")
	}
}

func TestTaxonomyWalk(t *testing.T) {
	tx := NewTaxonomy()
	_ = tx.Register(&Taxon{ID: "p1", Name: "P1", Rank: RankPhylum, ParentID: "tsg"})
	_ = tx.Register(&Taxon{ID: "c1", Name: "C1", Rank: RankClass, ParentID: "p1"})
	count := 0
	tx.Walk(func(tx *Taxon) bool {
		count++
		return true
	})
	if count != 3 {
		t.Fatalf("walk count = %d, want 3", count)
	}
}

func TestTaxonomyFlatten(t *testing.T) {
	tx := NewTaxonomy()
	_ = tx.Register(&Taxon{ID: "p1", Name: "P1", Rank: RankPhylum, ParentID: "tsg"})
	flat := tx.Flatten()
	if len(flat) != 2 {
		t.Fatalf("flatten len = %d, want 2", len(flat))
	}
}

package kingdom

import (
	"testing"
)

func TestNewLangBridge(t *testing.T) {
	lb := NewLangBridge()
	if lb == nil {
		t.Fatal("langbridge nil")
	}
	r := lb.Report()
	if !r.Go {
		t.Fatal("go should always be true")
	}
	// 探测结果至少包含 go 的布尔值，不 panic 即可
}

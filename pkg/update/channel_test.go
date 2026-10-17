package update

import "testing"

func TestIsStableRelease(t *testing.T) {
	cases := []struct {
		cur, rel string
		want     bool
	}{
		{"v4.14.0", "v4.15.0", true},   // minor bump patch==0
		{"v4.15.0", "v4.15.1", false},  // patch bump
		{"v4.15.0", "v5.0.0", true},    // major bump
		{"v4.15.0", "v4.16.0-beta", false}, // prerelease
		{"v4.15.0", "v4.15.0-rc1", false},
	}
	for _, c := range cases {
		got := IsStableRelease(c.cur, c.rel)
		if got != c.want {
			t.Fatalf("IsStableRelease(%s,%s)=%v want %v", c.cur, c.rel, got, c.want)
		}
	}
}

func TestIsMajorBump(t *testing.T) {
	if !IsMajorBump("v4.15.0", "v5.0.0") {
		t.Fatal("expected major bump")
	}
	if IsMajorBump("v4.15.0", "v4.16.0") {
		t.Fatal("expected not major bump")
	}
}

func TestFilterByChannel(t *testing.T) {
	rels := []Release{
		{TagName: "v4.15.1"},
		{TagName: "v4.16.0"},
		{TagName: "v4.16.0-beta"},
		{TagName: "v5.0.0"},
	}
	stable := FilterByChannel("v4.15.0", rels, ChannelStable)
	if len(stable) != 2 {
		t.Fatalf("expected 2 stable, got %d", len(stable))
	}
	beta := FilterByChannel("v4.15.0", rels, ChannelBeta)
	if len(beta) != 4 {
		t.Fatalf("expected 4 beta, got %d", len(beta))
	}
}

func TestParseChannel(t *testing.T) {
	if ParseChannel("beta") != ChannelBeta {
		t.Fatal("expected beta")
	}
	if ParseChannel("stable") != ChannelStable {
		t.Fatal("expected stable")
	}
	if ParseChannel("unknown") != ChannelStable {
		t.Fatal("expected default stable")
	}
}

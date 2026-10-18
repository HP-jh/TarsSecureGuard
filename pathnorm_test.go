package main

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/foo/../bar", "/bar"},
		{"./baz", "/baz"},
		{".", "/"},
	}
	for _, c := range cases {
		got := normalizePath(c.in)
		if got != c.want {
			t.Fatalf("normalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

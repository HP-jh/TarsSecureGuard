package main

import (
	"path"
	"strings"
)

func normalizePath(p string) string {
	p = path.Clean(p)
	if p == "." {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

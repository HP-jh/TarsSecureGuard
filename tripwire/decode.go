package tripwire

import (
	"encoding/base64"
	"regexp"
	"strconv"
)

// Decoded 解码后的段
type Decoded struct {
	Start int
	End   int
	Text  string
	Kind  string
}

var base64RunRe = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
var hexRunRe = regexp.MustCompile(`[0-9a-fA-F]{16,}`)
var percentRe = regexp.MustCompile(`(%[0-9A-Fa-f]{2})+`)

func printableRatio(bytes []byte) float32 {
	if len(bytes) == 0 {
		return 0
	}
	ok := 0
	for _, b := range bytes {
		if (b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t' {
			ok++
		}
	}
	return float32(ok) / float32(len(bytes))
}

func texty(bytes []byte) (string, bool) {
	if printableRatio(bytes) < 0.85 {
		return "", false
	}
	s, err := strconv.Unquote(`"` + string(bytes) + `"`)
	if err == nil {
		return s, true
	}
	return string(bytes), true
}

func base64Candidates(text string) []Decoded {
	var out []Decoded
	for _, m := range base64RunRe.FindAllStringIndex(text, -1) {
		s := text[m[0]:m[1]]
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(s)
		}
		if err != nil {
			continue
		}
		d, ok := texty(decoded)
		if !ok || d == s {
			continue
		}
		out = append(out, Decoded{Start: m[0], End: m[1], Text: d, Kind: "base64"})
	}
	return out
}

func hexCandidates(text string) []Decoded {
	var out []Decoded
	for _, m := range hexRunRe.FindAllStringIndex(text, -1) {
		s := text[m[0]:m[1]]
		if len(s)%2 != 0 {
			continue
		}
		bytes := make([]byte, 0, len(s)/2)
		ok := true
		for i := 0; i < len(s); i += 2 {
			b, err := strconv.ParseUint(s[i:i+2], 16, 8)
			if err != nil {
				ok = false
				break
			}
			bytes = append(bytes, byte(b))
		}
		if !ok {
			continue
		}
		d, ok := texty(bytes)
		if !ok {
			continue
		}
		out = append(out, Decoded{Start: m[0], End: m[1], Text: d, Kind: "hex"})
	}
	return out
}

func hexval(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

func percentCandidates(text string) []Decoded {
	if !percentRe.MatchString(text) {
		return nil
	}
	b := []byte(text)
	decoded := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		if b[i] == '%' && i+3 <= len(b) {
			if h, ok1 := hexval(b[i+1]); ok1 {
				if l, ok2 := hexval(b[i+2]); ok2 {
					decoded = append(decoded, h*16+l)
					i += 3
					continue
				}
			}
		}
		decoded = append(decoded, b[i])
		i++
	}
	d, ok := texty(decoded)
	if !ok || d == text {
		return nil
	}
	return []Decoded{{Start: 0, End: len(text), Text: d, Kind: "url"}}
}

func rot13Char(c byte) byte {
	switch {
	case c >= 'a' && c <= 'z':
		return ((c - 'a' + 13) % 26) + 'a'
	case c >= 'A' && c <= 'Z':
		return ((c - 'A' + 13) % 26) + 'A'
	}
	return c
}

func rot13Candidate(text string) *Decoded {
	hasAlpha := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasAlpha = true
			break
		}
	}
	if !hasAlpha {
		return nil
	}
	decoded := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		decoded[i] = rot13Char(text[i])
	}
	d, ok := texty(decoded)
	if !ok {
		return nil
	}
	return &Decoded{Start: 0, End: len(text), Text: d, Kind: "rot13"}
}

func vsByte(cp rune) (byte, bool) {
	switch {
	case cp >= 0xFE00 && cp <= 0xFE0F:
		return byte(cp - 0xFE00), true
	case cp >= 0xE0100 && cp <= 0xE01EF:
		return byte(cp - 0xE0100 + 16), true
	}
	return 0, false
}

const vsMinRun = 4

func vsCandidates(text string) []Decoded {
	var out []Decoded
	var start int = -1
	var end int
	var bytes []byte

	flush := func() {
		if len(bytes) >= vsMinRun {
			if d, ok := texty(bytes); ok {
				out = append(out, Decoded{Start: start, End: end, Text: d, Kind: "vs"})
			}
		}
		bytes = bytes[:0]
	}

	for i, ch := range text {
		if b, ok := vsByte(ch); ok {
			if start < 0 {
				start = i
			}
			bytes = append(bytes, b)
			end = i + len(string(ch))
		} else {
			if start >= 0 {
				flush()
				start = -1
			}
		}
	}
	if start >= 0 {
		flush()
	}
	return out
}

// DecodeCandidates 返回文本的候选解码以供重新扫描
func DecodeCandidates(text string) []Decoded {
	var out []Decoded
	out = append(out, base64Candidates(text)...)
	out = append(out, hexCandidates(text)...)
	out = append(out, percentCandidates(text)...)
	out = append(out, vsCandidates(text)...)
	if d := rot13Candidate(text); d != nil {
		out = append(out, *d)
	}
	return out
}

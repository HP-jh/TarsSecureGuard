package tripwire

import (
	"strings"
	"unicode"
)

// Smuggle 走私类型
type smuggleKind int

const (
	smuggleZeroWidth smuggleKind = iota
	smuggleBidi
	smuggleTag
)

func smuggleOf(c rune) (smuggleKind, bool) {
	switch c {
	case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff':
		return smuggleZeroWidth, true
	}
	switch {
	case c >= '\u202a' && c <= '\u202e':
		return smuggleBidi, true
	case c >= '\u2066' && c <= '\u2069':
		return smuggleBidi, true
	case c >= '\U000E0000' && c <= '\U000E007F':
		return smuggleTag, true
	}
	return 0, false
}

func findingForSmuggle(cat smuggleKind, start, end int) Finding {
	var label string
	var sev Severity
	var score float64
	switch cat {
	case smuggleTag:
		label, sev, score = "unicode_tag_smuggling", SeverityHigh, 0.95
	case smuggleBidi:
		label, sev, score = "bidi_control", SeverityMedium, 0.70
	case smuggleZeroWidth:
		label, sev, score = "zero_width", SeverityMedium, 0.60
	}
	return Finding{Kind: KindObfuscation, Label: label, Severity: sev, Score: score, Start: start, End: end, Source: SourceUser}
}

func homoglyphFinding(start, end int, detail string) Finding {
	return Finding{Kind: KindObfuscation, Label: "homoglyph", Severity: SeverityLow, Score: 0.30, Start: start, End: end, Source: SourceUser, Detail: detail}
}

// confusableToASCII 将形似拉丁字母的字符折叠为ASCII
func confusableToASCII(c rune) (rune, bool) {
	switch c {
	// 西里尔小写
	case '\u0430':
		return 'a', true
	case '\u0435':
		return 'e', true
	case '\u043e':
		return 'o', true
	case '\u0440':
		return 'p', true
	case '\u0441':
		return 'c', true
	case '\u0443':
		return 'y', true
	case '\u0445':
		return 'x', true
	case '\u0456':
		return 'i', true
	case '\u0458':
		return 'j', true
	case '\u0455':
		return 's', true
	case '\u043a':
		return 'k', true
	case '\u043c':
		return 'm', true
	// 西里尔大写
	case '\u0410':
		return 'A', true
	case '\u0412':
		return 'B', true
	case '\u0415':
		return 'E', true
	case '\u041a':
		return 'K', true
	case '\u041c':
		return 'M', true
	case '\u041d':
		return 'H', true
	case '\u041e':
		return 'O', true
	case '\u0420':
		return 'P', true
	case '\u0421':
		return 'C', true
	case '\u0422':
		return 'T', true
	case '\u0423':
		return 'Y', true
	case '\u0425':
		return 'X', true
	case '\u0406':
		return 'I', true
	case '\u0408':
		return 'J', true
	case '\u0405':
		return 'S', true
	// 希腊小写
	case '\u03bf':
		return 'o', true
	case '\u03b1':
		return 'a', true
	case '\u03b5':
		return 'e', true
	case '\u03c1':
		return 'p', true
	case '\u03b9':
		return 'i', true
	case '\u03bd':
		return 'v', true
	case '\u03ba':
		return 'k', true
	case '\u03c7':
		return 'x', true
	// 希腊大写
	case '\u0391':
		return 'A', true
	case '\u0392':
		return 'B', true
	case '\u0395':
		return 'E', true
	case '\u0397':
		return 'H', true
	case '\u0399':
		return 'I', true
	case '\u039a':
		return 'K', true
	case '\u039c':
		return 'M', true
	case '\u039d':
		return 'N', true
	case '\u039f':
		return 'O', true
	case '\u03a1':
		return 'P', true
	case '\u03a4':
		return 'T', true
	case '\u03a5':
		return 'Y', true
	case '\u03a7':
		return 'X', true
	case '\u0396':
		return 'Z', true
	// 全角字符 → 半角
	case '\uff01':
		return '!', true
	case '\uff02':
		return '"', true
	case '\uff03':
		return '#', true
	case '\uff04':
		return '$', true
	case '\uff05':
		return '%', true
	case '\uff06':
		return '&', true
	case '\uff07':
		return '\'', true
	case '\uff08':
		return '(', true
	case '\uff09':
		return ')', true
	case '\uff0a':
		return '*', true
	case '\uff0b':
		return '+', true
	case '\uff0c':
		return ',', true
	case '\uff0d':
		return '-', true
	case '\uff0e':
		return '.', true
	case '\uff0f':
		return '/', true
	case '\uff10':
		return '0', true
	case '\uff11':
		return '1', true
	case '\uff12':
		return '2', true
	case '\uff13':
		return '3', true
	case '\uff14':
		return '4', true
	case '\uff15':
		return '5', true
	case '\uff16':
		return '6', true
	case '\uff17':
		return '7', true
	case '\uff18':
		return '8', true
	case '\uff19':
		return '9', true
	case '\uff1a':
		return ':', true
	case '\uff1b':
		return ';', true
	case '\uff1c':
		return '<', true
	case '\uff1d':
		return '=', true
	case '\uff1e':
		return '>', true
	case '\uff1f':
		return '?', true
	case '\uff20':
		return '@', true
	case '\uff21':
		return 'A', true
	case '\uff22':
		return 'B', true
	case '\uff23':
		return 'C', true
	case '\uff24':
		return 'D', true
	case '\uff25':
		return 'E', true
	case '\uff26':
		return 'F', true
	case '\uff27':
		return 'G', true
	case '\uff28':
		return 'H', true
	case '\uff29':
		return 'I', true
	case '\uff2a':
		return 'J', true
	case '\uff2b':
		return 'K', true
	case '\uff2c':
		return 'L', true
	case '\uff2d':
		return 'M', true
	case '\uff2e':
		return 'N', true
	case '\uff2f':
		return 'O', true
	case '\uff30':
		return 'P', true
	case '\uff31':
		return 'Q', true
	case '\uff32':
		return 'R', true
	case '\uff33':
		return 'S', true
	case '\uff34':
		return 'T', true
	case '\uff35':
		return 'U', true
	case '\uff36':
		return 'V', true
	case '\uff37':
		return 'W', true
	case '\uff38':
		return 'X', true
	case '\uff39':
		return 'Y', true
	case '\uff3a':
		return 'Z', true
	case '\uff3b':
		return '[', true
	case '\uff3c':
		return '\\', true
	case '\uff3d':
		return ']', true
	case '\uff3e':
		return '^', true
	case '\uff3f':
		return '_', true
	case '\uff40':
		return '`', true
	case '\uff41':
		return 'a', true
	case '\uff42':
		return 'b', true
	case '\uff43':
		return 'c', true
	case '\uff44':
		return 'd', true
	case '\uff45':
		return 'e', true
	case '\uff46':
		return 'f', true
	case '\uff47':
		return 'g', true
	case '\uff48':
		return 'h', true
	case '\uff49':
		return 'i', true
	case '\uff4a':
		return 'j', true
	case '\uff4b':
		return 'k', true
	case '\uff4c':
		return 'l', true
	case '\uff4d':
		return 'm', true
	case '\uff4e':
		return 'n', true
	case '\uff4f':
		return 'o', true
	case '\uff50':
		return 'p', true
	case '\uff51':
		return 'q', true
	case '\uff52':
		return 'r', true
	case '\uff53':
		return 's', true
	case '\uff54':
		return 't', true
	case '\uff55':
		return 'u', true
	case '\uff56':
		return 'v', true
	case '\uff57':
		return 'w', true
	case '\uff58':
		return 'x', true
	case '\uff59':
		return 'y', true
	case '\uff5a':
		return 'z', true
	case '\uff5b':
		return '{', true
	case '\uff5c':
		return '|', true
	case '\uff5d':
		return '}', true
	case '\uff5e':
		return '~', true
	}
	return 0, false
}

// Normalized 规范化结果
type Normalized struct {
	Text     string    // 去走私、折叠后的文本
	Findings []Finding // 走私发现，偏移量在原始文本中
	orig     string    // 原始文本
	mapIdx   []int     // mapIdx[i] = 规范化字节i对应的原始字节偏移
}

// ToOriginal 将规范化字节偏移映射回原始文本
func (n *Normalized) ToOriginal(normByte int) int {
	if normByte < len(n.mapIdx) {
		return n.mapIdx[normByte]
	}
	return len(n.orig)
}

// Remap 将发现的偏移从规范化坐标重写为原始坐标
func (n *Normalized) Remap(f Finding) Finding {
	f.Start = n.ToOriginal(f.Start)
	f.End = n.ToOriginal(f.End)
	return f
}

// Analyze 规范化原始文本，检测unicode走私并折叠其余部分
func Analyze(original string) *Normalized {
	var text strings.Builder
	var mapIdx []int
	var findings []Finding

	var run *struct {
		cat   smuggleKind
		start int
		end   int
	}
	var homoRun *struct {
		start int
		end   int
	}

	flushRun := func() {
		if run != nil {
			findings = append(findings, findingForSmuggle(run.cat, run.start, run.end))
			run = nil
		}
	}
	flushHomo := func() {
		if homoRun != nil {
			findings = append(findings, homoglyphFinding(homoRun.start, homoRun.end, original[homoRun.start:homoRun.end]))
			homoRun = nil
		}
	}

	for i, ch := range original {
		end := i + len(string(ch))
		if cat, ok := smuggleOf(ch); ok {
			flushHomo()
			if run != nil && run.cat == cat {
				run.end = end
			} else {
				flushRun()
				run = &struct {
					cat   smuggleKind
					start int
					end   int
				}{cat: cat, start: i, end: end}
			}
			// 显示可打印的标签块字符 (U+E0020..=U+E007E -> ASCII)
			if cat == smuggleTag {
				cp := int(ch)
				if cp >= 0xE0020 && cp <= 0xE007E {
					if rch, ok := runeFromInt(cp - 0xE0000); ok {
						text.WriteRune(rch)
						mapIdx = append(mapIdx, i)
					}
				}
			}
		} else {
			flushRun()
			if ascii, ok := confusableToASCII(ch); ok {
				if homoRun == nil {
					homoRun = &struct{ start, end int }{start: i, end: end}
				} else {
					homoRun.end = end
				}
				text.WriteRune(ascii)
				mapIdx = append(mapIdx, i)
			} else {
				flushHomo()
				// 简化的NFKC：处理常见组合字符
				if nch, changed := simpleNFKC(ch); changed {
					text.WriteRune(nch)
					mapIdx = append(mapIdx, i)
				} else {
					text.WriteRune(ch)
					mapIdx = append(mapIdx, i)
				}
			}
		}
	}
	flushRun()
	flushHomo()
	mapIdx = append(mapIdx, len(original))

	return &Normalized{
		Text:     text.String(),
		Findings: findings,
		orig:     original,
		mapIdx:   mapIdx,
	}
}

func runeFromInt(i int) (rune, bool) {
	if i >= 0 && i <= unicode.MaxRune {
		return rune(i), true
	}
	return 0, false
}

// Normalize returns the smuggling-cleaned, homoglyph-folded text.
func Normalize(text string) string {
	return Analyze(text).Text
}

// simpleNFKC 简化的NFKC折叠——覆盖最常见的兼容性字符
func simpleNFKC(ch rune) (rune, bool) {
	// 处理带组合音符的拉丁字母
	switch ch {
	case '\u00e0', '\u00e1', '\u00e2', '\u00e3', '\u00e4', '\u00e5':
		return 'a', true
	case '\u00e7':
		return 'c', true
	case '\u00e8', '\u00e9', '\u00ea', '\u00eb':
		return 'e', true
	case '\u00ec', '\u00ed', '\u00ee', '\u00ef':
		return 'i', true
	case '\u00f1':
		return 'n', true
	case '\u00f2', '\u00f3', '\u00f4', '\u00f5', '\u00f6':
		return 'o', true
	case '\u00f9', '\u00fa', '\u00fb', '\u00fc':
		return 'u', true
	case '\u00fd', '\u00ff':
		return 'y', true
	case '\u00c0', '\u00c1', '\u00c2', '\u00c3', '\u00c4', '\u00c5':
		return 'A', true
	case '\u00c7':
		return 'C', true
	case '\u00c8', '\u00c9', '\u00ca', '\u00cb':
		return 'E', true
	case '\u00cc', '\u00cd', '\u00ce', '\u00cf':
		return 'I', true
	case '\u00d1':
		return 'N', true
	case '\u00d2', '\u00d3', '\u00d4', '\u00d5', '\u00d6':
		return 'O', true
	case '\u00d9', '\u00da', '\u00db', '\u00dc':
		return 'U', true
	case '\u00dd':
		return 'Y', true
	case '\u0153':
		return 'o', true
	case '\u0152':
		return 'O', true
	case '\u00e6':
		return 'a', true
	case '\u00c6':
		return 'A', true
	case '\u00df':
		return 's', true // 简化为s，实际应为ss
	}
	return ch, false
}

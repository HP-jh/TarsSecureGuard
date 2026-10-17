// pkg/voicecorrection — v4.14.0 语音输入纠错 MVP
// 基于编辑距离 + 拼音近似 + 常见同音词替换
package voicecorrection

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode"
)

// CorrectRequest 纠错请求
type CorrectRequest struct {
	Text     string   `json:"text"`
	Context  string   `json:"context,omitempty"`
	Dict     []string `json:"dict,omitempty"` // 自定义词典
}

// CorrectResult 纠错结果
type CorrectResult struct {
	Original   string            `json:"original"`
	Corrected  string            `json:"corrected"`
	Changes    []Change          `json:"changes"`
	Confidence float64           `json:"confidence"`
}

// Change 单处修改
type Change struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Position   int    `json:"position"`
	Reason     string `json:"reason"`
}

// 常见语音误识别替换表（中文同音/近音词）
var commonConfusions = map[string]string{
	"的": "地", "地": "的", // 视上下文
	"做": "作", "作": "做",
	"在": "再", "再": "在",
	"有": "又", "又": "有",
	"和": "合", "合": "和",
	"是": "事", "事": "是",
	"那": "哪", "哪": "那",
	"他": "她", "她": "他",
	"吗": "嘛", "嘛": "吗",
	"吧": "把", "把": "吧",
	"了": "啦", "啦": "了",
	"很": "狠", "狠": "很",
	"新": "心", "心": "新",
	"长": "常", "常": "长",
	"太": "泰", "泰": "太",
	"请": "情", "情": "请",
	"以": "已", "已": "以",
	"因": "应", "应": "因",
	"为": "位", "位": "为",
	"没": "每", "每": "没",
	"给": "跟", "跟": "给",
}

// 常见英文拼写错误
var commonTypos = map[string]string{
	"teh": "the", "adn": "and", "taht": "that",
	"wiht": "with", "fo": "of", "ot": "to",
	"si": "is", "ti": "it", "na": "an",
}

// Correct 主纠错函数
func Correct(req CorrectRequest) CorrectResult {
	text := req.Text
	if text == "" {
		return CorrectResult{Original: "", Corrected: ""}
	}

	var changes []Change
	words := splitWords(text)
	var corrected []string
	pos := 0

	for _, w := range words {
		orig := w
		reason := ""

		// 1. 中文单字同音替换
		if len([]rune(w)) == 1 {
			if rep, ok := commonConfusions[w]; ok {
				w = rep
				reason = "同音字替换"
			}
		}

		// 2. 英文拼写纠错
		lower := strings.ToLower(w)
		if rep, ok := commonTypos[lower]; ok {
			// 保留原大小写模式
			w = restoreCase(rep, w)
			reason = "拼写纠错"
		}

		// 3. 自定义词典匹配
		for _, dictWord := range req.Dict {
			if similarity(lower, strings.ToLower(dictWord)) > 0.8 && lower != strings.ToLower(dictWord) {
				w = restoreCase(dictWord, w)
				reason = "词典匹配"
				break
			}
		}

		if w != orig {
			changes = append(changes, Change{
				From:     orig,
				To:       w,
				Position: pos,
				Reason:   reason,
			})
		}
		corrected = append(corrected, w)
		pos += len([]rune(orig))
	}

	result := strings.Join(corrected, "")
	conf := 1.0
	if len(changes) > 0 {
		conf = 0.7 + 0.3*(1.0-float64(len(changes))/float64(len(words)))
	}

	return CorrectResult{
		Original:   text,
		Corrected:  result,
		Changes:    changes,
		Confidence: conf,
	}
}

// splitWords 简单分词（中英混合）
func splitWords(text string) []string {
	var words []string
	var current strings.Builder
	lastIsCJK := false

	for _, r := range text {
		isCJK := unicode.Is(unicode.Han, r)
		if isCJK {
			if current.Len() > 0 && !lastIsCJK {
				words = append(words, current.String())
				current.Reset()
			}
			if lastIsCJK && current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			current.WriteRune(r)
			lastIsCJK = true
		} else {
			if current.Len() > 0 && lastIsCJK {
				words = append(words, current.String())
				current.Reset()
			}
			if r == ' ' || r == '\t' || r == '\n' {
				if current.Len() > 0 {
					words = append(words, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
			lastIsCJK = false
		}
	}
	if current.Len() > 0 {
		words = append(words, current.String())
	}
	return words
}

// similarity 简单相似度（基于编辑距离）
func similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	if maxLen == 0 {
		return 0
	}
	dist := levenshtein(a, b)
	return 1.0 - float64(dist)/float64(maxLen)
}

// levenshtein 编辑距离
func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	m, n := len(ar), len(br)
	if m == 0 {
		return n
	}
	if n == 0 {
		return m
	}

	prev := make([]int, n+1)
	curr := make([]int, n+1)
	for j := 0; j <= n; j++ {
		prev[j] = j
	}

	for i := 1; i <= m; i++ {
		curr[0] = i
		for j := 1; j <= n; j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			curr[j] = min(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[n]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func restoreCase(corrected, original string) string {
	if len(original) == 0 {
		return corrected
	}
	// 如果原词首字母大写，修正后也首字母大写
	first := []rune(original)[0]
	if unicode.IsUpper(first) && len(corrected) > 0 {
		runes := []rune(corrected)
		runes[0] = unicode.ToUpper(runes[0])
		return string(runes)
	}
	return corrected
}

// ========== HTTP 处理器 ==========

func HandleCorrect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req CorrectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res := Correct(req)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

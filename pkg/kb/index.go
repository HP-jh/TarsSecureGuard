package kb

import (
	"math"
	"strings"
	"sync"
)

// InvertedIndex 内存倒排索引（TF-IDF 轻量版）
type InvertedIndex struct {
	mu     sync.RWMutex
	terms  map[string]map[string]float64 // term -> chunkID -> TF
	df     map[string]int                // term -> document frequency
	totalN int                           // 总 chunk 数
}

func NewIndex() *InvertedIndex {
	return &InvertedIndex{
		terms: make(map[string]map[string]float64),
		df:    make(map[string]int),
	}
}

func (idx *InvertedIndex) Add(c Chunk) {
	words := tokenize(c.Text)
	freq := termFreq(words)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	for term, tf := range freq {
		if idx.terms[term] == nil {
			idx.terms[term] = make(map[string]float64)
		}
		idx.terms[term][c.ID] = tf
		idx.df[term]++
	}
	idx.totalN++
}

func (idx *InvertedIndex) Remove(chunkID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	for term, docs := range idx.terms {
		if _, ok := docs[chunkID]; ok {
			delete(docs, chunkID)
			idx.df[term]--
			if idx.df[term] <= 0 {
				delete(idx.df, term)
			}
			if len(docs) == 0 {
				delete(idx.terms, term)
			}
		}
	}
	idx.totalN--
	if idx.totalN < 0 {
		idx.totalN = 0
	}
}

func (idx *InvertedIndex) Search(query string) map[string]float64 {
	words := tokenize(query)
	qFreq := termFreq(words)

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	scores := make(map[string]float64)
	for term, qtf := range qFreq {
		docs, ok := idx.terms[term]
		if !ok {
			continue
		}
		idf := math.Log(1 + float64(idx.totalN)/float64(1+idx.df[term]))
		for docID, tf := range docs {
			scores[docID] += tf * idf * qtf * idf
		}
	}
	return scores
}

func (idx *InvertedIndex) TermCount() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.terms)
}

// tokenize 简单分词（按空格和标点）
func tokenize(text string) []string {
	var words []string
	for _, w := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' ||
			r == ',' || r == '.' || r == '!' || r == '?' ||
			r == ';' || r == ':' || r == '"' || r == '\'' ||
			r == '(' || r == ')' || r == '[' || r == ']' ||
			r == '{' || r == '}' || r == '/' || r == '\\' ||
			r == '|' || r == '&' || r == '*' || r == '+' ||
			r == '-' || r == '=' || r == '<' || r == '>' ||
			r == '@' || r == '#' || r == '$' || r == '%' ||
			r == '^' || r == '`' || r == '~'
	}) {
		w = strings.ToLower(strings.TrimSpace(w))
		if len(w) > 1 {
			words = append(words, w)
		}
	}
	return words
}

func termFreq(words []string) map[string]float64 {
	freq := make(map[int]float64)
	for _, w := range words {
		freq[len(w)]++ // dummy key to count
	}
	// Actually count
	counts := make(map[string]int)
	for _, w := range words {
		counts[w]++
	}
	res := make(map[string]float64)
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	for w, c := range counts {
		if maxCount > 0 {
			res[w] = 0.5 + 0.5*float64(c)/float64(maxCount)
		} else {
			res[w] = 1.0
		}
	}
	return res
}

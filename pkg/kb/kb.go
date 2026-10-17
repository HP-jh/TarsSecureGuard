// pkg/kb — v4.14.0 Knowledge Base 骨架 MVP
package kb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Document 知识库文档
type Document struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Content   string            `json:"content"`
	Source    string            `json:"source"`
	Tags      []string          `json:"tags"`
	Meta      map[string]string `json:"meta"`
	ChunkedAt time.Time         `json:"chunkedAt"`
}

// Chunk 文本块
type Chunk struct {
	ID       string  `json:"id"`
	DocID    string  `json:"docId"`
	Text     string  `json:"text"`
	Score    float64 `json:"score"`
	Position int     `json:"position"`
}

// QueryResult 检索结果
type QueryResult struct {
	Query   string    `json:"query"`
	Chunks  []Chunk   `json:"chunks"`
	Total   int       `json:"total"`
	Latency int64     `json:"latencyMs"`
}

// KB 知识库实例
type KB struct {
	mu      sync.RWMutex
	docs    map[string]*Document
	chunks  []Chunk
	index   *InvertedIndex
}

func New() *KB {
	return &KB{
		docs:   make(map[string]*Document),
		chunks: make([]Chunk, 0),
		index:  NewIndex(),
	}
}

// Ingest 摄入文档
func (k *KB) Ingest(doc *Document) error {
	if doc.ID == "" {
		doc.ID = fmt.Sprintf("doc_%d", time.Now().UnixNano())
	}
	doc.ChunkedAt = time.Now()

	chunks := ChunkText(doc.Content, 256, 32)
	k.mu.Lock()
	k.docs[doc.ID] = doc
	for i, c := range chunks {
		c.ID = fmt.Sprintf("%s_c%d", doc.ID, i)
		c.DocID = doc.ID
		c.Position = i
		k.chunks = append(k.chunks, c)
		k.index.Add(c)
	}
	k.mu.Unlock()
	return nil
}

// Query 检索
func (k *KB) Query(q string, topK int) QueryResult {
	start := time.Now()
	if topK <= 0 {
		topK = 5
	}

	k.mu.RLock()
	scores := k.index.Search(q)
	k.mu.RUnlock()

	// 按分数排序
	type pair struct {
		chunk Chunk
		score float64
	}
	var pairs []pair
	for id, score := range scores {
		for i := range k.chunks {
			if k.chunks[i].ID == id {
				pairs = append(pairs, pair{chunk: k.chunks[i], score: score})
				break
			}
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].score > pairs[j].score
	})

	var out []Chunk
	for i := 0; i < len(pairs) && i < topK; i++ {
		pairs[i].chunk.Score = pairs[i].score
		out = append(out, pairs[i].chunk)
	}

	return QueryResult{
		Query:   q,
		Chunks:  out,
		Total:   len(out),
		Latency: time.Since(start).Milliseconds(),
	}
}

// ListDocs 列出所有文档
func (k *KB) ListDocs() []*Document {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]*Document, 0, len(k.docs))
	for _, d := range k.docs {
		out = append(out, d)
	}
	return out
}

// DeleteDoc 删除文档
func (k *KB) DeleteDoc(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.docs, id)
	var newChunks []Chunk
	for _, c := range k.chunks {
		if c.DocID != id {
			newChunks = append(newChunks, c)
		} else {
			k.index.Remove(c.ID)
		}
	}
	k.chunks = newChunks
}

// Stats 统计
func (k *KB) Stats() map[string]interface{} {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return map[string]interface{}{
		"documents": len(k.docs),
		"chunks":    len(k.chunks),
		"terms":     k.index.TermCount(),
	}
}

// ========== HTTP 处理器（供 main.go 调用） ==========

var DefaultKB = New()

func HandleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var doc Document
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := DefaultKB.Ingest(&doc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "true", "id": doc.ID})
}

func HandleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Query string `json:"query"`
		TopK  int    `json:"topK"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res := DefaultKB.Query(req.Query, req.TopK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func HandleListDocs(w http.ResponseWriter, r *http.Request) {
	docs := DefaultKB.ListDocs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"docs": docs, "total": len(docs)})
}

func HandleDeleteDoc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	DefaultKB.DeleteDoc(req.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
}

func HandleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DefaultKB.Stats())
}

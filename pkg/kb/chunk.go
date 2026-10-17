package kb

import (
	"strings"
	"unicode/utf8"
)

// ChunkText 简单文本分块（按字符数 + 重叠窗口）
func ChunkText(text string, chunkSize, overlap int) []Chunk {
	if chunkSize <= 0 {
		chunkSize = 256
	}
	if overlap < 0 {
		overlap = 0
	}
	if overlap >= chunkSize {
		overlap = chunkSize / 4
	}

	// 先按段落拆分
	paragraphs := strings.Split(text, "\n")
	var chunks []Chunk
	var current strings.Builder
	currentSize := 0

	flush := func() {
		if current.Len() > 0 {
			chunks = append(chunks, Chunk{Text: strings.TrimSpace(current.String())})
			// 保留重叠部分
			s := current.String()
			if overlap > 0 && utf8.RuneCountInString(s) > overlap {
				runes := []rune(s)
				start := len(runes) - overlap
				if start < 0 {
					start = 0
				}
				current.Reset()
				current.WriteString(string(runes[start:]))
				currentSize = overlap
			} else {
				current.Reset()
				currentSize = 0
			}
		}
	}

	for _, p := range paragraphs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pLen := utf8.RuneCountInString(p)
		if currentSize+pLen > chunkSize && currentSize > 0 {
			flush()
		}
		if currentSize > 0 {
			current.WriteString("\n")
		}
		current.WriteString(p)
		currentSize = utf8.RuneCountInString(current.String())
		if currentSize >= chunkSize {
			flush()
		}
	}
	if current.Len() > 0 {
		chunks = append(chunks, Chunk{Text: strings.TrimSpace(current.String())})
	}
	return chunks
}

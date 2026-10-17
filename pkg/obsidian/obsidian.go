// pkg/obsidian — v4.14.0 Obsidian Vault 连接器 MVP
package obsidian

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VaultConfig Obsidian Vault 配置
type VaultConfig struct {
	Path      string `json:"path"`
	AutoSync  bool   `json:"autoSync"`
	SyncInterval int `json:"syncInterval"` // minutes
}

// ObsidianDoc Vault 中的文档
type ObsidianDoc struct {
	Path      string            `json:"path"`
	Title     string            `json:"title"`
	Content   string            `json:"content"`
	FrontMatter map[string]interface{} `json:"frontMatter"`
	Links     []string          `json:"links"`     // [[link]] 解析
	Tags      []string          `json:"tags"`
	Modified  time.Time         `json:"modified"`
}

// ParseVault 扫描并解析整个 Vault
func ParseVault(vaultPath string) ([]ObsidianDoc, error) {
	var docs []ObsidianDoc

	err := filepath.Walk(vaultPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 跳过无权限文件
		}
		if info.IsDir() {
			// 跳过 .obsidian 配置目录和附件目录
			name := info.Name()
			if name == ".obsidian" || name == "Attachments" || name == "attachments" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}

		doc, err := ParseNote(path, vaultPath)
		if err != nil {
			return nil // 跳过解析失败的文件
		}
		docs = append(docs, doc)
		return nil
	})

	return docs, err
}

// ParseNote 解析单个 Markdown 笔记
func ParseNote(filePath, vaultRoot string) (ObsidianDoc, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ObsidianDoc{}, err
	}

	content := string(data)
	doc := ObsidianDoc{
		Path:     strings.TrimPrefix(filePath, vaultRoot),
		Content:  content,
		Modified: time.Now(),
	}

	// 解析文件名作为标题
	base := filepath.Base(filePath)
	doc.Title = strings.TrimSuffix(base, ".md")

	// 解析 frontmatter
	doc.FrontMatter, content = parseFrontMatter(content)
	doc.Content = content

	// 解析 [[双向链接]]
	doc.Links = extractWikiLinks(content)

	// 解析 #tags
	doc.Tags = extractTags(content)

	return doc, nil
}

// parseFrontMatter 解析 YAML frontmatter
func parseFrontMatter(content string) (map[string]interface{}, string) {
	result := make(map[string]interface{})
	if !strings.HasPrefix(content, "---\n") {
		return result, content
	}

	end := strings.Index(content[4:], "\n---")
	if end == -1 {
		return result, content
	}

	yamlBlock := content[4 : 4+end]
	remaining := content[4+end+4:]

	// 极简 YAML 解析（key: value 格式）
	for _, line := range strings.Split(yamlBlock, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			result[key] = val
		}
	}

	return result, remaining
}

// extractWikiLinks 提取 [[link]] 格式的双向链接
func extractWikiLinks(content string) []string {
	var links []string
	seen := make(map[string]bool)

	for {
		start := strings.Index(content, "[[")
		if start == -1 {
			break
		}
		end := strings.Index(content[start+2:], "]]")
		if end == -1 {
			break
		}
		link := content[start+2 : start+2+end]
		// 处理 [[alias|link]] 格式
		if idx := strings.Index(link, "|"); idx != -1 {
			link = link[idx+1:]
		}
		link = strings.TrimSpace(link)
		if link != "" && !seen[link] {
			seen[link] = true
			links = append(links, link)
		}
		content = content[start+2+end+2:]
	}
	return links
}

// extractTags 提取 #tag 格式的标签
func extractTags(content string) []string {
	var tags []string
	seen := make(map[string]bool)
	words := strings.Fields(content)
	for _, w := range words {
		if strings.HasPrefix(w, "#") && len(w) > 1 {
			tag := strings.TrimPrefix(w, "#")
			// 去掉标点
			tag = strings.TrimFunc(tag, func(r rune) bool {
				return r == ',' || r == '.' || r == '!' || r == '?' || r == ';' || r == ':'
			})
			if tag != "" && !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	return tags
}

// ========== HTTP 处理器 ==========

func HandleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}

	docs, err := ParseVault(req.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"vault":   req.Path,
		"count":   len(docs),
		"docs":    docs,
	})
}

func HandleParseNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		FilePath string `json:"filePath"`
		VaultRoot string `json:"vaultRoot"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	doc, err := ParseNote(req.FilePath, req.VaultRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

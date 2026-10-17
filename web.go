package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ===================== 搜索 =====================
func webSearch(query string, count int) (map[string]interface{}, error) {
	cfgMu.RLock()
	eng := cfg.Search.Engine
	key := cfg.Search.APIKey
	cfgMu.RUnlock()
	if eng == "serper" && key != "" {
		return serperSearch(query, count)
	}
	return bingRSSSearch(query, count)
}

func bingRSSSearch(query string, count int) (map[string]interface{}, error) {
	u := "https://www.bing.com/search?q=" + url.QueryEscape(query) + "&format=rss&count=" + strconv.Itoa(count)
	resp, err := httpClientShort.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFetchBytes {
		return nil, fmt.Errorf("搜索响应过大")
	}
	var rss struct {
		Channel struct {
			Items []struct {
				Title       string `xml:"title"`
				Link        string `xml:"link"`
				Description string `xml:"description"`
			} `xml:"item"`
		} `xml:"channel"`
	}
	if err := xml.Unmarshal(data, &rss); err != nil {
		return map[string]interface{}{"query": query, "results": []interface{}{}, "engine": "bing-rss", "note": "解析失败"}, nil
	}
	var results []map[string]interface{}
	for _, it := range rss.Channel.Items {
		results = append(results, map[string]interface{}{
			"title":   it.Title,
			"url":     it.Link,
			"snippet": stripHTML(it.Description),
		})
		if len(results) >= count {
			break
		}
	}
	return map[string]interface{}{"query": query, "results": results, "engine": "bing-rss", "count": len(results)}, nil
}

func serperSearch(query string, count int) (map[string]interface{}, error) {
	body := map[string]interface{}{"q": query, "num": count}
	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://google.serper.dev/search", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", cfg.Search.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClientShort.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

// ===================== URL 抓取 =====================
var htmlTagRE = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]+>`)
var whitespaceRE = regexp.MustCompile(`[ \t\r\n]+`)

func stripHTML(s string) string {
	s = htmlTagRE.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.TrimSpace(whitespaceRE.ReplaceAllString(s, " "))
}

func fetchURLText(u string, maxLen int) (map[string]interface{}, error) {
	if !isHTTPURL(u) {
		return nil, fmt.Errorf("仅支持 http/https 链接")
	}
	cur := u
	var resp *http.Response
	for hop := 0; ; hop++ {
		req, err := http.NewRequest("GET", cur, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TarsSecureGuard/9.0")
		// v4.6.3：fetchClient（SSRF 严格模式，禁自动重定向）——目标 URL 模型可控
		resp, err = fetchClient.Do(req)
		if err != nil {
			return nil, err
		}
		// 3xx：逐跳校验重定向目标后手工跟随（最多 3 跳），杜绝 3xx 跳内网绕过
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && hop < 3 {
			next, ok := ssrfRedirectURL(resp)
			resp.Body.Close()
			if !ok {
				return nil, fmt.Errorf("重定向目标不合法或被 SSRF 防护拒绝")
			}
			cur = next
			continue
		}
		break
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFetchBytes {
		return nil, fmt.Errorf("内容超过 %d 字节，已拒绝读取", maxFetchBytes)
	}
	ct := resp.Header.Get("Content-Type")
	text := string(data)
	if strings.Contains(ct, "html") || strings.Contains(ct, "xml") {
		text = stripHTML(string(data))
	}
	if maxLen > 0 && len(text) > maxLen {
		text = text[:maxLen] + "...[截断]"
	}
	return map[string]interface{}{
		"url":          cur,
		"status":       resp.StatusCode,
		"content_type": ct,
		"length":       len(text),
		"content":      text,
	}, nil
}

// ===================== OpenAPI 工具 =====================
type openAPIDoc struct {
	OpenAPI string `json:"openapi"`
	Swagger string `json:"swagger"`
	Info    struct {
		Title       string `json:"title"`
		Version     string `json:"version"`
		Description string `json:"description"`
	} `json:"info"`
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Paths map[string]interface{} `json:"paths"`
}

func loadOpenAPIDoc(id string) (*openAPIDoc, error) {
	var data []byte
	var err error
	if isHTTPURL(id) {
		// v4.6.3：文档 URL 由 API 请求体传入——走 fetchClient 严格 SSRF 防线，
		// 3xx 逐跳校验后手工跟随（最多 3 跳）
		cur := id
		var resp *http.Response
		for hop := 0; ; hop++ {
			var e error
			resp, e = fetchClient.Get(cur)
			if e != nil {
				return nil, e
			}
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && hop < 3 {
				next, ok := ssrfRedirectURL(resp)
				resp.Body.Close()
				if !ok {
					return nil, fmt.Errorf("OpenAPI 重定向目标不合法或被 SSRF 防护拒绝")
				}
				cur = next
				continue
			}
			break
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(io.LimitReader(resp.Body, maxOpenAPIBytes+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxOpenAPIBytes {
			return nil, fmt.Errorf("OpenAPI 文档过大（超过 %d 字节）", maxOpenAPIBytes)
		}
	} else {
		if !isPathAllowed(id, false) {
			return nil, fmt.Errorf("本地文件不在授权读取范围内")
		}
		data, err = os.ReadFile(id)
		if err != nil {
			return nil, err
		}
		if len(data) > maxOpenAPIBytes {
			return nil, fmt.Errorf("OpenAPI 文档过大（超过 %d 字节）", maxOpenAPIBytes)
		}
	}
	var doc openAPIDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("OpenAPI 解析失败: %v", err)
	}
	return &doc, nil
}

func openAPIOverview(id string) (interface{}, error) {
	doc, err := loadOpenAPIDoc(id)
	if err != nil {
		return nil, err
	}
	var paths []string
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return map[string]interface{}{
		"id":          id,
		"title":       doc.Info.Title,
		"version":     doc.Info.Version,
		"description": doc.Info.Description,
		"servers":     doc.Servers,
		"pathCount":   len(paths),
		"paths":       paths,
	}, nil
}

func openAPIOperation(id, op string) (interface{}, error) {
	doc, err := loadOpenAPIDoc(id)
	if err != nil {
		return nil, err
	}
	for p, v := range doc.Paths {
		pathItem, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		for method, opv := range pathItem {
			opMap, ok := opv.(map[string]interface{})
			if !ok {
				continue
			}
			opID, _ := opMap["operationId"].(string)
			route := strings.ToLower(strings.TrimSpace(method) + " " + p)
			if opID == op || route == strings.ToLower(strings.TrimSpace(op)) || p == op {
				return map[string]interface{}{
					"id":          id,
					"path":        p,
					"method":      strings.ToUpper(method),
					"operationId": opID,
					"summary":     opMap["summary"],
					"description": opMap["description"],
					"parameters":  opMap["parameters"],
					"requestBody": opMap["requestBody"],
					"responses":   opMap["responses"],
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("未找到操作: %s", op)
}

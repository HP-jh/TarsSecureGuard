package main

// ===================== v3.9.0 网关知识库（Knowledge Base）=====================
//
// 设计目标：为网关提供可配置、可加密、可审计的知识资产中心。
//
// 加密分级：
//   L0 公开 — 通用规范/模板，明文存储，默认开放读
//   L1 内部 — 默认配置/一般策略，系统密钥加密
//   L2 敏感 — WAF规则/PII规则/密钥相关，用户可选单/双密钥
//   L3 机密 — 签名/根密钥，强制双密钥+用户密钥
//
// 用户自管密钥（SSOT）：用户提供加密密钥，系统仅存密文+元数据，
// 不持有用户密钥。支持“用户加密”档位切换。
//
// 云端备份：用户级解密视图定期备份到飞书云空间（lark-cli drive），
// 备份范围与频率按安全等级定夺。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"net/http"
	"sync"
	"time"
)

// KnowledgeLevel 知识条目敏感度等级
type KnowledgeLevel int

const (
	LevelPublic     KnowledgeLevel = 0 // L0 公开
	LevelInternal   KnowledgeLevel = 1 // L1 内部
	LevelSensitive  KnowledgeLevel = 2 // L2 敏感
	LevelConfidential KnowledgeLevel = 3 // L3 机密
)

func (l KnowledgeLevel) String() string {
	switch l {
	case LevelPublic:     return "public"
	case LevelInternal:   return "internal"
	case LevelSensitive:  return "sensitive"
	case LevelConfidential: return "confidential"
	default:              return "unknown"
	}
}

// KnowledgeEntry 单条知识库条目
type KnowledgeEntry struct {
	ID          string                 `json:"id"`
	Category    string                 `json:"category"`     // 分类：protocol/waf/pii/semantic/policy/persona/extender
	Name        string                 `json:"name"`
	Level       KnowledgeLevel         `json:"level"`
	Content     string                 `json:"content"`      // 明文内容（内存中），存盘时按 Level 加密
	Tags        []string               `json:"tags"`
	Meta        map[string]interface{} `json:"meta"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Version     int                    `json:"version"`      // 条目版本，用于备份去重
	Checksum    string                 `json:"checksum"`     // SHA-256(content) 用于完整性校验
	EncryptedBy string                 `json:"encrypted_by"` // "system" / "user" / "dual" / ""
}

// KnowledgeBase 知识库管理器
type KnowledgeBase struct {
	mu       sync.RWMutex
	entries  map[string]*KnowledgeEntry
	dir      string

	systemKey []byte // L1 系统密钥（从 cfg 派生或环境变量）
	userKey   []byte // L2/L3 用户自管密钥（运行时注入，不持久化）
	backupCfg BackupConfig
}

// BackupConfig 云端备份配置
type BackupConfig struct {
	Enabled      bool          `json:"enabled"`
	Interval     time.Duration `json:"interval"`      // 备份间隔
	MinLevel     KnowledgeLevel `json:"min_level"`    // 最低备份等级（>=该等级才备份）
	LastBackupAt time.Time     `json:"last_backup_at"`
	BackupPath   string        `json:"backup_path"`   // 本地暂存路径
}

// 分类常量
const (
	CatProtocol  = "protocol"   // HTTP/JSON/正则/URL 规范
	CatWAF       = "waf"        // WAF 规则模板
	CatPII       = "pii"        // PII 检测规则
	CatSemantic  = "semantic"   // 语义护栏分类
	CatPolicy    = "policy"     // 策略模板
	CatPersona   = "persona"    // 职业上下文
	CatExtender  = "extender"   // 扩展器接入片段
)

var kb *KnowledgeBase

// ===================== 初始化 =====================

func initKnowledgeBase(dir string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("mkdir kb: %w", err)
	}

	sysKey := deriveSystemKey()
	backupDir := filepath.Join(dir, "backup")
	_ = os.MkdirAll(backupDir, 0750)

	kb = &KnowledgeBase{
		entries:   make(map[string]*KnowledgeEntry),
		dir:       dir,
		systemKey: sysKey,
		backupCfg: BackupConfig{
			Enabled:    true,
			Interval:   24 * time.Hour,
			MinLevel:   LevelInternal,
			BackupPath: backupDir,
		},
	}

	// 加载已有条目
	if err := kb.loadAll(); err != nil {
		return fmt.Errorf("kb load: %w", err)
	}

	// 若为空，注入内置知识库种子
	if len(kb.entries) == 0 {
		kb.seedBuiltin()
	}

	// 启动备份协程
	go kb.backupLoop()

	return nil
}

// deriveSystemKey 从 cfg.Security.APIKey 派生系统密钥（L1 加密用）
func deriveSystemKey() []byte {
	base := cfg.Security.APIKey
	if base == "" {
		base = apiKeyDefault
	}
	h := sha256.Sum256([]byte("tsg-kb-system:" + base))
	return h[:]
}

// SetUserKey 注入用户自管密钥（SSOT），支持热切换
type userKeyHolder struct {
	mu  sync.RWMutex
	key []byte
}

var ukh userKeyHolder

func SetUserKey(passphrase string) {
	ukh.mu.Lock()
	defer ukh.mu.Unlock()
	if passphrase == "" {
		ukh.key = nil
		return
	}
	h := sha256.Sum256([]byte("tsg-kb-user:" + passphrase))
	ukh.key = h[:]
	if kb != nil {
		kb.userKey = ukh.key
	}
}

// ===================== CRUD =====================

func (k *KnowledgeBase) Put(entry *KnowledgeEntry) error {
	if entry.ID == "" {
		entry.ID = genKVID()
	}
	entry.UpdatedAt = time.Now()
	entry.Checksum = hashContent(entry.Content)
	entry.Version++

	// 根据 Level 确定加密方式
	switch entry.Level {
	case LevelPublic:
		entry.EncryptedBy = ""
	case LevelInternal:
		entry.EncryptedBy = "system"
	case LevelSensitive:
		if ukh.key != nil {
			entry.EncryptedBy = "user"
		} else {
			entry.EncryptedBy = "system"
		}
	case LevelConfidential:
		entry.EncryptedBy = "dual"
	}

	if err := k.saveEntry(entry); err != nil {
		return err
	}

	k.mu.Lock()
	k.entries[entry.ID] = entry
	k.mu.Unlock()

	auditLog("KB_PUT", "-", fmt.Sprintf("%s/%s level=%s", entry.Category, entry.Name, entry.Level))
	return nil
}

func (k *KnowledgeBase) Get(id string) (*KnowledgeEntry, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	entry, ok := k.entries[id]
	if !ok {
		return nil, fmt.Errorf("kb entry not found: %s", id)
	}
	// 返回副本防篡改
	cp := *entry
	return &cp, nil
}

func (k *KnowledgeBase) List(category string, minLevel KnowledgeLevel) []*KnowledgeEntry {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var out []*KnowledgeEntry
	for _, e := range k.entries {
		if category != "" && e.Category != category {
			continue
		}
		if e.Level < minLevel {
			continue
		}
		cp := *e
		out = append(out, &cp)
	}
	return out
}

func (k *KnowledgeBase) Delete(id string) error {
	k.mu.Lock()
	delete(k.entries, id)
	k.mu.Unlock()

	path := k.entryPath(id)
	_ = os.Remove(path)
	auditLog("KB_DEL", "-", id)
	return nil
}

// ===================== 存储与加密 =====================

// diskEntry 存盘格式
type diskEntry struct {
	ID          string                 `json:"id"`
	Category    string                 `json:"category"`
	Name        string                 `json:"name"`
	Level       KnowledgeLevel         `json:"level"`
	CipherText  string                 `json:"cipher_text"`   // base64 密文（L0 为明文）
	Tags        []string               `json:"tags"`
	Meta        map[string]interface{} `json:"meta"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Version     int                    `json:"version"`
	Checksum    string                 `json:"checksum"`
	EncryptedBy string                 `json:"encrypted_by"`
}

func (k *KnowledgeBase) saveEntry(entry *KnowledgeEntry) error {
	de := diskEntry{
		ID: entry.ID, Category: entry.Category, Name: entry.Name,
		Level: entry.Level, Tags: entry.Tags, Meta: entry.Meta,
		CreatedAt: entry.CreatedAt, UpdatedAt: entry.UpdatedAt,
		Version: entry.Version, Checksum: entry.Checksum,
		EncryptedBy: entry.EncryptedBy,
	}

	var plaintext []byte
	switch entry.Level {
	case LevelPublic:
		de.CipherText = entry.Content // 明文直接存
	default:
		plaintext = []byte(entry.Content)
		key := k.resolveKey(entry.Level, entry.EncryptedBy)
		if key == nil {
			return fmt.Errorf("no key available for level %s", entry.Level)
		}
		ct, err := encryptAESGCM(plaintext, key)
		if err != nil {
			return err
		}
		de.CipherText = base64.StdEncoding.EncodeToString(ct)
	}

	data, err := json.MarshalIndent(de, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(k.dir, entry.Category, entry.ID+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

func (k *KnowledgeBase) loadAll() error {
	entries, err := os.ReadDir(k.dir)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(k.dir, ent.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var de diskEntry
		if err := json.Unmarshal(data, &de); err != nil {
			continue
		}
		entry := &KnowledgeEntry{
			ID: de.ID, Category: de.Category, Name: de.Name,
			Level: de.Level, Tags: de.Tags, Meta: de.Meta,
			CreatedAt: de.CreatedAt, UpdatedAt: de.UpdatedAt,
			Version: de.Version, Checksum: de.Checksum,
			EncryptedBy: de.EncryptedBy,
		}
		// 解密
		if de.Level == LevelPublic {
			entry.Content = de.CipherText
		} else {
			ct, err := base64.StdEncoding.DecodeString(de.CipherText)
			if err != nil {
				entry.Content = "[decrypt-error]"
				continue
			}
			key := k.resolveKey(de.Level, de.EncryptedBy)
			if key == nil {
				entry.Content = "[key-unavailable]"
			} else {
				pt, err := decryptAESGCM(ct, key)
				if err != nil {
					entry.Content = "[decrypt-failed]"
				} else {
					entry.Content = string(pt)
				}
			}
		}
		// 校验完整性
		if entry.Checksum != "" && entry.Checksum != hashContent(entry.Content) {
			entry.Content = "[integrity-failed]"
		}
		k.entries[entry.ID] = entry
	}
	return nil
}

func (k *KnowledgeBase) resolveKey(level KnowledgeLevel, encryptedBy string) []byte {
	switch level {
	case LevelInternal:
		return k.systemKey
	case LevelSensitive:
		if encryptedBy == "user" && ukh.key != nil {
			return ukh.key
		}
		return k.systemKey
	case LevelConfidential:
		// dual = systemKey XOR userKey
		if k.systemKey == nil {
			return nil
		}
		if ukh.key == nil {
			return nil
		}
		dual := make([]byte, 32)
		for i := range dual {
			dual[i] = k.systemKey[i] ^ ukh.key[i]
		}
		return dual
	}
	return nil
}

func (k *KnowledgeBase) entryPath(id string) string {
	// 按分类分目录存储
	var cat string
	k.mu.RLock()
	if e, ok := k.entries[id]; ok {
		cat = e.Category
	}
	k.mu.RUnlock()
	if cat == "" {
		cat = "misc"
	}
	return filepath.Join(k.dir, cat, id+".json")
}

// ===================== 加密工具 =====================

func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

func hashContent(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

func genKVID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("kb_%x_%d", b, time.Now().Unix())
}

// ===================== 内置种子 =====================

func (k *KnowledgeBase) seedBuiltin() {
	seeds := []*KnowledgeEntry{
		// L0 公开 — 协议规范
		{Category: CatProtocol, Name: "HTTP/1.1 规范摘要", Level: LevelPublic, Content: "HTTP/1.1 RFC 7230-7235 核心语义：请求行、头部、正文、状态码、持久连接、分块传输。", Tags: []string{"http", "rfc"}},
		{Category: CatProtocol, Name: "JSON 安全解析规范", Level: LevelPublic, Content: "JSON 解析须设 MaxDepth、限制字符串长度、拒绝未知字段（按场景）、使用流式解析器处理大 JSON。", Tags: []string{"json", "parser"}},
		{Category: CatProtocol, Name: "URL 编码与解码规范", Level: LevelPublic, Content: "RFC 3986 百分号编码；解码前须校验 charset；拒绝 %00 空字节；规范化路径（移除 ../）。", Tags: []string{"url", "encoding"}},
		{Category: CatProtocol, Name: "正则表达式安全指南", Level: LevelPublic, Content: "避免 ReDoS：禁用回溯量词（.{0,1000} 替代 .*）；预编译常用正则；使用 timeout 限制匹配时间。", Tags: []string{"regex", "redos"}},

		// L0 公开 — WAF 规则模板
		{Category: CatWAF, Name: "SQL 注入基础规则集", Level: LevelPublic, Content: "模板：检测 UNION SELECT、OR 1=1、sleep()、benchmark()、-- 注释、; 堆叠查询。建议配合参数化查询。", Tags: []string{"sqli", "template"}},
		{Category: CatWAF, Name: "XSS 基础规则集", Level: LevelPublic, Content: "模板：检测 <script、javascript:、onerror=、eval(、document.cookie、window.location。建议配合 CSP。", Tags: []string{"xss", "template"}},
		{Category: CatWAF, Name: "路径遍历规则模板", Level: LevelPublic, Content: "模板：检测 ../、..\\、%2e%2e%2f、%c0%af、空字节截断。建议配合 chroot/沙箱。", Tags: []string{"path-traversal", "template"}},

		// L1 内部 — PII 规则
		{Category: CatPII, Name: "中国大陆身份证检测", Level: LevelInternal, Content: "正则：(^|[^0-9])([1-9]\\d{5}(18|19|20)\\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\\d{3}[0-9Xx])([^0-9]|$)；校验：加权求和模11。", Tags: []string{"pii", "idcard", "cn"}},
		{Category: CatPII, Name: "手机号检测（中/美/欧）", Level: LevelInternal, Content: "CN: 1[3-9]\\d{9}; US: \\b[2-9]\\d{2}-?\\d{3}-?\\d{4}\\b; EU: 国际前缀 + 国家格式。", Tags: []string{"pii", "phone"}},
		{Category: CatPII, Name: "邮箱地址检测", Level: LevelInternal, Content: "正则：\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b；注意假阳性（如文件名）。", Tags: []string{"pii", "email"}},
		{Category: CatPII, Name: "银行卡号检测（Luhn）", Level: LevelInternal, Content: "正则提取 13-19 位数字；Luhn 校验；屏蔽中间 8-10 位。", Tags: []string{"pii", "bank", "luhn"}},

		// L1 内部 — 语义护栏分类库
		{Category: CatSemantic, Name: "语义护栏分类 v1", Level: LevelInternal, Content: "分类：HATE（仇恨）、HARASS（骚扰）、SELF_HARM（自伤）、SEXUAL（性内容）、VIOLENCE（暴力）、ILLEGAL（违法）、PII（隐私）、JAILBREAK（越狱）。每类含 5-10 条典型示例与触发关键词。", Tags: []string{"semantic", "guard", "classification"}},
		{Category: CatSemantic, Name: "越狱攻击模式库", Level: LevelInternal, Content: "模式：DAN、Developer Mode、Ignore Previous、Hypothetical、Roleplay、Token Smuggling、Payload Splitting。每模式含检测正则与置信度评分。", Tags: []string{"semantic", "jailbreak", "pattern"}},

		// L1 内部 — 策略模板
		{Category: CatPolicy, Name: "默认速率限制策略", Level: LevelInternal, Content: "chat: 60/min; admin: 10/min; model: 6/min; burst: 1.5x; cooldown: 30s。IP 级 + user 级双维度。", Tags: []string{"policy", "ratelimit"}},
		{Category: CatPolicy, Name: "默认 WAF 响应策略", Level: LevelInternal, Content: "命中规则：记录日志+审计+IP信誉扣分；连续命中3次：临时封禁300s；白名单优先于黑名单。", Tags: []string{"policy", "waf"}},
		{Category: CatPolicy, Name: "默认审计保留策略", Level: LevelInternal, Content: "保留期：30天；滚动删除；哈希链每100条commit一次；导出格式 JSONL；敏感字段 mask。", Tags: []string{"policy", "audit"}},

		// L1 内部 — 职业上下文
		{Category: CatPersona, Name: "学生职业上下文", Level: LevelInternal, Content: "偏好：学术规范引用、逻辑清晰、分步推导；敏感：拒绝代写论文、拒绝考试作弊；推荐模型：性价比优先（Doubao/DeepSeek）。", Tags: []string{"persona", "student"}},
		{Category: CatPersona, Name: "开发者职业上下文", Level: LevelInternal, Content: "偏好：代码可运行、注释完整、最佳实践、安全审计；敏感：拒绝生成恶意代码、拒绝漏洞利用；推荐模型：代码能力优先（Claude/GPT-4）。", Tags: []string{"persona", "developer"}},
		{Category: CatPersona, Name: "文字创作者职业上下文", Level: LevelInternal, Content: "偏好：文风模仿、修辞丰富、多版本输出；敏感：拒绝抄袭、拒绝洗稿；推荐模型：创意优先（GPT-4/Claude）。", Tags: []string{"persona", "writer"}},
		{Category: CatPersona, Name: "研究者职业上下文", Level: LevelInternal, Content: "偏好：文献引用、数据严谨、方法论完整、批判性分析；敏感：拒绝捏造数据、拒绝伪造引用；推荐模型：推理优先（o1/DeepSeek-R1）。", Tags: []string{"persona", "researcher"}},

		// L1 内部 — 扩展器片段
		{Category: CatExtender, Name: "OpenAI 兼容接入片段", Level: LevelInternal, Content: "目标探测：GET /v1/models -> 200 + models列表；POST /v1/chat/completions -> 支持 stream/json；header: Authorization: Bearer {key}。", Tags: []string{"extender", "openai", "snippet"}},
		{Category: CatExtender, Name: "Ollama 兼容接入片段", Level: LevelInternal, Content: "目标探测：GET /api/tags -> 200 + 模型列表；POST /api/generate -> 支持 stream；POST /api/chat -> 对话格式。", Tags: []string{"extender", "ollama", "snippet"}},
		{Category: CatExtender, Name: "LMStudio 兼容接入片段", Level: LevelInternal, Content: "目标探测：GET /v1/models -> OpenAI 兼容；本地默认端口 1234；支持模型动态加载。", Tags: []string{"extender", "lmstudio", "snippet"}},
	}

	for _, e := range seeds {
		e.ID = genKVID()
		e.CreatedAt = time.Now()
		e.UpdatedAt = e.CreatedAt
		e.Version = 1
		e.Checksum = hashContent(e.Content)
		_ = k.Put(e)
	}
}

// ===================== 云端备份 =====================

func (k *KnowledgeBase) backupLoop() {
	ticker := time.NewTicker(k.backupCfg.Interval)
	defer ticker.Stop()
	for {
		<-ticker.C
		if !k.backupCfg.Enabled {
			continue
		}
		_ = k.performBackup()
	}
}

// performBackup 执行一次本地备份（云端上传由外部触发）
// 返回备份文件路径列表
func (k *KnowledgeBase) performBackup() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()

	var paths []string
	timestamp := time.Now().Format("20060102-150405")

	// 按等级分组导出
	for level := k.backupCfg.MinLevel; level <= LevelConfidential; level++ {
		var entries []diskEntry
		for _, e := range k.entries {
			if e.Level < level {
				continue
			}
			// 导出解密视图（用户级可读）
			de := diskEntry{
				ID: e.ID, Category: e.Category, Name: e.Name,
				Level: e.Level, Tags: e.Tags, Meta: e.Meta,
				CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt,
				Version: e.Version, Checksum: e.Checksum,
				EncryptedBy: "", // 备份为解密视图
				CipherText:  e.Content, // 明文
			}
			entries = append(entries, de)
		}
		if len(entries) == 0 {
			continue
		}
		data, _ := json.MarshalIndent(entries, "", "  ")
		fname := fmt.Sprintf("kb-backup-%s-level%d.json", timestamp, level)
		path := filepath.Join(k.backupCfg.BackupPath, fname)
		if err := os.WriteFile(path, data, 0600); err == nil {
			paths = append(paths, path)
		}
	}

	k.backupCfg.LastBackupAt = time.Now()
	if len(paths) > 0 {
		auditLog("KB_BACKUP", "-", fmt.Sprintf("levels>=%s files=%d", k.backupCfg.MinLevel, len(paths)))
	}
	return paths
}

// ExportBackupForCloud 导出指定等级的解密备份并返回内容（供 lark-cli drive 上传）
func (k *KnowledgeBase) ExportBackupForCloud(minLevel KnowledgeLevel) (string, []byte, error) {
	paths := k.performBackup()
	if len(paths) == 0 {
		return "", nil, fmt.Errorf("no backup generated")
	}
	// 取最高等级备份（通常包含所有内容）
	path := paths[len(paths)-1]
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	return filepath.Base(path), data, nil
}

// ===================== HTTP API =====================

func handleKBList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	cat := q.Get("category")
	minLevel := LevelPublic
	if l := q.Get("min_level"); l != "" {
		fmt.Sscanf(l, "%d", &minLevel)
	}
	entries := kb.List(cat, minLevel)
	writeJSON(w, map[string]interface{}{"entries": entries, "count": len(entries)})
}

func handleKBGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	entry, err := kb.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, entry)
}

func handleKBSetKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	SetUserKey(req.Passphrase)
	writeJSON(w, map[string]string{"status": "user_key_set"})
}

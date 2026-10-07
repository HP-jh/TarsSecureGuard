// Package crown 是皇冠架构的冠环（Crown Bus）：
// 统一信封 Envelope、N1-N12 固定序流水线、模块注册表与三原语（invoke/emit/transform）。
//
// 设计契约（v4.0 重写，保留清单对应项见各字段注释）：
//   - 全链路唯一数据载体是 Envelope，节点只读写 Envelope，互不直调；
//   - 节点顺序由本包常量唯一确定，任何模块不得增删或重排节点；
//   - 模块间只经显式接口交互，注册表负责依赖闭合与启停序。
package crown

import "sync"

// NodeID 标识流水线节点。
type NodeID string

// N1-N12：十二节点固定序（皇冠架构调研定稿，职业仅可覆盖 N4/N5/N6/N10 的行为参数）。
const (
	N1Ingress        NodeID = "N1_INGRESS"         // 接入（HTTP/stdio 归一，生成 trace）
	N2Identity       NodeID = "N2_IDENTITY"        // 身份与配额（RBAC 矩阵/三层配额）
	N3Precheck       NodeID = "N3_PRECHECK"        // 安全预检（WAF 六规则族）
	N4Intent         NodeID = "N4_INTENT"          // 意图与职业路由（含蜜罐路由分支）
	N5Context        NodeID = "N5_CONTEXT"         // 上下文装配（共享记忆/信息/上下文包）
	N6TransformReq   NodeID = "N6_TRANSFORM_REQ"   // 请求侧转化（persona+chainopt 真接线）
	N7Semguard       NodeID = "N7_SEMGUARD"        // 语义护栏（分级分流+fail-close）
	N8Gatekeeper     NodeID = "N8_GATEKEEPER"      // 守门人确认（动作级防线）
	N9Model          NodeID = "N9_MODEL"           // 模型调用（注册表/适配/熔断/缓存）
	N10TransformResp NodeID = "N10_TRANSFORM_RESP" // 响应侧转化（职业文风模板）
	N11RespFilter    NodeID = "N11_RESPFILTER"     // 响应过滤（PII 脱敏）
	N12Audit         NodeID = "N12_AUDIT"          // 审计与计量（hash 链 + emit）
)

// canonicalOrder 是 N1→N12 的唯一合法顺序。
// 保留契约：重写可以换任何实现，但这条顺序是行为契约的一部分。
var canonicalOrder = []NodeID{
	N1Ingress, N2Identity, N3Precheck, N4Intent, N5Context, N6TransformReq,
	N7Semguard, N8Gatekeeper, N9Model, N10TransformResp, N11RespFilter, N12Audit,
}

// CanonicalOrder 返回固定序的副本（供装配校验、测试与诊断使用）。
func CanonicalOrder() []NodeID {
	out := make([]NodeID, len(canonicalOrder))
	copy(out, canonicalOrder)
	return out
}

// TokenBudget 记录本次请求的 token 预算分配（职业 Profile 在 N5 填写）。
// 预算框架来自皇冠架构调研：persona 5-8% / 系统安全 5% / 记忆检索 20-30% /
// 历史 15-25% / 余量给用户问题；稳定前缀优先以命中缓存。
type TokenBudget struct {
	Persona  int // persona 前缀预算（字符数）
	System   int // 系统/安全指令
	Memory   int // 共享记忆/检索注入
	History  int // 对话历史
	Question int // 用户问题余量
}

// ChainHints 是职业调用链优化参数（chainopt）。
// 由职业 Profile 声明、在 N6 真正写进出站请求体——
// 旧版 v3.8.0 此处断链（参数未落请求体），v4.0 以端到端测试锁定。
type ChainHints struct {
	Temperature   *float64 // nil = 不覆盖
	MaxTokens     *int     // nil = 不覆盖
	TimeoutGainMS int      // 超时增益（毫秒）
	RetryPolicy   string   // conservative | moderate | aggressive
	Enabled       bool     // 该请求是否启用职业链路优化
}

// Envelope 是全链路唯一数据载体。
// 并发约定：Body/Resp 等字段由流水线串行推进，仅单协程写；
// attrs 经 SetAttr/Attr 带锁访问，供旁路观测安全读取。
type Envelope struct {
	mu sync.RWMutex

	TraceID string // 全链路追踪号（N1 生成，响应头回显，出站转发）
	Tenant  string // 租户标识
	User    string // 用户标识
	Role    string // RBAC 角色
	Persona string // 当前职业 Profile ID

	Stage  NodeID // 当前所处节点（由 Pipeline 推进，观测依赖）
	Body   []byte // 入站请求体（JSON）
	Resp   []byte // 出站响应体
	Status int    // 处理结果状态码（0 = 继续推进）

	Budget TokenBudget // N5 填写
	Hints  ChainHints  // N4/N6 填写

	AuditRefs []string // 已产生的审计事件引用（N12 emit 汇总）

	attrs    map[string]string // 节点间附加数据
	abortErr error             // 任一节点可置入终止错误
}

// NewEnvelope 构造空信封。
func NewEnvelope() *Envelope {
	return &Envelope{attrs: map[string]string{}}
}

// SetAttr 写入节点间附加数据（并发安全）。
func (e *Envelope) SetAttr(k, v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.attrs == nil {
		e.attrs = map[string]string{}
	}
	e.attrs[k] = v
}

// Attr 读取节点间附加数据（并发安全）。
func (e *Envelope) Attr(k string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	v, ok := e.attrs[k]
	return v, ok
}

// Abort 由节点调用以终止流水线（如安全链拒绝）。err 必须非空，
// 否则视为无效调用——终止必须携带原因，原因进审计。
func (e *Envelope) Abort(err error) {
	if err == nil {
		return
	}
	e.abortErr = err
}

// Aborted 返回终止错误（nil 表示未终止）。
func (e *Envelope) Aborted() error { return e.abortErr }

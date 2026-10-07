// Package nodes 提供 N1-N12 各节点的实现。
// B1 批次为骨架占位：每个节点只记录流水线到访，供装配与链路测试使用；
// 自 B2 起逐节点替换为真实实现（替换时保持 NewAll 的顺序契约不变）。
package nodes

import "tarssecureguard/crown"

// stubNode 是 B1 占位节点：记录到访（attrs: visited:<NodeID> = Name），不做业务。
type stubNode struct {
	id   crown.NodeID
	name string
}

func (s *stubNode) ID() crown.NodeID { return s.id }
func (s *stubNode) Name() string     { return s.name }
func (s *stubNode) Handle(env *crown.Envelope) error {
	env.SetAttr("visited:"+string(s.id), s.name)
	return nil
}

// VisitedKey 返回到访标记的 attr 键（测试与诊断共用）。
func VisitedKey(id crown.NodeID) string { return "visited:" + string(id) }

// defs 是 12 节点的名称定义，顺序即规范顺序。
var defs = []struct {
	id   crown.NodeID
	name string
}{
	{crown.N1Ingress, "接入"},
	{crown.N2Identity, "身份与配额"},
	{crown.N3Precheck, "安全预检"},
	{crown.N4Intent, "意图与职业路由"},
	{crown.N5Context, "上下文装配"},
	{crown.N6TransformReq, "请求侧转化"},
	{crown.N7Semguard, "语义护栏"},
	{crown.N8Gatekeeper, "守门人确认"},
	{crown.N9Model, "模型调用"},
	{crown.N10TransformResp, "响应侧转化"},
	{crown.N11RespFilter, "响应过滤"},
	{crown.N12Audit, "审计与计量"},
}

// NewAll 返回按规范顺序排列的 12 个节点（B1 为占位实现）。
// 与 crown.NewPipeline 配合：顺序与 crown.CanonicalOrder 逐位一致。
func NewAll() []crown.Node {
	nodes := make([]crown.Node, len(defs))
	for i, d := range defs {
		nodes[i] = &stubNode{id: d.id, name: d.name}
	}
	return nodes
}

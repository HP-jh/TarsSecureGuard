package crown

import "fmt"

// Pipeline 是 N1→N12 的固定骨架（冠石之后的唯一执行路径）。
// 节点集合与顺序在构造时一次锁定，运行期不可增删、不可改序；
// 任何模块只能经由 Node 接口参与流水线，无法绕过节点顺序。
// 对应保留契约：12 节点固定序是行为契约的一部分（皇冠架构调研定稿）。
type Pipeline struct {
	nodes []Node
}

// NewPipeline 校验并装配流水线：必须恰好 12 个节点、无 nil、
// 按位等于 CanonicalOrder。违规返回错误，调用方应在启动期拒绝服务（fail-fast）。
func NewPipeline(nodes []Node) (*Pipeline, error) {
	order := CanonicalOrder()
	if len(nodes) != len(order) {
		return nil, fmt.Errorf("crown: pipeline requires exactly %d nodes, got %d", len(order), len(nodes))
	}
	for i, n := range nodes {
		if n == nil {
			return nil, fmt.Errorf("crown: pipeline node at position %d (%s) is nil", i+1, order[i])
		}
		if n.ID() != order[i] {
			return nil, fmt.Errorf("crown: pipeline order violation at position %d: want %s, got %s", i+1, order[i], n.ID())
		}
	}
	cp := make([]Node, len(nodes))
	copy(cp, nodes)
	return &Pipeline{nodes: cp}, nil
}

// Nodes 返回节点切片（只读用途；调用方不得修改）。
func (p *Pipeline) Nodes() []Node { return p.nodes }

// Run 按规范顺序执行全部节点：
//   - 每个节点执行前把 env.Stage 推进到该节点（观测依赖）；
//   - 节点返回错误，或 env 已被 Abort，立即停止并返回该错误；
//   - 返回 nil 表示全链路放行（业务结果由节点写入 Envelope）。
func (p *Pipeline) Run(env *Envelope) error {
	if env == nil {
		return fmt.Errorf("crown: pipeline run with nil envelope")
	}
	for _, n := range p.nodes {
		if err := env.Aborted(); err != nil {
			return err
		}
		env.mu.Lock()
		env.Stage = n.ID()
		env.mu.Unlock()
		if err := n.Handle(env); err != nil {
			return err
		}
	}
	return nil
}

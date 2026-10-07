package crown

// Node 是流水线上的一个处理节点。
//
// 契约：
//   - 节点只读写 Envelope；不直接调用其它节点；
//   - 节点不绕过 store 域直接落盘；
//   - 节点幂等可测：Handle 不持有跨请求状态（状态放模块里）。
type Node interface {
	ID() NodeID
	Name() string
	Handle(env *Envelope) error
}

package tripwire

// Direction 扫描方向
type Direction int

const (
	DirectionInbound  Direction = iota // 进入模型（用户/系统/工具/文档输入）
	DirectionOutbound                    // 返回调用方（模型输出）
)

// Kind 发现类型
type Kind int

const (
	KindInjection     Kind = iota // 指令注入
	KindExfiltration              // 数据外泄
	KindObfuscation               // 混淆/走私
)

// Severity 严重等级
type Severity int

const (
	SeverityInfo     Severity = iota // 值得关注但不可单独行动
	SeverityLow                      // 弱信号，通常需佐证
	SeverityMedium                   // 值得标记的可靠信号
	SeverityHigh                     // 置信检测，应采取行动
	SeverityCritical                 // 明确的秘密/攻击材料，阻断
)

// Source 扫描文本来源
type Source int

const (
	SourceUser          Source = iota // 用户输入
	SourceSystem                      // 系统提示词
	SourceTool                        // 工具输出（不可信）
	SourceDocument                    // 获取的文档内容（不可信）
	SourceMcpDescription              // MCP工具描述（不可信；投毒面）
	SourceModelOutput                 // 模型自身输出（外泄面）
)

// Finding 单次检测结果
type Finding struct {
	Kind     Kind     `json:"kind"`
	Label    string   `json:"label"`    // 稳定机器标签，如 instruction_override
	Severity Severity `json:"severity"`
	Score    float64  `json:"score"`    // 0.0..=1.0
	Start    int      `json:"start"`    // 原始文本中的字节偏移起始
	End      int      `json:"end"`      // 原始文本中的字节偏移结束
	Source   Source   `json:"source"`
	Detail   string   `json:"detail,omitempty"` // 可选人类/调试详情
}

// ScanResult 扫描结果
type ScanResult struct {
	Findings []Finding `json:"findings"`
	Clean    bool      `json:"clean"` // true 表示无发现
}

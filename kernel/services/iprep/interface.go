// Package iprep: IP reputation service — 本地行为指纹累积评分，security-core 内置不可关闭。
//
// 起分 100；WAF 命中-30、扫描型404突发-10/分钟、限流违规-15；低于40触发动态封禁。

package iprep



// ===================== 接口定义 =====================

// Scorer IP信誉评分器。
type Scorer interface {
	// Score 返回指定 IP 的当前信誉分（无记录=100）。
	Score(ip string) float64
	// Penalty 对指定 IP 扣分（source: waf/scan404/rate-limit/abuse; detail=WAF规则名）。
	Penalty(ip string, delta float64, source string, detail string)
	// Banned 判断指定 IP 是否处于封禁期。
	Banned(ip string) bool
	// Unban 解封指定 IP（admin API 调用）。
	Unban(ip string)
	// Whitelisted 判断 IP 是否在白名单中（不参与评分）。
	Whitelisted(ip string) bool
}

// ===================== Service =====================

// Service 是 IP 信誉子系统入口。
type Service struct {
	scoreFn     func(string) float64
	penaltyFn   func(string, float64, string, string)
	bannedFn    func(string) bool
	unbanFn     func(string)
	whitelistedFn func(string) bool
}

// NewService 构建 IP 信誉 Service。
func NewService(scoreFn func(string) float64, penaltyFn func(string, float64, string, string),
	bannedFn func(string) bool, unbanFn func(string), whitelistedFn func(string) bool) *Service {

	return &Service{
		scoreFn: scoreFn, penaltyFn: penaltyFn, bannedFn: bannedFn,
		unbanFn: unbanFn, whitelistedFn: whitelistedFn,
	}
}

// Scorer returns the Scorer interface.
func (s *Service) Scorer() Scorer { return s }

func (s *Service) Score(ip string) float64                  { return s.scoreFn(ip) }
func (s *Service) Penalty(ip string, delta float64, source string, detail string) { s.penaltyFn(ip, delta, source, detail) }
func (s *Service) Banned(ip string) bool                    { return s.bannedFn(ip) }
func (s *Service) Unban(ip string)                          { s.unbanFn(ip) }
func (s *Service) Whitelisted(ip string) bool               { return s.whitelistedFn(ip) }

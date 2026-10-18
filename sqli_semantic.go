package main

import (
	"strings"
	"unicode"
)

// ===================== SQL 注入语义分析层 (v4.33.0) =====================
// 在正则匹配基础上增加轻量级语法结构分析，通过关键词+语法树联合判断，
// 显著降低误报（如数字比较、合法查询），同时保持对变形注入的检出率。

// tokenKind 表示 lexer 切出的词法单元类型
type tokenKind int

const (
	tokEOF tokenKind = iota
	tokKeyword // SQL 关键字 (union, select, insert 等)
	tokIdent   // 标识符 / 字面量
	tokNumber  // 数字
	tokString  // 字符串字面量
	tokOp      // 运算符 = < > ! + - 等
	tokParen   // ( ) , ;
	tokComment // -- /* */
	tokOther   // 其它字符
)

// token 词法单元
type token struct {
	kind tokenKind
	val  string
}

// sqliLex 对输入字符串做轻量级 SQL tokenizer，专为注入检测设计。
// 不追求完整 SQL 语法，只提取关键字、字符串、数字、运算符等关键 token。
func sqliLex(s string) []token {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]

		// 空白字符跳过
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}

		// 单行注释 --
		if c == '-' && i+1 < len(s) && s[i+1] == '-' {
			j := i + 2
			for j < len(s) && s[j] != '\n' {
				j++
			}
			toks = append(toks, token{tokComment, s[i:j]})
			i = j
			continue
		}

		// 多行注释 /* */
		if c == '/' && i+1 < len(s) && s[i+1] == '*' {
			j := i + 2
			for j+1 < len(s) && !(s[j] == '*' && s[j+1] == '/') {
				j++
			}
			if j+1 < len(s) {
				j += 2
			}
			toks = append(toks, token{tokComment, s[i:j]})
			i = j
			continue
		}

		// 单引号字符串（SQL 注入中常见未闭合引号）
		if c == '\'' {
			j := i + 1
			for j < len(s) {
				if s[j] == '\'' {
					// 处理转义 ''
					if j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			// 未闭合引号：不把整个字符串吞掉，而是把 ' 作为独立 token，继续 lex 后面
			if j == len(s) && (len(s) == 0 || s[len(s)-1] != '\'') {
				toks = append(toks, token{tokOther, "'"})
				i = i + 1
				continue
			}
			toks = append(toks, token{tokString, s[i:j]})
			i = j
			continue
		}

		// 双引号字符串（部分 SQL 方言）
		if c == '"' {
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			if j < len(s) {
				j++
			}
			toks = append(toks, token{tokString, s[i:j]})
			i = j
			continue
		}

		// 数字
		if c >= '0' && c <= '9' {
			j := i
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.') {
				j++
			}
			toks = append(toks, token{tokNumber, s[i:j]})
			i = j
			continue
		}

		// 字母 / 下划线开头 → 关键字或标识符
		if unicode.IsLetter(rune(c)) || c == '_' || c == '@' {
			j := i
			for j < len(s) && (unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j])) || s[j] == '_' || s[j] == '$' || s[j] == '@') {
				j++
			}
			word := strings.ToLower(s[i:j])
			if isSQLKeyword(word) {
				toks = append(toks, token{tokKeyword, word})
			} else {
				toks = append(toks, token{tokIdent, word})
			}
			i = j
			continue
		}

		// 括号与逗号分号
		if c == '(' || c == ')' || c == ',' || c == ';' {
			toks = append(toks, token{tokParen, string(c)})
			i++
			continue
		}

		// 运算符
		if c == '=' || c == '<' || c == '>' || c == '!' || c == '+' || c == '-' || c == '*' || c == '/' || c == '|' || c == '&' || c == '%' {
			j := i
			if j+1 < len(s) {
				next := s[j+1]
				if (c == '<' && next == '=') || (c == '<' && next == '>') ||
					(c == '>' && next == '=') || (c == '!' && next == '=') ||
					(c == '|' && next == '|') || (c == '&' && next == '&') {
					j += 2
				} else {
					j++
				}
			} else {
				j++
			}
			toks = append(toks, token{tokOp, s[i:j]})
			i = j
			continue
		}

		// 十六进制前缀 0x（MySQL 风格）
		if c == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') {
			j := i + 2
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || (s[j] >= 'a' && s[j] <= 'f') || (s[j] >= 'A' && s[j] <= 'F')) {
				j++
			}
			toks = append(toks, token{tokIdent, s[i:j]})
			i = j
			continue
		}

		// 其它字符跳过
		i++
	}
	return toks
}

// isSQLKeyword 判断是否为 SQL 关键字
func isSQLKeyword(word string) bool {
	switch word {
	case "select", "union", "insert", "update", "delete", "drop", "create",
		"alter", "truncate", "from", "where", "and", "or", "not",
		"into", "values", "set", "table", "database", "schema",
		"order", "group", "by", "having", "limit", "offset",
		"join", "inner", "outer", "left", "right", "on",
		"sleep", "benchmark", "load_file", "outfile", "dumpfile",
		"information_schema", "columns", "tables", "concat",
		"cast", "convert", "char", "ascii", "substring", "mid",
		"if", "case", "when", "then", "else", "end",
		"null", "true", "false", "like", "in", "exists",
		"exec", "execute", "xp_cmdshell", "sp_oamethod":
		return true
	}
	return false
}

// sqliHasKeyword 判断 token 列表中是否包含指定关键字（任意位置）
func sqliHasKeyword(toks []token, kw string) bool {
	for _, t := range toks {
		if t.kind == tokKeyword && t.val == kw {
			return true
		}
	}
	return false
}

// sqliKeywordSequence 检测 token 列表中是否按顺序出现给定的关键字序列
func sqliKeywordSequence(toks []token, seq ...string) bool {
	if len(seq) == 0 {
		return true
	}
	idx := 0
	for _, t := range toks {
		if t.kind == tokKeyword && t.val == seq[idx] {
			idx++
			if idx >= len(seq) {
				return true
			}
		}
	}
	return false
}

// sqliKeywordCount 统计关键字数量（去重）
func sqliKeywordCount(toks []token) int {
	seen := make(map[string]struct{})
	for _, t := range toks {
		if t.kind == tokKeyword {
			seen[t.val] = struct{}{}
		}
	}
	return len(seen)
}

// ===================== 语义检测模式 =====================

// sqliSemanticCheck 对输入字符串做语义分析，返回 (得分, 是否确认注入, 理由)。
// 得分 ≥40 确认注入，20-39 可疑，<20 大概率误报。
func sqliSemanticCheck(s string) (score int, confirmed bool, reason string) {
	toks := sqliLex(s)
	if len(toks) == 0 {
		return 0, false, ""
	}

	// 白名单 1：文档/教学类纯说明文本
	if isDocumentationLike(s) {
		return 0, false, ""
	}

	// 白名单 2：简单的 key=value 或数字比较（无 SQL 关键字）
	if isSimpleKeyValue(s) {
		return 0, false, ""
	}

	// 白名单 3：union 作为普通英文单词使用（如 "European Union"）
	if isUnionAsCommonWord(s) {
		return 0, false, ""
	}

	// ---------- 检测模式 ----------

	// 模式 1：union + select（经典的联合查询注入）
	if sqliKeywordSequence(toks, "union", "select") {
		score += 45
		reason = "UNION SELECT 联合查询注入"
	}

	// 模式 2：insert + into（插入注入）
	if sqliKeywordSequence(toks, "insert", "into") {
		score += 40
		reason = "INSERT INTO 注入"
	}

	// 模式 3：update + set（更新注入）
	if sqliKeywordSequence(toks, "update", "set") {
		score += 40
		reason = "UPDATE SET 注入"
	}

	// 模式 4：delete + from（删除注入）
	if sqliKeywordSequence(toks, "delete", "from") {
		score += 40
		reason = "DELETE FROM 注入"
	}

	// 模式 5：drop + table（删表注入）
	if sqliKeywordSequence(toks, "drop", "table") {
		score += 50
		reason = "DROP TABLE 注入"
	}

	// 模式 6：布尔恒真式（如 '1'='1'、1=1、admin'-- 等）
	if hasBooleanTautology(toks) {
		score += 45
		if reason == "" {
			reason = "布尔恒真式注入"
		}
	}

	// 模式 7：sleep() / benchmark() 时间盲注
	if sqliHasKeyword(toks, "sleep") || sqliHasKeyword(toks, "benchmark") {
		score += 45
		if reason == "" {
			reason = "时间盲注 (SLEEP/BENCHMARK)"
		}
	}

	// 模式 8：堆叠查询（分号后接新语句）
	if hasStackedQuery(toks) {
		score += 40
		if reason == "" {
			reason = "堆叠查询注入"
		}
	}

	// 模式 9：注释截断 (--、#、/**/)
	if hasCommentTruncation(s, toks) {
		score += 35
		if reason == "" {
			reason = "注释截断注入"
		}
	}

	// 模式 10：information_schema 信息泄露探测
	if sqliHasKeyword(toks, "information_schema") {
		score += 35
		if reason == "" {
			reason = "information_schema 探测"
		}
	}

	// 模式 11：load_file / into outfile 文件操作注入
	if sqliHasKeyword(toks, "load_file") {
		score += 40
		if reason == "" {
			reason = "LOAD_FILE 文件注入"
		}
	}
	if sqliKeywordSequence(toks, "into", "outfile") || sqliKeywordSequence(toks, "into", "dumpfile") {
		score += 40
		if reason == "" {
			reason = "INTO OUTFILE 文件写入注入"
		}
	}

	// 模式 12：关键字密度加分（多种关键字混合 = 高可疑度）
	if kc := sqliKeywordCount(toks); kc >= 4 {
		score += 15
	} else if kc >= 3 {
		score += 8
	}

	// 模式 13：字符串拼接函数（concat/char/ascii 常用于绕过）
	if sqliHasKeyword(toks, "concat") || sqliHasKeyword(toks, "char") || sqliHasKeyword(toks, "ascii") {
		score += 15
	}

	// 模式 14：类型转换函数（cast/convert 常用于绕过）
	if sqliHasKeyword(toks, "cast") || sqliHasKeyword(toks, "convert") {
		score += 12
	}

	// 模式 15：xp_cmdshell / sp_oamethod（MSSQL 高危存储过程）
	if sqliHasKeyword(toks, "xp_cmdshell") || sqliHasKeyword(toks, "sp_oamethod") || sqliHasKeyword(toks, "exec") {
		score += 45
		if reason == "" {
			reason = "MSSQL 高危存储过程注入"
		}
	}

	// ---------- 原始字符串兜底检测（应对引号配对吞关键字的情况） ----------
	lower := strings.ToLower(s)

	// 兜底 A：布尔恒真式子串
	if score < 40 && (strings.Contains(lower, "'1'='1") || strings.Contains(lower, "1=1") ||
		strings.Contains(lower, "'a'='a") || strings.Contains(lower, "'x'='x") ||
		strings.Contains(lower, "0=0") || strings.Contains(lower, "'0'='0")) {
		score += 45
		if reason == "" {
			reason = "布尔恒真式注入"
		}
	}

	// 兜底 B：load_file / into outfile 子串（引号可能把关键字吞进字符串）
	if score < 40 && strings.Contains(lower, "load_file") {
		score += 40
		if reason == "" {
			reason = "LOAD_FILE 文件注入"
		}
	}
	if score < 40 && (strings.Contains(lower, "into outfile") || strings.Contains(lower, "into dumpfile")) {
		score += 40
		if reason == "" {
			reason = "INTO OUTFILE 文件写入注入"
		}
	}

	// 兜底 C：注释截断（检测到 '-- 或 /* 或 # 与引号/SQL 关键字共存）
	if score < 40 && (strings.Contains(lower, "--") || strings.Contains(lower, "/*") || strings.Contains(lower, "#")) {
		if sqliKeywordCount(toks) >= 1 || strings.Contains(lower, "'") {
			score += 40
			if reason == "" {
				reason = "注释截断注入"
			}
		}
	}

	// 兜底 D：经典 SQL 注入组合子串（应对引号/JSON 把关键字吞进字符串的情况）
	if score < 40 {
		if strings.Contains(lower, "union") && strings.Contains(lower, "select") {
			score += 45
			if reason == "" {
				reason = "UNION SELECT 联合查询注入"
			}
		} else if strings.Contains(lower, "insert") && strings.Contains(lower, "into") {
			score += 40
			if reason == "" {
				reason = "INSERT INTO 注入"
			}
		} else if strings.Contains(lower, "update") && strings.Contains(lower, "set") {
			score += 40
			if reason == "" {
				reason = "UPDATE SET 注入"
			}
		} else if strings.Contains(lower, "delete") && strings.Contains(lower, "from") {
			score += 40
			if reason == "" {
				reason = "DELETE FROM 注入"
			}
		} else if strings.Contains(lower, "drop") && strings.Contains(lower, "table") {
			score += 50
			if reason == "" {
				reason = "DROP TABLE 注入"
			}
		}
	}

	// ---------- 误报减分项 ----------
	// 只有单一关键字且无运算符/括号 → 极大可能是误报
	if len(toks) <= 2 && sqliKeywordCount(toks) == 1 {
		score -= 20
	}
	// 全是英文正常句子（大写开头、句点结尾）
	if looksLikeNormalSentence(s) {
		score -= 15
	}
	// 查询参数中常见合法 key 名包含 select/union（如 ?sort=select）
	if isLikelyParameterKey(s) {
		score -= 10
	}

	if score < 0 {
		score = 0
	}
	confirmed = score >= 40
	return
}

// sqliSemanticWAFCheck 返回语义确认的理由字符串，若未确认返回 ""
func sqliSemanticWAFCheck(s string) string {
	score, confirmed, reason := sqliSemanticCheck(s)
	_ = score
	if confirmed {
		return "SQL 注入（语义确认: " + reason + "）"
	}
	return ""
}

// ===================== 子检测函数 =====================

// hasBooleanTautology 检测布尔恒真式，如 '1'='1'、1=1、admin'-- 等
func hasBooleanTautology(toks []token) bool {
	// 扫描 token 序列找 数字/字符串 = 数字/字符串 或 1=1 类模式
	for i := 0; i < len(toks)-2; i++ {
		// 模式 A：数字/字符串 = 数字/字符串
		if toks[i].kind == tokNumber || toks[i].kind == tokString {
			if toks[i+1].kind == tokOp && toks[i+1].val == "=" {
				if toks[i+2].kind == tokNumber || toks[i+2].kind == tokString {
					return true
				}
			}
		}
		// 模式 B：'1' = '1'（字符串内部带引号的情况，lexer 已处理为 tokString）
		if toks[i].kind == tokString && toks[i+1].kind == tokOp && toks[i+1].val == "=" {
			if toks[i+2].kind == tokString {
				return true
			}
		}
	}
	// 模式 C：直接子串匹配常见恒真式（处理 lexer 可能切不干净的边界）
	joined := joinTokens(toks)
	patterns := []string{
		"'1'='1", "'1'='1'", "1=1", "1 = 1",
		"'a'='a", "'x'='x", "0=0", "'0'='0",
	}
	for _, p := range patterns {
		if strings.Contains(joined, p) {
			return true
		}
	}
	return false
}

// hasStackedQuery 检测堆叠查询（分号后接关键字）
func hasStackedQuery(toks []token) bool {
	for i := 0; i < len(toks)-1; i++ {
		if toks[i].kind == tokParen && toks[i].val == ";" {
			// 分号后是关键字 → 堆叠查询
			if toks[i+1].kind == tokKeyword {
				return true
			}
		}
	}
	return false
}

// hasCommentTruncation 检测注释截断攻击
func hasCommentTruncation(s string, toks []token) bool {
	// 子串匹配常见注释截断模式
	lower := strings.ToLower(s)
	if strings.Contains(lower, "-- ") || strings.Contains(lower, "#") ||
		strings.Contains(lower, "/*") || strings.Contains(lower, "//") {
		// 同时存在 SQL 关键字 → 才认为是注入
		if sqliKeywordCount(toks) >= 2 {
			return true
		}
	}
	// token 级别检测注释 token
	for _, t := range toks {
		if t.kind == tokComment {
			if sqliKeywordCount(toks) >= 2 {
				return true
			}
		}
	}
	return false
}

// joinTokens 把 token 的值重新拼接为字符串（用于子串匹配兜底）
func joinTokens(toks []token) string {
	var sb strings.Builder
	for _, t := range toks {
		sb.WriteString(t.val)
		sb.WriteByte(' ')
	}
	return sb.String()
}

// ===================== 白名单函数 =====================

// isDocumentationLike 判断是否为文档/教学类说明文本
func isDocumentationLike(s string) bool {
	lower := strings.ToLower(s)
	phrases := []string{
		"for example", "such as", "the following", "e.g.", "i.e.",
		"in this case", "as shown", "documentation", "tutorial",
		"this query", "the query", "example query", "sample query",
		"how to", "what is", "explain", "note that", "please note",
	}
	for _, p := range phrases {
		if strings.Contains(lower, p) {
			// 同时含有 "select" 且没有危险模式 → 文档示例
			if strings.Contains(lower, "select") &&
				!strings.Contains(lower, "union") &&
				!strings.Contains(lower, "sleep") &&
				!strings.Contains(lower, "benchmark") &&
				!strings.Contains(lower, "drop") &&
				!strings.Contains(lower, "delete") {
				return true
			}
		}
	}
	return false
}

// isSimpleKeyValue 简单 key=value 或纯数字比较（无 SQL 关键字）
func isSimpleKeyValue(s string) bool {
	// 如果字符串里没有任何 SQL 关键字，可能是合法参数
	toks := sqliLex(s)
	kwCount := sqliKeywordCount(toks)
	if kwCount == 0 {
		// 无关键字但包含引号/注释/分号等注入特征 → 不简单
		lower := strings.ToLower(s)
		if strings.Contains(lower, "'") || strings.Contains(lower, "--") ||
			strings.Contains(lower, "/*") || strings.Contains(lower, "#") ||
			strings.Contains(lower, ";") {
			return false
		}
		return true
	}
	// 只有一个关键字且无括号/运算符（如 ?sort=select）
	if kwCount == 1 && len(toks) <= 3 {
		hasOp := false
		hasParen := false
		for _, t := range toks {
			if t.kind == tokOp {
				hasOp = true
			}
			if t.kind == tokParen {
				hasParen = true
			}
		}
		if !hasOp && !hasParen {
			return true
		}
	}
	return false
}

// isUnionAsCommonWord 判断 union 是否作为普通英文单词使用
func isUnionAsCommonWord(s string) bool {
	lower := strings.ToLower(s)
	// "European Union"、"credit union"、"student union" 等常见短语
	commonPhrases := []string{
		"european union", "credit union", "student union", "labor union",
		"trade union", "union station", "union city",
	}
	for _, phrase := range commonPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// looksLikeNormalSentence 判断是否为正常英文句子（大写开头、句点结尾）
func looksLikeNormalSentence(s string) bool {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) == 0 {
		return false
	}
	// 大写开头
	first := rune(trimmed[0])
	if !unicode.IsUpper(first) {
		return false
	}
	// 句点结尾
	if trimmed[len(trimmed)-1] == '.' {
		return true
	}
	return false
}

// isLikelyParameterKey 判断字符串是否像 URL 参数 key（如 sort=select）
func isLikelyParameterKey(s string) bool {
	// 如果包含 = 且 = 前面是常见参数名，后面是单个关键字
	if idx := strings.Index(s, "="); idx > 0 {
		key := strings.ToLower(strings.TrimSpace(s[:idx]))
		commonKeys := []string{"sort", "order", "field", "column", "by", "type", "mode", "action"}
		for _, ck := range commonKeys {
			if key == ck || strings.HasSuffix(key, "_"+ck) || strings.HasPrefix(key, ck+"_") {
				return true
			}
		}
	}
	return false
}

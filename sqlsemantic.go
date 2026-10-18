package main

import (
	"regexp"
	"strings"
	"unicode"
)

// ===================== v4.33.0 SQL 语义分析层 =====================
//
// 在现有正则 WAF 基础上增加 SQL 语法树解析，识别正则难以覆盖的注入手法：
//   1. 注释绕过：攻击者用 /**/、/*!50000*/、--、# 等注释分割关键字，
//      使 UNION SELECT 变成 UNI/**/ON SEL/**/ECT，绕过基于字符串匹配的正则。
//   2. 拼接注入：利用 CONCAT()、||、+ 等拼接函数/运算符动态组装 SQL 关键字，
//      如 CONCAT('UN','ION')、'uni'||'on'，静态正则难以穷尽组合。
//   3. 时间盲注：利用 SLEEP()、BENCHMARK()、pg_sleep()、WAITFOR DELAY 等
//      时间延迟函数，配合条件判断实现无回显的数据窃取。
//
// 设计原则：零外部依赖、纯 Go 标准库、与现有 wafMatch 链式调用、
// 命中后返回 "SQL 语义注入"，审计日志中可区分正则命中与语义命中。

// sqlTokenKind SQL 词法单元类型
type sqlTokenKind int

const (
	sqlEOF sqlTokenKind = iota
	sqlIdent      // 标识符/关键字（含反引号包裹）
	sqlString     // 字符串字面量 '...' 或 "..."
	sqlNumber     // 数字
	sqlComment    // 注释 /**/、--、#
	sqlPunct      // 标点符号 ( ) , ; = < > 等
	sqlOp         // 运算符 + - * / || && |
	sqlUnknown    // 其他字符
)

// sqlToken 词法单元
type sqlToken struct {
	kind sqlTokenKind
	text string
}

// sqlTokenizer SQL 轻量级分词器（支持 MySQL/SQLite/PostgreSQL/SQL Server 常见语法）
type sqlTokenizer struct {
	input string
	pos   int
	len   int
}

func newSQLTokenizer(input string) *sqlTokenizer {
	return &sqlTokenizer{input: input, len: len(input)}
}

func (t *sqlTokenizer) peek() byte {
	if t.pos >= t.len {
		return 0
	}
	return t.input[t.pos]
}

func (t *sqlTokenizer) next() byte {
	if t.pos >= t.len {
		return 0
	}
	ch := t.input[t.pos]
	t.pos++
	return ch
}

func (t *sqlTokenizer) skipWhitespace() {
	for t.pos < t.len {
		c := t.input[t.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			t.pos++
		} else {
			break
		}
	}
}

// nextToken 返回下一个词法单元
func (t *sqlTokenizer) nextToken() sqlToken {
	t.skipWhitespace()
	if t.pos >= t.len {
		return sqlToken{kind: sqlEOF}
	}

	c := t.peek()

	// 字符串字面量 '...' 或 "..." 或 `...`
	if c == '\'' || c == '"' || c == '`' {
		return t.readString(c)
	}

	// 数字
	if (c >= '0' && c <= '9') || (c == '.' && t.pos+1 < t.len && t.input[t.pos+1] >= '0' && t.input[t.pos+1] <= '9') {
		return t.readNumber()
	}

	// 注释 /**/ 或 //* (MySQL 条件注释 /*!50000...*/)
	if c == '/' && t.pos+1 < t.len {
		if t.input[t.pos+1] == '*' {
			return t.readBlockComment()
		}
	}

	// 注释 -- 或 #
	if c == '-' && t.pos+1 < t.len && t.input[t.pos+1] == '-' {
		return t.readLineComment()
	}
	if c == '#' {
		return t.readLineCommentHash()
	}

	// 运算符：||、&&、|、&、+、-、*、/、=、<、>、!
	if c == '|' || c == '&' || c == '+' || c == '-' || c == '*' || c == '/' ||
		c == '=' || c == '<' || c == '>' || c == '!' || c == '%' || c == '~' {
		return t.readOperator()
	}

	// 标点
	if c == '(' || c == ')' || c == ',' || c == ';' || c == '.' || c == '@' || c == ':' {
		return sqlToken{kind: sqlPunct, text: string(t.next())}
	}

	// 标识符/关键字
	if unicode.IsLetter(rune(c)) || c == '_' || c == '$' {
		return t.readIdent()
	}

	// 未知字符（如 \x00 等控制字符，常见于编码绕过）
	t.pos++
	return sqlToken{kind: sqlUnknown, text: string(c)}
}

func (t *sqlTokenizer) readString(quote byte) sqlToken {
	start := t.pos
	t.pos++ // 跳过起始引号
	for t.pos < t.len {
		if t.input[t.pos] == quote {
			if quote == '\'' && t.pos+1 < t.len && t.input[t.pos+1] == '\'' {
				// SQL 转义 ''
				t.pos += 2
				continue
			}
			t.pos++
			return sqlToken{kind: sqlString, text: t.input[start:t.pos]}
		}
		// 跳过转义 \'
		if t.input[t.pos] == '\\' && t.pos+1 < t.len {
			t.pos += 2
			continue
		}
		t.pos++
	}
	// 未闭合的字符串：返回剩余全部内容，但标记为特殊字符串（含未闭合特征）
	return sqlToken{kind: sqlString, text: t.input[start:t.pos]}
}

func (t *sqlTokenizer) readNumber() sqlToken {
	start := t.pos
	for t.pos < t.len && (t.input[t.pos] >= '0' && t.input[t.pos] <= '9' || t.input[t.pos] == '.' || t.input[t.pos] == 'e' || t.input[t.pos] == 'E' || t.input[t.pos] == '+' || t.input[t.pos] == '-') {
		t.pos++
	}
	return sqlToken{kind: sqlNumber, text: t.input[start:t.pos]}
}

func (t *sqlTokenizer) readBlockComment() sqlToken {
	start := t.pos
	t.pos += 2 // 跳过 /*
	for t.pos < t.len {
		if t.input[t.pos] == '*' && t.pos+1 < t.len && t.input[t.pos+1] == '/' {
			t.pos += 2
			return sqlToken{kind: sqlComment, text: t.input[start:t.pos]}
		}
		t.pos++
	}
	return sqlToken{kind: sqlComment, text: t.input[start:t.pos]}
}

func (t *sqlTokenizer) readLineComment() sqlToken {
	start := t.pos
	t.pos += 2 // 跳过 --
	for t.pos < t.len && t.input[t.pos] != '\n' {
		t.pos++
	}
	return sqlToken{kind: sqlComment, text: t.input[start:t.pos]}
}

func (t *sqlTokenizer) readLineCommentHash() sqlToken {
	start := t.pos
	t.pos++ // 跳过 #
	for t.pos < t.len && t.input[t.pos] != '\n' {
		t.pos++
	}
	return sqlToken{kind: sqlComment, text: t.input[start:t.pos]}
}

func (t *sqlTokenizer) readOperator() sqlToken {
	start := t.pos
	c := t.next()
	// 双字符运算符
	if t.pos < t.len {
		next := t.input[t.pos]
		if (c == '|' && next == '|') || (c == '&' && next == '&') ||
			(c == '<' && next == '=') || (c == '>' && next == '=') ||
			(c == '!' && next == '=') || (c == '<' && next == '>') {
			t.pos++
		}
	}
	return sqlToken{kind: sqlOp, text: t.input[start:t.pos]}
}

func (t *sqlTokenizer) readIdent() sqlToken {
	start := t.pos
	for t.pos < t.len {
		c := t.input[t.pos]
		if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_' || c == '$' {
			t.pos++
		} else {
			break
		}
	}
	return sqlToken{kind: sqlIdent, text: t.input[start:t.pos]}
}

// ===================== 语义分析 =====================

// sqlDangerousKeywords 高危 SQL 关键字
type sqlKeyword struct {
	word    string
	needsLP bool // 是否需要左括号跟随（用于函数型关键字）
}

var sqlDangerousKeywords = []sqlKeyword{
	{"union", false}, {"select", false}, {"insert", false}, {"delete", false},
	{"update", false}, {"drop", false}, {"alter", false}, {"create", false},
	{"exec", true}, {"execute", true}, {"shutdown", false}, {"grant", false},
	{"revoke", false}, {"truncate", false},
}

// sqlTimeFunctions 时间盲注函数
type sqlTimeFunc struct {
	name    string
	needsLP bool
}

var sqlTimeFunctions = []sqlTimeFunc{
	{"sleep", true}, {"benchmark", true}, {"pg_sleep", true},
	{"waitfor", false}, {"dbms_pipe.receive_message", true},
	{"dbms_lock.sleep", true}, {"generate_series", true},
}

// sqlConcatFunctions 拼接函数
type sqlConcatFunc struct {
	name string
}

var sqlConcatFunctions = []sqlConcatFunc{
	{"concat"}, {"concat_ws"}, {"char"}, {"chr"},
}

// sqlSemanticResult 语义分析结果
type sqlSemanticResult struct {
	matched  bool
	category string // comment_bypass | concat_injection | time_blind | stacked_query
	detail   string
}

// sqlSemanticAnalyze 对输入进行 SQL 语义分析
func sqlSemanticAnalyze(input string) sqlSemanticResult {
	// 快速预筛：不含 SQL 相关字符的直接跳过（性能优化）
	lower := strings.ToLower(input)
	hasSQLChar := false
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if (c >= 'a' && c <= 'z') || c == '\'' || c == '"' || c == '/' || c == '-' || c == '#' ||
			c == '*' || c == '(' || c == ')' || c == ';' || c == '|' || c == '+' || c == '`' ||
			c == '=' || c == '%' || c == '!' || c == '<' || c == '>' {
			hasSQLChar = true
			break
		}
	}
	if !hasSQLChar {
		return sqlSemanticResult{matched: false}
	}

	// 1. 注释绕过检测（字符串级处理，处理未闭合引号场景）
	if r := sqlDetectCommentBypassString(input); r.matched {
		return r
	}

	// 2. 拼接注入检测
	if r := sqlDetectConcatInjectionString(input); r.matched {
		return r
	}

	// 3. 时间盲注检测
	if r := sqlDetectTimeBlindString(input); r.matched {
		return r
	}

	// 4. 堆叠查询检测（字符串级处理）
	if r := sqlDetectStackedQueryString(input); r.matched {
		return r
	}

	return sqlSemanticResult{matched: false}
}

// stripSQLComments 从输入中处理所有 SQL 注释：
//   - 普通 /**/ 块注释：移除
//   - MySQL 条件注释 /*!50000...*/：保留内部内容（MySQL 会执行）
//   - -- 行注释、# 行注释：移除
// 返回处理后的字符串（空白已折叠为单个空格，方便关键字检测）
func stripSQLComments(input string) string {
	var result strings.Builder
	i := 0
	for i < len(input) {
		// /* 开头的块注释
		if i+1 < len(input) && input[i] == '/' && input[i+1] == '*' {
			// 检查是否是 MySQL 条件注释 /*!...*/
			if i+2 < len(input) && input[i+2] == '!' {
				end := strings.Index(input[i+3:], "*/")
				if end >= 0 {
					// 保留 /*! 之后的内容（含版本号），去掉尾部的 */
					inner := input[i+3 : i+3+end]
					result.WriteString(inner)
					result.WriteByte(' ')
					i += end + 5
					continue
				}
			} else {
				// 普通块注释：直接移除
				end := strings.Index(input[i+2:], "*/")
				if end >= 0 {
					i += end + 4
					continue
				}
			}
			break
		}
		// -- 行注释
		if i+1 < len(input) && input[i] == '-' && input[i+1] == '-' {
			for i < len(input) && input[i] != '\n' {
				i++
			}
			// 保留一个空格，避免 --\n 把前后关键字粘在一起
			result.WriteByte(' ')
			continue
		}
		// # 行注释
		if input[i] == '#' {
			for i < len(input) && input[i] != '\n' {
				i++
			}
			result.WriteByte(' ')
			continue
		}
		result.WriteByte(input[i])
		i++
	}
	return result.String()
}

// sqlDetectCommentBypassString 检测注释绕过（字符串级处理）
func sqlDetectCommentBypassString(input string) sqlSemanticResult {
	// 先检查是否真的有注释；无注释时不应触发
	hasComment := strings.Contains(input, "/*") || strings.Contains(input, "--") || strings.Contains(input, "#")
	if !hasComment {
		return sqlSemanticResult{matched: false}
	}

	// 去注释后检查高危关键字组合
	stripped := strings.ToLower(stripSQLComments(input))
	// 规范化空白：折叠多个空白/换行为单个空格
	stripped = regexp.MustCompile(`\s+`).ReplaceAllString(stripped, " ")

	// 去注释后出现 UNION SELECT / UNION ALL SELECT / INSERT INTO / DELETE FROM / DROP TABLE
	dangerous := []string{
		"union select", "union all select", "insert into", "delete from",
		"drop table", "alter table", "create table", "exec(", "execute(",
	}
	for _, d := range dangerous {
		if strings.Contains(stripped, d) {
			return sqlSemanticResult{
				matched:  true,
				category: "comment_bypass",
				detail:   "注释分割关键字后重组命中: " + d,
			}
		}
	}

	// 注释分割可能导致关键字被空白隔开（如 UNI /**/ ON → "UNI ON"），
	// 再去掉所有空白后检查拼接形式（如 unionselect、insertinto）
	noSpace := regexp.MustCompile(`\s+`).ReplaceAllString(stripped, "")
	concatDangerous := []string{
		"unionselect", "unionallselect", "insertinto", "deletefrom",
		"droptable", "altertable", "createtable", "exec(", "execute(",
	}
	for _, d := range concatDangerous {
		if strings.Contains(noSpace, d) {
			return sqlSemanticResult{
				matched:  true,
				category: "comment_bypass",
				detail:   "注释分割关键字后重组命中: " + d,
			}
		}
	}

	// MySQL 条件注释特殊处理：关键字前可能带数字版本号，如 50000union
	// 用正则匹配数字后直接跟高危关键字（支持两侧都带版本号）
	condPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\d+union\s+(\d+)?select`),
		regexp.MustCompile(`\d+insert\s+(\d+)?into`),
		regexp.MustCompile(`\d+delete\s+(\d+)?from`),
		regexp.MustCompile(`\d+drop\s+(\d+)?table`),
	}
	for _, re := range condPatterns {
		if m := re.FindString(stripped); m != "" {
			return sqlSemanticResult{
				matched:  true,
				category: "comment_bypass",
				detail:   "MySQL 条件注释绕过: " + m,
			}
		}
	}

	return sqlSemanticResult{matched: false}
}

// sqlDetectConcatInjectionString 检测拼接注入（字符串级处理）
func sqlDetectConcatInjectionString(input string) sqlSemanticResult {
	lower := strings.ToLower(input)

	// 策略 A：CHR(XX) 或 CHAR(XX) 编码拼接
	hasChr := strings.Contains(lower, "chr(") || strings.Contains(lower, "char(")
	hasConcatOp := strings.Contains(lower, "||")
	hasConcatFunc := strings.Contains(lower, "concat(") || strings.Contains(lower, "concat_ws(")

	if hasChr && (hasConcatOp || hasConcatFunc) {
		return sqlSemanticResult{
			matched:  true,
			category: "concat_injection",
			detail:   "CHR/CHAR 编码拼接注入",
		}
	}

	// 策略 B：CONCAT/CONCAT_WS 函数参数中含关键字片段
	if hasConcatFunc {
		// 提取单引号字符串并拼接
		fragments := extractQuotedStrings(input)
		var combined strings.Builder
		for _, s := range fragments {
			combined.WriteString(strings.ToLower(s))
		}
		combo := combined.String()
		for _, kw := range sqlDangerousKeywords {
			if strings.Contains(combo, kw.word) {
				return sqlSemanticResult{
					matched:  true,
					category: "concat_injection",
					detail:   "CONCAT 参数拼接出关键字: " + kw.word,
				}
			}
		}
	}

	// 策略 C：字符串字面量 + || 拼接出关键字片段
	if hasConcatOp {
		fragments := extractQuotedStrings(input)
		if len(fragments) >= 2 {
			var combined strings.Builder
			for _, f := range fragments {
				combined.WriteString(strings.ToLower(f))
			}
			combo := combined.String()
			for _, kw := range sqlDangerousKeywords {
				if strings.Contains(combo, kw.word) {
					return sqlSemanticResult{
						matched:  true,
						category: "concat_injection",
						detail:   "|| 拼接出关键字: " + kw.word,
					}
				}
			}
		}
	}

	return sqlSemanticResult{matched: false}
}

// extractQuotedStrings 从输入中提取单引号/双引号字符串内容（不含引号）
func extractQuotedStrings(input string) []string {
	var result []string
	i := 0
	for i < len(input) {
		if input[i] == '\'' || input[i] == '"' {
			quote := input[i]
			i++
			start := i
			for i < len(input) && input[i] != quote {
				if input[i] == '\\' && i+1 < len(input) {
					i += 2
					continue
				}
				i++
			}
			if start < i {
				result = append(result, input[start:i])
			}
			if i < len(input) {
				i++ // 跳过结束引号
			}
			continue
		}
		i++
	}
	return result
}

// sqlDetectTimeBlindString 检测时间盲注（字符串级处理）
func sqlDetectTimeBlindString(input string) sqlSemanticResult {
	lower := strings.ToLower(input)

	// 直接匹配时间函数名，但要求函数调用语法（后跟 '('）或 WAITFOR DELAY 上下文
	for _, tf := range sqlTimeFunctions {
		if !strings.Contains(lower, tf.name) {
			continue
		}
		if tf.name == "waitfor" {
			if strings.Contains(lower, "waitfor") && strings.Contains(lower, "delay") {
				return sqlSemanticResult{
					matched:  true,
					category: "time_blind",
					detail:   "SQL Server WAITFOR DELAY 盲注",
				}
			}
			continue
		}
		// 其他函数需要函数调用语法：name(
		idx := strings.Index(lower, tf.name)
		if idx >= 0 {
			endPos := idx + len(tf.name)
			if endPos < len(lower) && lower[endPos] == '(' {
				return sqlSemanticResult{
					matched:  true,
					category: "time_blind",
					detail:   "时间盲注函数: " + tf.name,
				}
			}
		}
	}

	// 十六进制编码的时间函数：0x736C656570 = sleep
	if strings.Contains(lower, "0x") && strings.Contains(lower, "(") {
		// 常见十六进制编码函数名（统一小写匹配）
		hexFuncs := []string{"0x736c656570", "0x62656e63686d61726b", "0x70675f736c656570"}
		for _, hf := range hexFuncs {
			if strings.Contains(lower, hf) {
				return sqlSemanticResult{
					matched:  true,
					category: "time_blind",
					detail:   "十六进制编码时间盲注",
				}
			}
		}
	}

	return sqlSemanticResult{matched: false}
}

// sqlDetectStackedQueryString 检测堆叠查询（字符串级处理）
func sqlDetectStackedQueryString(input string) sqlSemanticResult {
	lower := strings.ToLower(input)

	// 堆叠查询通常出现在注入场景中，需配合其他注入特征才触发（减少误报）
	// 纯分号（如正常多语句）不足以触发，需配合引号/注释/布尔运算符等注入特征
	hasInjectionIndicator := strings.Contains(lower, "'") ||
		strings.Contains(lower, "--") ||
		strings.Contains(lower, "#") ||
		strings.Contains(lower, " or ") ||
		strings.Contains(lower, " and ") ||
		strings.Contains(lower, "=") && strings.Contains(lower, "'")

	if !hasInjectionIndicator {
		return sqlSemanticResult{matched: false}
	}

	// 用正则查找 ; 后跟高危关键字（允许空白）
	// 模式：;\s*(drop|delete|insert|union|select|update|alter|create|exec|execute|truncate)\b
	re := regexp.MustCompile(`;\s*(drop|delete|insert|union|select|update|alter|create|exec|execute|truncate)\b`)
	if m := re.FindStringSubmatch(lower); m != nil {
		return sqlSemanticResult{
			matched:  true,
			category: "stacked_query",
			detail:   "堆叠查询: ;" + m[1],
		}
	}

	return sqlSemanticResult{matched: false}
}

// sqlSemanticMatch SQL 语义分析入口，与 wafMatch 返回值风格一致
// 命中返回 "SQL 语义注入"，未命中返回空串
func sqlSemanticMatch(input string) string {
	result := sqlSemanticAnalyze(input)
	if result.matched {
		return "SQL 语义注入"
	}
	return ""
}

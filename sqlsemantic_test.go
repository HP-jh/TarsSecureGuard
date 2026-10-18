package main

import "testing"

// ===================== v4.33.0 SQL 语义分析测试 =====================

func TestSQLSemanticCommentBypass(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		// 注释绕过：/**/ 分割关键字
		{"1' UNI/**/ON SEL/**/ECT * FROM users", true},
		{"1' UNI\n/**/\nON SEL\n/**/\nECT * FROM users", true},
		{"id=1 /*!50000UNION*/ /*!50000SELECT*/ * FROM users", true},
		{"id=1 /*!union*/ /*!select*/ 1,2,3", true},
		// -- 注释绕过
		{"1' UNION--\nSELECT * FROM users", true},
		{"1' UNION-- comment\nSELECT * FROM users", true},
		// # 注释绕过
		{"1' UNION#comment\nSELECT * FROM users", true},
		// INSERT / DELETE / DROP 注释绕过
		{"1'; INS/**/ERT INTO users VALUES('a','b')", true},
		{"1'; DEL/**/ETE FROM users", true},
		{"1'; DR/**/OP TABLE users", true},
		// 正常 SQL（不应误报）
		{"SELECT * FROM users WHERE name = 'admin'", false},
		{"INSERT INTO logs (msg) VALUES ('user login')", false},
		{"DELETE FROM sessions WHERE expired = 1", false},
		// 非 SQL 输入
		{"hello world", false},
		{"The union of sets A and B", false},
		{"Please select an option from the dropdown", false},
	}

	for _, c := range cases {
		result := sqlSemanticAnalyze(c.input)
		got := result.matched && result.category == "comment_bypass"
		if got != c.want {
			t.Errorf("comment bypass: input=%q got matched=%v (category=%s), want %v", c.input, got, result.category, c.want)
		}
	}
}

func TestSQLSemanticConcatInjection(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		// CHR/CHAR 编码拼接
		{"CHR(85)||CHR(78)||CHR(73)||CHR(79)||CHR(78)", true},
		{"CONCAT('UN','ION')", true},
		{"CONCAT('SE','LECT')", true},
		{"CONCAT_WS('', 'UN', 'ION', ' ', 'SEL', 'ECT')", true},
		{"CONCAT(CHAR(85),CHAR(78),CHAR(73),CHAR(79),CHAR(78))", true},
		// 字符串字面量拼接
		{"'un'||'ion'||' select'", true},
		{"'de'||'lete'||' from'", true},
		// 正常 CONCAT（不应误报）
		{"CONCAT(first_name, ' ', last_name)", false},
		{"SELECT CONCAT('Hello', ' World')", false},
	}

	for _, c := range cases {
		result := sqlSemanticAnalyze(c.input)
		got := result.matched && result.category == "concat_injection"
		if got != c.want {
			t.Errorf("concat injection: input=%q got matched=%v (category=%s), want %v", c.input, got, result.category, c.want)
		}
	}
}

func TestSQLSemanticTimeBlind(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		// 标准时间盲注
		{"1' AND SLEEP(5)--", true},
		{"1' AND sleep(10)#", true},
		{"1' AND BENCHMARK(1000000,MD5(1))--", true},
		{"1' AND pg_sleep(5)--", true},
		{"1'; WAITFOR DELAY '0:0:5'--", true},
		// 大小写混合
		{"1' AND Sleep(3)--", true},
		{"1' AND benchmark(500000,sha1(1))#", true},
		// 编码变形
		{"1' AND 0x736C656570(5)--", true}, // 十六进制 sleep
		// 正常用法（不应误报）
		{"The sleep study shows interesting results", false},
		{"Benchmark report for Q3", false},
		{"SELECT * FROM pg_sleep_log", false}, // 表名含 pg_sleep 但无函数调用
	}

	for _, c := range cases {
		result := sqlSemanticAnalyze(c.input)
		got := result.matched && result.category == "time_blind"
		if got != c.want {
			t.Errorf("time blind: input=%q got matched=%v (category=%s detail=%s), want %v", c.input, got, result.category, result.detail, c.want)
		}
	}
}

func TestSQLSemanticStackedQuery(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		// 堆叠查询（含注释的会被 comment_bypass 先捕获，同属注入检测）
		{"1'; DROP TABLE users; --", true},
		{"1'; DELETE FROM users; --", true},
		{"1'; INSERT INTO logs VALUES('hack'); --", true},
		{"1'; UNION SELECT * FROM admin; --", true},
		// 无空格堆叠
		{"1';DROP TABLE users--", true},
		// 无注释纯堆叠
		{"1'; DROP TABLE users", true},
		{"1'; DELETE FROM users", true},
		// 正常分号（不应误报）
		{"SELECT * FROM users; SELECT * FROM orders", false},
		{"INSERT INTO logs (msg) VALUES ('done; ok')", false},
	}

	for _, c := range cases {
		result := sqlSemanticAnalyze(c.input)
		// 堆叠查询和注释绕过都算作命中（都是 SQL 注入的不同形式）
		got := result.matched && (result.category == "stacked_query" || result.category == "comment_bypass")
		if got != c.want {
			t.Errorf("stacked query: input=%q got matched=%v (category=%s detail=%s), want %v", c.input, got, result.category, result.detail, c.want)
		}
	}
}

func TestSQLSemanticMatch(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// 应命中
		{"1' UNI/**/ON SEL/**/ECT * FROM users", "SQL 语义注入"},
		{"CHR(85)||CHR(78)||CHR(73)||CHR(79)||CHR(78)", "SQL 语义注入"},
		{"1' AND SLEEP(5)--", "SQL 语义注入"},
		{"1'; DROP TABLE users; --", "SQL 语义注入"},
		// 不应命中
		{"hello world", ""},
		{"The union of sets A and B", ""},
		{"Please select an option", ""},
		{"CONCAT(first_name, ' ', last_name)", ""},
	}

	for _, c := range cases {
		got := sqlSemanticMatch(c.input)
		if got != c.want {
			t.Errorf("sqlSemanticMatch(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestSQLTokenizer(t *testing.T) {
	input := "SELECT /* comment */ 'str' || 123 + col"
	tok := newSQLTokenizer(input)
	var kinds []sqlTokenKind
	var texts []string
	for {
		tk := tok.nextToken()
		if tk.kind == sqlEOF {
			break
		}
		kinds = append(kinds, tk.kind)
		texts = append(texts, tk.text)
	}

	wantKinds := []sqlTokenKind{sqlIdent, sqlComment, sqlString, sqlOp, sqlNumber, sqlOp, sqlIdent}
	wantTexts := []string{"SELECT", "/* comment */", "'str'", "||", "123", "+", "col"}

	if len(kinds) != len(wantKinds) {
		t.Fatalf("tokenizer kinds len=%d, want %d; got %v", len(kinds), len(wantKinds), kinds)
	}
	for i := range kinds {
		if kinds[i] != wantKinds[i] {
			t.Errorf("token[%d] kind=%d, want %d (text=%q)", i, kinds[i], wantKinds[i], texts[i])
		}
		if texts[i] != wantTexts[i] {
			t.Errorf("token[%d] text=%q, want %q", i, texts[i], wantTexts[i])
		}
	}
}

func TestSQLTokenizerComments(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/**/", "/**/"},
		{"-- comment\nSELECT", "-- comment"},
		{"# comment\nSELECT", "# comment"},
		{"/*!50000SELECT*/", "/*!50000SELECT*/"},
	}
	for _, c := range cases {
		tok := newSQLTokenizer(c.input)
		tk := tok.nextToken()
		if tk.kind != sqlComment {
			t.Errorf("input=%q expected comment, got kind=%d text=%q", c.input, tk.kind, tk.text)
			continue
		}
		if tk.text != c.want {
			t.Errorf("input=%q comment=%q, want %q", c.input, tk.text, c.want)
		}
	}
}

func TestSQLSemanticNoFalsePositive(t *testing.T) {
	// 常见误报场景
	innocent := []string{
		"hello world",
		"The union of workers went on strike",
		"Please select your preferred language",
		"How to insert a USB drive",
		"Delete the temporary files",
		"Drop the package at the door",
		"Sleep well tonight",
		"Benchmark your PC",
		"CONCAT(first_name, last_name)",
		"I need to wait for the delay",
		"The sleep study shows...",
		"SELECT * FROM users",
		"INSERT INTO logs VALUES ('ok')",
		"UPDATE users SET name='admin'",
		"CREATE TABLE test (id INT)",
		"ALTER TABLE users ADD COLUMN age INT",
	}
	for _, s := range innocent {
		if r := sqlSemanticMatch(s); r != "" {
			t.Errorf("false positive: sqlSemanticMatch(%q) = %q, want empty", s, r)
		}
	}
}

func BenchmarkSQLSemanticMatch(b *testing.B) {
	inputs := []string{
		"1' UNI/**/ON SEL/**/ECT * FROM users",
		"hello world, this is a normal chat message with no sql",
		"The union of sets A and B is defined as...",
		"1' AND SLEEP(5)--",
		"CONCAT(first_name, ' ', last_name)",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, in := range inputs {
			sqlSemanticMatch(in)
		}
	}
}

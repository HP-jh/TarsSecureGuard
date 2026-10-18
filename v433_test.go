package main

import (
	"strings"
	"testing"
)

// ========== 版本号检查 ==========

func TestV433VersionBumped(t *testing.T) {
	if version != "4.36.0" {
		t.Fatalf("期望版本 4.33.0，实际 %s", version)
	}
}

// ========== 语义分析单元测试 ==========

func TestSqliLexBasic(t *testing.T) {
	toks := sqliLex("SELECT * FROM users WHERE id = 1")
	if len(toks) == 0 {
		t.Fatal("lexer 未切出 token")
	}
	if !sqliHasKeyword(toks, "select") {
		t.Error("缺少 select 关键字")
	}
	if !sqliHasKeyword(toks, "from") {
		t.Error("缺少 from 关键字")
	}
	if !sqliHasKeyword(toks, "where") {
		t.Error("缺少 where 关键字")
	}
}

func TestSqliLexUnclosedQuote(t *testing.T) {
	toks := sqliLex("' UNION SELECT password FROM admins --")
	if len(toks) == 0 {
		t.Fatal("lexer 未切出 token")
	}
	if !sqliHasKeyword(toks, "union") {
		t.Error("未闭合引号后应能识别 union")
	}
	if !sqliHasKeyword(toks, "select") {
		t.Error("未闭合引号后应能识别 select")
	}
}

func TestSqliSemanticUnionSelect(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("' UNION SELECT password FROM admins --")
	if !confirmed {
		t.Fatalf("UNION SELECT 应被确认注入，得分=%d 理由=%s", score, reason)
	}
	if !strings.Contains(reason, "UNION SELECT") {
		t.Errorf("理由应包含 UNION SELECT，实际=%s", reason)
	}
}

func TestSqliSemanticInsertInto(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("'; INSERT INTO logs VALUES (1,2) --")
	if !confirmed {
		t.Fatalf("INSERT INTO 应被确认注入，得分=%d 理由=%s", score, reason)
	}
	if !strings.Contains(reason, "INSERT INTO") {
		t.Errorf("理由应包含 INSERT INTO，实际=%s", reason)
	}
}

func TestSqliSemanticUpdateSet(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("'; UPDATE users SET admin=1 WHERE id=1 --")
	if !confirmed {
		t.Fatalf("UPDATE SET 应被确认注入，得分=%d 理由=%s", score, reason)
	}
	if !strings.Contains(reason, "UPDATE SET") {
		t.Errorf("理由应包含 UPDATE SET，实际=%s", reason)
	}
}

func TestSqliSemanticDeleteFrom(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("'; DELETE FROM users WHERE 1=1 --")
	if !confirmed {
		t.Fatalf("DELETE FROM 应被确认注入，得分=%d 理由=%s", score, reason)
	}
	if !strings.Contains(reason, "DELETE FROM") {
		t.Errorf("理由应包含 DELETE FROM，实际=%s", reason)
	}
}

func TestSqliSemanticBooleanTautology(t *testing.T) {
	cases := []string{
		"admin' AND '1'='1",
		"' OR '1'='1' --",
		"id=1 AND 1=1",
	}
	for _, c := range cases {
		score, confirmed, reason := sqliSemanticCheck(c)
		if !confirmed {
			t.Errorf("布尔恒真式 '%s' 应被确认注入，得分=%d 理由=%s", c, score, reason)
		}
	}
}

func TestSqliSemanticSleepBenchmark(t *testing.T) {
	cases := []string{
		"' OR sleep(5) --",
		"'; benchmark(1000000,md5(1)) --",
	}
	for _, c := range cases {
		score, confirmed, reason := sqliSemanticCheck(c)
		if !confirmed {
			t.Errorf("时间盲注 '%s' 应被确认注入，得分=%d 理由=%s", c, score, reason)
		}
	}
}

func TestSqliSemanticDropTable(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("'; DROP TABLE users --")
	if !confirmed {
		t.Fatalf("DROP TABLE 应被确认注入，得分=%d 理由=%s", score, reason)
	}
	if !strings.Contains(reason, "DROP TABLE") {
		t.Errorf("理由应包含 DROP TABLE，实际=%s", reason)
	}
}

func TestSqliSemanticStackedQuery(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("1'; DELETE FROM logs; --")
	if !confirmed {
		t.Fatalf("堆叠查询应被确认注入，得分=%d 理由=%s", score, reason)
	}
}

func TestSqliSemanticInformationSchema(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("' UNION SELECT table_name FROM information_schema.tables --")
	if !confirmed {
		t.Fatalf("information_schema 探测应被确认注入，得分=%d 理由=%s", score, reason)
	}
}

func TestSqliSemanticLoadFile(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("' UNION SELECT load_file('/etc/passwd') --")
	if !confirmed {
		t.Fatalf("LOAD_FILE 应被确认注入，得分=%d 理由=%s", score, reason)
	}
}

func TestSqliSemanticIntoOutfile(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("' UNION SELECT password INTO OUTFILE '/tmp/p' --")
	if !confirmed {
		t.Fatalf("INTO OUTFILE 应被确认注入，得分=%d 理由=%s", score, reason)
	}
}

func TestSqliSemanticCommentTruncation(t *testing.T) {
	score, confirmed, reason := sqliSemanticCheck("admin'--")
	if !confirmed {
		t.Fatalf("注释截断应被确认注入，得分=%d 理由=%s", score, reason)
	}
}

// ========== 误报白名单测试 ==========

func TestSqliSemanticNoFalsePositive_NumberCompare(t *testing.T) {
	score, confirmed, _ := sqliSemanticCheck("price=100")
	if confirmed {
		t.Fatalf("纯数字比较不应被确认注入，得分=%d", score)
	}
}

func TestSqliSemanticNoFalsePositive_LegitQuery(t *testing.T) {
	score, confirmed, _ := sqliSemanticCheck("For example, SELECT * FROM users is a common query.")
	if confirmed {
		t.Fatalf("文档示例不应被确认注入，得分=%d", score)
	}
}

func TestSqliSemanticNoFalsePositive_UnionCommonWord(t *testing.T) {
	score, confirmed, _ := sqliSemanticCheck("The European Union was founded in 1993.")
	if confirmed {
		t.Fatalf("European Union 不应被确认注入，得分=%d", score)
	}
}

func TestSqliSemanticNoFalsePositive_SimpleParameter(t *testing.T) {
	score, confirmed, _ := sqliSemanticCheck("sort=select")
	if confirmed {
		t.Fatalf("简单参数值不应被确认注入，得分=%d", score)
	}
}

func TestSqliSemanticNoFalsePositive_NormalSentence(t *testing.T) {
	score, confirmed, _ := sqliSemanticCheck("I will select the best option.")
	if confirmed {
		t.Fatalf("正常句子不应被确认注入，得分=%d", score)
	}
}

func TestSqliSemanticNoFalsePositive_CJKContent(t *testing.T) {
	score, confirmed, _ := sqliSemanticCheck("这是一个普通的查询请求")
	if confirmed {
		t.Fatalf("中文内容不应被确认注入，得分=%d", score)
	}
}

// ========== WAF 集成测试 ==========

func TestWAFIntegration_SQLiSemanticConfirm(t *testing.T) {
	reason := wafMatch("' UNION SELECT password FROM admins --", true)
	if reason == "" {
		t.Fatal("WAF 应拦截 UNION SELECT 注入")
	}
	if !strings.Contains(reason, "SQL 注入") {
		t.Errorf("理由应包含 SQL 注入，实际=%s", reason)
	}
}

func TestWAFIntegration_SQLiSemanticDowngrade(t *testing.T) {
	reason := wafMatch("sort=select", true)
	if strings.Contains(reason, "SQL 注入") {
		t.Errorf("简单参数值 sort=select 不应被确认为 SQL 注入，实际=%s", reason)
	}
}

func TestWAFIntegration_SQLiRegexMissSemanticHit(t *testing.T) {
	payload := "1' UnIoN SeLeCt 1,2,3--"
	reason := wafMatch(payload, true)
	if reason == "" {
		t.Fatal("WAF 应通过语义层拦截变形 UNION SELECT 注入")
	}
	if !strings.Contains(reason, "SQL 注入") {
		t.Errorf("理由应包含 SQL 注入，实际=%s", reason)
	}
}

func TestWAFIntegration_SQLiNonStrictNoSemantic(t *testing.T) {
	// non-strict 模式语义层不激活，主要确认不 panic
	_ = wafMatch("' UNION SELECT 1 --", false)
}

// ========== Body 扫描集成测试 ==========

func TestWAFScanBody_SQLiInJSON(t *testing.T) {
	body := []byte(`{"query": "' UNION SELECT password FROM admins --"}`)
	reason := wafScanBody(body, true, false)
	if reason == "" {
		t.Fatal("Body 扫描应检测到 JSON 中的 SQL 注入")
	}
	if !strings.Contains(reason, "SQL 注入") {
		t.Errorf("理由应包含 SQL 注入，实际=%s", reason)
	}
}

// ========== 基准测试 ==========

func BenchmarkSqliLex(b *testing.B) {
	payload := "' UNION SELECT password,email FROM admins WHERE id = 1 AND '1'='1' --"
	for i := 0; i < b.N; i++ {
		_ = sqliLex(payload)
	}
}

func BenchmarkSqliSemanticCheck(b *testing.B) {
	payload := "' UNION SELECT password FROM admins --"
	for i := 0; i < b.N; i++ {
		_, _, _ = sqliSemanticCheck(payload)
	}
}

func BenchmarkWAFMatchWithSemantic(b *testing.B) {
	payload := "' UNION SELECT password FROM admins --"
	for i := 0; i < b.N; i++ {
		_ = wafMatch(payload, true)
	}
}


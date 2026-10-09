package bench

import (
	"context"
	"testing"

	"tarssecureguard-v41/crownext/security"
	"tarssecureguard-v41/crownext/vault"
)

// BenchmarkVaultDerive 计算维度：PBKDF2 密钥派生
func BenchmarkVaultDerive(b *testing.B) {
	v, err := vault.NewKeyVault("/tmp/tsg-bench-vault")
	if err != nil {
		b.Fatal(err)
	}
	defer v.Wipe()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := v.Derive("bench-service")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVaultSealOpen 计算维度：AES-GCM 密封/解封
func BenchmarkVaultSealOpen(b *testing.B) {
	v, err := vault.NewKeyVault("/tmp/tsg-bench-vault-seal")
	if err != nil {
		b.Fatal(err)
	}
	defer v.Wipe()

	key, err := v.Derive("bench-seal")
	if err != nil {
		b.Fatal(err)
	}
	plaintext := []byte("sensitive api key value here for benchmarking purpose")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sealed, err := v.Seal("bench-seal", plaintext)
		if err != nil {
			b.Fatal(err)
		}
		opened, err := v.Open("bench-seal", sealed)
		if err != nil {
			b.Fatal(err)
		}
		_ = opened
		_ = key
	}
}

// BenchmarkSecurityEvaluate 计算维度：安全评分引擎
func BenchmarkSecurityEvaluate(b *testing.B) {
	eng := security.NewScoreEngine()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := eng.Evaluate(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHarnessCompute 用 Harness 汇总计算维度
func BenchmarkHarnessCompute(b *testing.B) {
	h := NewHarness()

	h.Run("Compute/VaultDerive", func(b *testing.B) {
		v, _ := vault.NewKeyVault("/tmp/tsg-bench-h1")
		defer v.Wipe()
		for i := 0; i < b.N; i++ {
			v.Derive("svc")
		}
	})

	h.Run("Compute/VaultSealOpen", func(b *testing.B) {
		v, _ := vault.NewKeyVault("/tmp/tsg-bench-h2")
		defer v.Wipe()
		pt := []byte("api-key-12345678901234567890")
		for i := 0; i < b.N; i++ {
			sealed, _ := v.Seal("svc", pt)
			v.Open("svc", sealed)
		}
	})

	h.Run("Compute/SecurityEvaluate", func(b *testing.B) {
		eng := security.NewScoreEngine()
		ctx := context.Background()
		for i := 0; i < b.N; i++ {
			eng.Evaluate(ctx)
		}
	})

	b.Log("\n" + h.Report())
}

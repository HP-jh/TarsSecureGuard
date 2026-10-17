package bench

import (
	"testing"

	"tarssecureguard-v41/crownext/vault"
)

// BenchmarkSecretStoreSet 存储维度：加密写入
func BenchmarkSecretStoreSet(b *testing.B) {
	v, err := vault.NewKeyVault("/tmp/tsg-bench-store")
	if err != nil {
		b.Fatal(err)
	}
	defer v.Wipe()
	store := vault.NewSecretStore(v)
	value := []byte("database-password-12345")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := "secret-" + string(rune('a'+i%26))
		_, err := store.Set(key, value)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSecretStoreGet 存储维度：解密读取
func BenchmarkSecretStoreGet(b *testing.B) {
	v, err := vault.NewKeyVault("/tmp/tsg-bench-store-get")
	if err != nil {
		b.Fatal(err)
	}
	defer v.Wipe()
	store := vault.NewSecretStore(v)
	value := []byte("database-password-12345")
	sealed, err := store.Set("test-secret", value)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.Get("test-secret", sealed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHarnessStorage 用 Harness 汇总存储维度
func BenchmarkHarnessStorage(b *testing.B) {
	h := NewHarness()

	h.Run("Storage/SecretStoreSet", func(b *testing.B) {
		v, _ := vault.NewKeyVault("/tmp/tsg-bench-hs1")
		defer v.Wipe()
		store := vault.NewSecretStore(v)
		val := []byte("pw-12345")
		for i := 0; i < b.N; i++ {
			store.Set("k", val)
		}
	})

	h.Run("Storage/SecretStoreGet", func(b *testing.B) {
		v, _ := vault.NewKeyVault("/tmp/tsg-bench-hs2")
		defer v.Wipe()
		store := vault.NewSecretStore(v)
		val := []byte("pw-12345")
		sealed, _ := store.Set("k", val)
		for i := 0; i < b.N; i++ {
			store.Get("k", sealed)
		}
	})

	b.Log("\n" + h.Report())
}

// transit.go — 传输加密（目：Ordo-TransitEncrypt）
// 端到端AES-GCM加密 + SHA-256密钥派生
package transit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// Cipher 传输加密器
type Cipher struct {
	key []byte
}

// NewCipher 从共享密钥创建加密器（SHA-256派生固定32字节密钥）
func NewCipher(sharedKey string) *Cipher {
	h := sha256.Sum256([]byte(sharedKey))
	return &Cipher{key: h[:]}
}

// Encrypt 加密明文，返回base64编码的密文
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解密base64编码的密文
func (c *Cipher) Decrypt(ciphertextB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DeriveKey 从密码派生密钥（PBKDF2简化版：单次SHA-256）
func DeriveKey(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}

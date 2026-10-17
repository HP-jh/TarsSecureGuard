// derive.go — Key derivation using PBKDF2 (FIPS-compliant, no external deps).
package vault

import (
	"crypto/sha256"
	"hash"
)

// pbkdf2Derive derives a key from password+salt using PBKDF2-HMAC-SHA256.
func pbkdf2Derive(password, salt []byte, iter, keyLen int) []byte {
	prf := hmacSHA256New(password)
	var buf [4]byte
	dk := make([]byte, 0, keyLen)
	u := make([]byte, prf.Size())
	for block := 1; len(dk) < keyLen; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		digest := prf.Sum(nil)
		copy(u, digest)
		// U_1 XOR U_2 XOR ... XOR U_iter
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(digest)
			digest = prf.Sum(nil)
			for i := range u {
				u[i] ^= digest[i]
			}
		}
		dk = append(dk, u...)
	}
	return dk[:keyLen]
}

// deriveKey derives a service key from master+salt+context.
func deriveKey(master, salt, context []byte) []byte {
	prf := hmacSHA256New(master)
	prf.Write(salt)
	prf.Write(context)
	return prf.Sum(nil)
}

// hmacSHA256New returns an HMAC-SHA256 hasher.
// Self-contained implementation using standard crypto/sha256.
func hmacSHA256New(key []byte) hash.Hash {
	blockSize := 64 // SHA-256 block size
	if len(key) > blockSize {
		h := sha256.New()
		h.Write(key)
		key = h.Sum(nil)
	}
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	copy(ipad, key)
	copy(opad, key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	return &hmac256{ipad: ipad, opad: opad}
}

type hmac256 struct {
	ipad  []byte
	opad  []byte
	inner hash.Hash
	outer hash.Hash
}

func (h *hmac256) init() {
	h.inner = sha256.New()
	h.outer = sha256.New()
	h.inner.Write(h.ipad)
	h.outer.Write(h.opad)
}

func (h *hmac256) Write(p []byte) (int, error) {
	if h.inner == nil {
		h.init()
	}
	return h.inner.Write(p)
}

func (h *hmac256) Sum(b []byte) []byte {
	if h.inner == nil {
		h.init()
	}
	innerHash := h.inner.Sum(nil)
	outerCopy := sha256.New()
	outerCopy.Write(h.opad)
	outerCopy.Write(innerHash)
	return outerCopy.Sum(b)
}

func (h *hmac256) Reset() {
	h.inner = nil
	h.outer = nil
}

func (h *hmac256) Size() int      { return sha256.Size }
func (h *hmac256) BlockSize() int { return sha256.New().BlockSize() }

package main

// oauth-jwt.go —— OAuth id_token 验签的标准库实现（RS256 / ES256）。
// 独立成文件：密码学代码集中一处，便于锦衣卫审计。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
)

// jwtVerifyRS256 JWKS RSA 公钥（n, e base64url）验 RS256 签名
func jwtVerifyRS256(headerB64, payloadB64, sigB64 string, key map[string]interface{}) error {
	nB64, _ := key["n"].(string)
	eB64, _ := key["e"].(string)
	if nB64 == "" || eB64 == "" {
		return errors.New("JWKS RSA 密钥缺少 n/e")
	}
	nBytes, err := b64urlDecode(nB64)
	if err != nil {
		return errors.New("n 解码失败")
	}
	eBytes, err := b64urlDecode(eB64)
	if err != nil {
		return errors.New("e 解码失败")
	}
	if len(eBytes) > 8 {
		return errors.New("e 异常超长")
	}
	var eVal uint64
	for _, b := range eBytes {
		eVal = eVal<<8 | uint64(b)
	}
	if eVal == 0 || eVal > 1<<32 {
		return errors.New("e 值域非法")
	}
	pub := &rsaPublicKeyLike{N: new(big.Int).SetBytes(nBytes), E: int(eVal)}
	sig, err := b64urlDecode(sigB64)
	if err != nil {
		return errors.New("signature 解码失败")
	}
	sum := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	if !rsaVerifyPKCS1v15(pub, sum[:], sig) {
		return errors.New("RS256 签名不匹配")
	}
	return nil
}

// rsaPublicKeyLike 最小 RSA 公钥（避免引入 crypto/rsa 完整依赖面）
type rsaPublicKeyLike struct {
	N *big.Int
	E int
}

// rsaVerifyPKCS1v15 RSASSA-PKCS1-v1_5 with SHA-256（标准库手写实现：
// s^e mod n 还原 EMSA-PKCS1-v1_5 编码块比对——constant-time 比对防时序侧信道）
func rsaVerifyPKCS1v15(pub *rsaPublicKeyLike, hashed, sig []byte) bool {
	k := (pub.N.BitLen() + 7) / 8
	if k < 11 || len(sig) != k {
		return false
	}
	// s^e mod n
	s := new(big.Int).SetBytes(sig)
	if s.Cmp(pub.N) >= 0 {
		return false
	}
	e := big.NewInt(int64(pub.E))
	m := new(big.Int).Exp(s, e, pub.N)
	em := make([]byte, k)
	m.FillBytes(em)
	// EMSA-PKCS1-v1_5：0x00 0x01 FF..FF 0x00 || DigestInfo(SHA-256) || hash
	want := make([]byte, k)
	padLen := k - 3 - len(digestInfoSHA256) - len(hashed)
	if padLen < 8 {
		return false
	}
	want[0], want[1] = 0x00, 0x01
	for i := 2; i < 2+padLen; i++ {
		want[i] = 0xFF
	}
	want[2+padLen] = 0x00 // PS 与 DigestInfo 之间的 0x00 分隔符
	copy(want[3+padLen:], digestInfoSHA256)
	copy(want[k-len(hashed):], hashed)
	return subtle.ConstantTimeCompare(em, want) == 1
}

// digestInfoSHA256 EMSA-PKCS1-v1_5 DigestInfo 前缀（DER，SHA-256）
var digestInfoSHA256 = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

// jwtVerifyES256 JWKS EC P-256 公钥（x, y base64url）验 ES256 签名
func jwtVerifyES256(headerB64, payloadB64, sigB64 string, key map[string]interface{}) error {
	crv, _ := key["crv"].(string)
	if crv != "P-256" {
		return errors.New("仅支持 P-256（ES256）")
	}
	xB64, _ := key["x"].(string)
	yB64, _ := key["y"].(string)
	if xB64 == "" || yB64 == "" {
		return errors.New("JWKS EC 密钥缺少 x/y")
	}
	xBytes, err := b64urlDecode(xB64)
	if err != nil || len(xBytes) != 32 {
		return errors.New("x 解码失败或长度非 32")
	}
	yBytes, err := b64urlDecode(yB64)
	if err != nil || len(yBytes) != 32 {
		return errors.New("y 解码失败或长度非 32")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !elliptic.P256().IsOnCurve(x, y) {
		return errors.New("公钥点不在 P-256 曲线上")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	sig, err := b64urlDecode(sigB64)
	if err != nil || len(sig) != 64 {
		return errors.New("signature 解码失败或长度非 64")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	sum := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return errors.New("ES256 签名不匹配")
	}
	return nil
}

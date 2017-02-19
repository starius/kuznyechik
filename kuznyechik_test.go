package kuznyechik

// The test was taken from kuznyechik.txt from cppcrypto 0.15.
// It is also available in https://www.tc26.ru/standard/draft/GOSTR-rbsh.pdf

import (
	"encoding/hex"
	"testing"
)

func TestKuznyechik(t *testing.T) {
	key, err := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	if err != nil {
		t.Fatalf("failed to decode key for kuznyechik from hex: %s", err)
	}
	k, err := NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create kuznyechik block cipher: %s", err)
	}
	if k.BlockSize() != 16 {
		t.Errorf("want BlockSize=16, got %d", k.BlockSize())
	}
	testCases := []struct {
		plain, crypto string
	}{
		{"1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd"},
		{"00112233445566778899aabbcceeff0a", "b429912c6e0032f9285452d76718d08b"},
		{"112233445566778899aabbcceeff0a00", "f0ca33549d247ceef3f5a5313bd4b157"},
		{"2233445566778899aabbcceeff0a0011", "d0b09ccde830b9eb3a02c4c5aa8ada98"},
	}
	// Encrypt.
	for _, c := range testCases {
		plain, err := hex.DecodeString(c.plain)
		if err != nil {
			t.Fatalf("failed to create plaintext from hex: %s", err)
		}
		crypto := make([]byte, 16)
		k.Encrypt(crypto, plain)
		cryptoHEX := hex.EncodeToString(crypto)
		if cryptoHEX != c.crypto {
			t.Errorf("crypto for %#v: want %s, got %s", c, c.crypto, cryptoHEX)
		}
	}
	// Decrypt.
	for _, c := range testCases {
		crypto, err := hex.DecodeString(c.crypto)
		if err != nil {
			t.Fatalf("failed to create cryptotext from hex: %s", err)
		}
		plain := make([]byte, 16)
		k.Decrypt(plain, crypto)
		plainHEX := hex.EncodeToString(plain)
		if plainHEX != c.plain {
			t.Errorf("plain for %#v: want %s, got %s", c, c.plain, plainHEX)
		}
	}
}

func TestBadKeyLength(t *testing.T) {
	_, err := NewCipher(make([]byte, 64))
	if err == nil {
		t.Fatalf("want error, got success")
	}
	want := "kuznyechik key len: want 32, got 64"
	if err.Error() != want {
		t.Fatalf("want error text %q, got %q", want, err.Error())
	}
}

func catchPanic(f func()) (err interface{}) {
	defer func() {
		err = recover()
	}()
	f()
	return nil
}

func TestBadBlockLength(t *testing.T) {
	k, err := NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("failed to create kuznyechik block cipher: %s", err)
	}
	e := catchPanic(func() {
		k.Encrypt(make([]byte, 16), make([]byte, 15))
	})
	if e == nil {
		t.Fatalf("Expected Encrypt with bad block length to panic")
	}
	e = catchPanic(func() {
		k.Decrypt(make([]byte, 16), make([]byte, 15))
	})
	if e == nil {
		t.Fatalf("Expected Decrypt with bad block length to panic")
	}
}

func BenchmarkNewCipher(b *testing.B) {
	key, err := hex.DecodeString("1e8cbafa6827f6ef0ba6d3aff5b7778797f9e9b74885dee661640e68cc44a934")
	if err != nil {
		b.Fatalf("failed to decode key for kuznyechik from hex: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewCipher(key)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key, err := hex.DecodeString("1e8cbafa6827f6ef0ba6d3aff5b7778797f9e9b74885dee661640e68cc44a934")
	if err != nil {
		b.Fatalf("failed to decode key for kuznyechik from hex: %s", err)
	}
	k, err := NewCipher(key)
	if err != nil {
		b.Fatalf("failed to create kuznyechik block cipher: %s", err)
	}
	plain, err := hex.DecodeString("bbe5cf6c73619525b1ebaea263148bc2")
	if err != nil {
		b.Fatalf("failed to decode plain from hex: %s", err)
	}
	crypto := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Encrypt(crypto, plain)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, err := hex.DecodeString("1e8cbafa6827f6ef0ba6d3aff5b7778797f9e9b74885dee661640e68cc44a934")
	if err != nil {
		b.Fatalf("failed to decode key for kuznyechik from hex: %s", err)
	}
	k, err := NewCipher(key)
	if err != nil {
		b.Fatalf("failed to create kuznyechik block cipher: %s", err)
	}
	crypto, err := hex.DecodeString("938d54d5ecf7b5cc422216ac43390bba")
	if err != nil {
		b.Fatalf("failed to decode plain from hex: %s", err)
	}
	plain := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.Decrypt(plain, crypto)
	}
}

package kuznyechik

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// Based on kuznyechik.cpp from cppcrypto 0.15.
// Original code was written by kerukuro for cppcrypto library
// (http://cppcrypto.sourceforge.net/) and released into public domain.
// Backup: https://gist.github.com/3f43a2c46ba9a4f48836f4f1811a2150

func ls(x1, x2 uint64) (t1, t2 uint64) {
	t1 = t[0][uint8(x1)][0] ^ t[1][uint8(x1>>8)][0] ^ t[2][uint8(x1>>16)][0] ^ t[3][uint8(x1>>24)][0] ^ t[4][uint8(x1>>32)][0] ^ t[5][uint8(x1>>40)][0] ^ t[6][uint8(x1>>48)][0] ^ t[7][uint8(x1>>56)][0] ^ t[8][uint8(x2)][0] ^ t[9][uint8(x2>>8)][0] ^ t[10][uint8(x2>>16)][0] ^ t[11][uint8(x2>>24)][0] ^ t[12][uint8(x2>>32)][0] ^ t[13][uint8(x2>>40)][0] ^ t[14][uint8(x2>>48)][0] ^ t[15][uint8(x2>>56)][0]
	t2 = t[0][uint8(x1)][1] ^ t[1][uint8(x1>>8)][1] ^ t[2][uint8(x1>>16)][1] ^ t[3][uint8(x1>>24)][1] ^ t[4][uint8(x1>>32)][1] ^ t[5][uint8(x1>>40)][1] ^ t[6][uint8(x1>>48)][1] ^ t[7][uint8(x1>>56)][1] ^ t[8][uint8(x2)][1] ^ t[9][uint8(x2>>8)][1] ^ t[10][uint8(x2>>16)][1] ^ t[11][uint8(x2>>24)][1] ^ t[12][uint8(x2>>32)][1] ^ t[13][uint8(x2>>40)][1] ^ t[14][uint8(x2>>48)][1] ^ t[15][uint8(x2>>56)][1]
	return
}

func ils(x1, x2 uint64) (t1, t2 uint64) {
	t1 = it[0][uint8(x1)][0] ^ it[1][uint8(x1>>8)][0] ^ it[2][uint8(x1>>16)][0] ^ it[3][uint8(x1>>24)][0] ^ it[4][uint8(x1>>32)][0] ^ it[5][uint8(x1>>40)][0] ^ it[6][uint8(x1>>48)][0] ^ it[7][uint8(x1>>56)][0] ^ it[8][uint8(x2)][0] ^ it[9][uint8(x2>>8)][0] ^ it[10][uint8(x2>>16)][0] ^ it[11][uint8(x2>>24)][0] ^ it[12][uint8(x2>>32)][0] ^ it[13][uint8(x2>>40)][0] ^ it[14][uint8(x2>>48)][0] ^ it[15][uint8(x2>>56)][0]
	t2 = it[0][uint8(x1)][1] ^ it[1][uint8(x1>>8)][1] ^ it[2][uint8(x1>>16)][1] ^ it[3][uint8(x1>>24)][1] ^ it[4][uint8(x1>>32)][1] ^ it[5][uint8(x1>>40)][1] ^ it[6][uint8(x1>>48)][1] ^ it[7][uint8(x1>>56)][1] ^ it[8][uint8(x2)][1] ^ it[9][uint8(x2>>8)][1] ^ it[10][uint8(x2>>16)][1] ^ it[11][uint8(x2>>24)][1] ^ it[12][uint8(x2>>32)][1] ^ it[13][uint8(x2>>40)][1] ^ it[14][uint8(x2>>48)][1] ^ it[15][uint8(x2>>56)][1]
	return
}

func ilss(x1, x2 uint64) (t1, t2 uint64) {
	t1 = it[0][s[uint8(x1)]][0] ^ it[1][s[uint8(x1>>8)]][0] ^ it[2][s[uint8(x1>>16)]][0] ^ it[3][s[uint8(x1>>24)]][0] ^ it[4][s[uint8(x1>>32)]][0] ^ it[5][s[uint8(x1>>40)]][0] ^ it[6][s[uint8(x1>>48)]][0] ^ it[7][s[uint8(x1>>56)]][0] ^ it[8][s[uint8(x2)]][0] ^ it[9][s[uint8(x2>>8)]][0] ^ it[10][s[uint8(x2>>16)]][0] ^ it[11][s[uint8(x2>>24)]][0] ^ it[12][s[uint8(x2>>32)]][0] ^ it[13][s[uint8(x2>>40)]][0] ^ it[14][s[uint8(x2>>48)]][0] ^ it[15][s[uint8(x2>>56)]][0]
	t2 = it[0][s[uint8(x1)]][1] ^ it[1][s[uint8(x1>>8)]][1] ^ it[2][s[uint8(x1>>16)]][1] ^ it[3][s[uint8(x1>>24)]][1] ^ it[4][s[uint8(x1>>32)]][1] ^ it[5][s[uint8(x1>>40)]][1] ^ it[6][s[uint8(x1>>48)]][1] ^ it[7][s[uint8(x1>>56)]][1] ^ it[8][s[uint8(x2)]][1] ^ it[9][s[uint8(x2>>8)]][1] ^ it[10][s[uint8(x2>>16)]][1] ^ it[11][s[uint8(x2>>24)]][1] ^ it[12][s[uint8(x2>>32)]][1] ^ it[13][s[uint8(x2>>40)]][1] ^ it[14][s[uint8(x2>>48)]][1] ^ it[15][s[uint8(x2>>56)]][1]
	return
}

func isi(val uint64) (res uint64) {
	// Apply "is" byte-by-byte
	var i uint
	for i = 0; i < 64; i += 8 {
		res |= uint64(is[uint8(val>>i)]) << i
	}
	return
}

func f(k00, k01, k10, k11 uint64, i int) (o00, o01, o10, o11 uint64) {
	o10 = k00
	o11 = k01
	k00 ^= c[i][0]
	k01 ^= c[i][1]
	o00, o01 = ls(k00, k01)
	o00 ^= k10
	o01 ^= k11
	return
}

func fk(k00, k01, k10, k11 uint64, ist int) (o00, i01, o10, o11 uint64) {
	var t00, t01, t10, t11 uint64
	for i := 0; i < 8; i += 2 {
		t00, t01, t10, t11 = f(k00, k01, k10, k11, i+ist)
		k00, k01, k10, k11 = f(t00, t01, t10, t11, i+1+ist)
	}
	return k00, k01, k10, k11
}

type kuznyechikCipher struct {
	// erk is used in Encrypt, drk is used in Decrypt.
	erk, drk [10][2]uint64
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("kuznyechik key len: want 32, got %d", len(key))
	}
	k00 := binary.LittleEndian.Uint64(key[0:8])
	k01 := binary.LittleEndian.Uint64(key[8:16])
	k10 := binary.LittleEndian.Uint64(key[16:24])
	k11 := binary.LittleEndian.Uint64(key[24:32])
	k := new(kuznyechikCipher)
	k.erk[0][0] = k00
	k.erk[0][1] = k01
	k.erk[1][0] = k10
	k.erk[1][1] = k11
	k00, k01, k10, k11 = fk(k00, k01, k10, k11, 0)
	k.erk[2][0] = k00
	k.erk[2][1] = k01
	k.erk[3][0] = k10
	k.erk[3][1] = k11
	k00, k01, k10, k11 = fk(k00, k01, k10, k11, 8)
	k.erk[4][0] = k00
	k.erk[4][1] = k01
	k.erk[5][0] = k10
	k.erk[5][1] = k11
	k00, k01, k10, k11 = fk(k00, k01, k10, k11, 16)
	k.erk[6][0] = k00
	k.erk[6][1] = k01
	k.erk[7][0] = k10
	k.erk[7][1] = k11
	k00, k01, k10, k11 = fk(k00, k01, k10, k11, 24)
	k.erk[8][0] = k00
	k.erk[8][1] = k01
	k.erk[9][0] = k10
	k.erk[9][1] = k11
	// drf is based on erk
	k.drk[0] = k.erk[0] // first element is just copied
	for i := 1; i < 10; i++ {
		k.drk[i][0], k.drk[i][1] = ilss(k.erk[i][0], k.erk[i][1])
	}
	return k, nil
}

func (k *kuznyechikCipher) BlockSize() int {
	return 16
}

func (k *kuznyechikCipher) Encrypt(dst, src []byte) {
	if len(src) != 16 || len(dst) != 16 {
		panic(fmt.Sprintf("len(dst)=%d, len(src)=%d", len(dst), len(src)))
	}
	x1 := binary.LittleEndian.Uint64(src[0:8])
	x2 := binary.LittleEndian.Uint64(src[8:16])
	var t1, t2 uint64
	x1 ^= k.erk[0][0]
	x2 ^= k.erk[0][1]
	t1, t2 = ls(x1, x2)
	t1 ^= k.erk[1][0]
	t2 ^= k.erk[1][1]
	x1, x2 = ls(t1, t2)
	x1 ^= k.erk[2][0]
	x2 ^= k.erk[2][1]
	t1, t2 = ls(x1, x2)
	t1 ^= k.erk[3][0]
	t2 ^= k.erk[3][1]
	x1, x2 = ls(t1, t2)
	x1 ^= k.erk[4][0]
	x2 ^= k.erk[4][1]
	t1, t2 = ls(x1, x2)
	t1 ^= k.erk[5][0]
	t2 ^= k.erk[5][1]
	x1, x2 = ls(t1, t2)
	x1 ^= k.erk[6][0]
	x2 ^= k.erk[6][1]
	t1, t2 = ls(x1, x2)
	t1 ^= k.erk[7][0]
	t2 ^= k.erk[7][1]
	x1, x2 = ls(t1, t2)
	x1 ^= k.erk[8][0]
	x2 ^= k.erk[8][1]
	t1, t2 = ls(x1, x2)
	t1 ^= k.erk[9][0]
	t2 ^= k.erk[9][1]
	binary.LittleEndian.PutUint64(dst[0:8], t1)
	binary.LittleEndian.PutUint64(dst[8:16], t2)
}

func (k *kuznyechikCipher) Decrypt(dst, src []byte) {
	if len(src) != 16 || len(dst) != 16 {
		panic(fmt.Sprintf("len(dst)=%d, len(src)=%d", len(dst), len(src)))
	}
	x1 := binary.LittleEndian.Uint64(src[0:8])
	x2 := binary.LittleEndian.Uint64(src[8:16])
	var t1, t2 uint64
	t1, t2 = ilss(x1, x2)
	t1 ^= k.drk[9][0]
	t2 ^= k.drk[9][1]
	x1, x2 = ils(t1, t2)
	x1 ^= k.drk[8][0]
	x2 ^= k.drk[8][1]
	t1, t2 = ils(x1, x2)
	t1 ^= k.drk[7][0]
	t2 ^= k.drk[7][1]
	x1, x2 = ils(t1, t2)
	x1 ^= k.drk[6][0]
	x2 ^= k.drk[6][1]
	t1, t2 = ils(x1, x2)
	t1 ^= k.drk[5][0]
	t2 ^= k.drk[5][1]
	x1, x2 = ils(t1, t2)
	x1 ^= k.drk[4][0]
	x2 ^= k.drk[4][1]
	t1, t2 = ils(x1, x2)
	t1 ^= k.drk[3][0]
	t2 ^= k.drk[3][1]
	x1, x2 = ils(t1, t2)
	x1 ^= k.drk[2][0]
	x2 ^= k.drk[2][1]
	t1, t2 = ils(x1, x2)
	t1 ^= k.drk[1][0]
	t2 ^= k.drk[1][1]
	t1 = isi(t1)
	t2 = isi(t2)
	t1 ^= k.drk[0][0]
	t2 ^= k.drk[0][1]
	binary.LittleEndian.PutUint64(dst[0:8], t1)
	binary.LittleEndian.PutUint64(dst[8:16], t2)
}

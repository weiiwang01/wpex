package analyzer

import (
	"bytes"
	"crypto/rand"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"net"
)

func hash(dst []byte, data ...[]byte) [32]byte {
	hash, _ := blake2s.New256(nil)
	for _, d := range data {
		hash.Write(d)
	}
	return [32]byte(hash.Sum(dst))
}

func mac16(dst []byte, key [16]byte, data ...[]byte) [16]byte {
	mac, _ := blake2s.New128(key[:])
	for _, d := range data {
		mac.Write(d)
	}
	return [16]byte(mac.Sum(dst))
}

func mac32(dst []byte, key [32]byte, data ...[]byte) [16]byte {
	mac, _ := blake2s.New128(key[:])
	for _, d := range data {
		mac.Write(d)
	}
	return [16]byte(mac.Sum(dst))
}

func xaead(dst []byte, key [32]byte, nonce [24]byte, plain []byte, auth []byte) []byte {
	xaead, _ := chacha20poly1305.NewX(key[:])
	return xaead.Seal(dst, nonce[:], plain, auth)
}

func token(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func addrEqual(a1, a2 net.UDPAddr) bool {
	return a1.Port == a2.Port && bytes.Equal(a1.IP, a2.IP) && a1.Zone == a2.Zone
}

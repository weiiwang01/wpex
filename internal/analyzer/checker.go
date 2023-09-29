package analyzer

import (
	"crypto/hmac"
	"encoding/binary"
	"net"
	"time"
)

type macChecker struct {
	secret  [32]byte
	start   time.Time
	pubkeys [][]byte
}

func (c *macChecker) cookie(addr net.UDPAddr) [16]byte {
	ticks := uint64(time.Now().Sub(c.start) / (time.Duration(120) * time.Minute))
	addrBytes, _ := addr.AddrPort().MarshalBinary()
	return mac32(nil, c.secret, binary.BigEndian.AppendUint64(nil, ticks), addrBytes)
}

func (c *macChecker) VerifyMac2(addr net.UDPAddr, message []byte) bool {
	l := len(message)
	mac2 := mac16(nil, c.cookie(addr), message[:l-macSize])
	return hmac.Equal(message[l-macSize:], mac2[:])
}

func (c *macChecker) MatchPubkey(message []byte) []byte {
	if len(message) < 2*macSize {
		return nil
	}
	if len(c.pubkeys) == 0 {
		return nil
	}
	l := len(message)
	mac1 := message[l-2*macSize : l-macSize]
	d := message[:l-2*macSize]
	for _, pubkey := range c.pubkeys {
		key := hash(nil, []byte("mac1----"), pubkey)
		m := mac32(nil, key, d)
		if hmac.Equal(mac1, m[:]) {
			return pubkey
		}
	}
	return nil
}

func (c *macChecker) CreateReply(pubkey []byte, addr net.UDPAddr, msg []byte) ([]byte, error) {
	cookie := c.cookie(addr)
	nonce, err := token(24)
	if err != nil {
		return nil, err
	}
	key := hash(nil, []byte("cookie--"), pubkey)
	reply := make([]byte, 64)
	reply[0] = 3
	copy(reply[4:8], msg[4:8])
	copy(reply[8:32], nonce)
	mac1 := msg[handshakeInitiationSize-2*macSize : handshakeInitiationSize-macSize]
	xaead(reply[:32], key, [24]byte(nonce), cookie[:], mac1)
	return reply, nil
}

func (c *macChecker) RequireCheck() bool {
	return len(c.pubkeys) > 0
}

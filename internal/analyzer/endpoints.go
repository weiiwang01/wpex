package analyzer

import (
	"crypto/hmac"
	"log/slog"
	"net"
	"sync"
	"time"
)

type endpointVerificationStatus int

const (
	illegalEndpoint endpointVerificationStatus = iota
	endpointNotVerified
	endpointPendingVerification
	endpointVerified
)

type unverifiedEndpoint struct {
	cookie [cookieSize]byte
	ttl    time.Time
}

type EndpointChecker struct {
	mu        sync.Mutex
	pubkeys   [][]byte
	endpoints map[string]unverifiedEndpoint
}

func (c *EndpointChecker) cleanup() {
	now := time.Now()
	for addr := range c.endpoints {
		if c.endpoints[addr].ttl.Before(now) {
			slog.Debug("remove expired endpoint cookie", "addr", addr)
			delete(c.endpoints, addr)
		}
	}
}

// CreateReply generate a cookie reply for the handshake initiation message.
func (c *EndpointChecker) CreateReply(addr net.UDPAddr, msg []byte) ([]byte, error) {
	pubkey := c.matchPubkey(msg)
	if pubkey == nil {
		panic("public key not found")
	}
	secret, err := token(32)
	if err != nil {
		return nil, err
	}
	src, err := addr.AddrPort().MarshalBinary()
	if err != nil {
		return nil, err
	}
	cookie := mac32(nil, [32]byte(secret), src)
	nonce, err := token(24)
	if err != nil {
		return nil, err
	}
	key := hash(nil, []byte("cookie--"), pubkey)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpoints[addr.String()] = unverifiedEndpoint{
		cookie: cookie,
		ttl:    time.Now().Add(time.Duration(10) * time.Second),
	}
	reply := make([]byte, 64)
	reply[0] = 3
	copy(reply[4:8], msg[4:8])
	copy(reply[8:32], nonce)
	mac1 := msg[handshakeInitiationSize-2*macSize : handshakeInitiationSize-macSize]
	xaead(reply[:32], key, [24]byte(nonce), cookie[:], mac1)
	return reply, nil
}

func (c *EndpointChecker) matchPubkey(packet []byte) []byte {
	if len(packet) < 2*macSize {
		return nil
	}
	if len(c.pubkeys) == 0 {
		return nil
	}
	l := len(packet)
	mac1 := packet[l-2*macSize : l-macSize]
	d := packet[:l-2*macSize]
	for _, pubkey := range c.pubkeys {
		key := hash(nil, []byte("mac1----"), pubkey)
		m := mac32(nil, key, d)
		if hmac.Equal(mac1, m[:]) {
			return pubkey
		}
	}
	return nil
}

func (c *EndpointChecker) VerifyHandshakeInitiation(addr net.UDPAddr, msg []byte) endpointVerificationStatus {
	if len(c.pubkeys) == 0 {
		return endpointVerified
	}
	logger := slog.With("addr", addr.String())
	pubkey := c.matchPubkey(msg)
	if pubkey == nil {
		logger.Warn("invalid mac1 in handshake initiation")
		return illegalEndpoint
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanup()

	endpoint, ok := c.endpoints[addr.String()]
	if !ok {
		return endpointNotVerified
	}

	mac2 := mac16(nil, endpoint.cookie, msg[:handshakeInitiationSize-macSize])
	if hmac.Equal(msg[handshakeInitiationSize-macSize:], mac2[:]) {
		delete(c.endpoints, addr.String())
		slog.Debug("endpoint verified", "addr", addr.String())
		return endpointVerified
	}
	return endpointPendingVerification
}

func (c *EndpointChecker) VerifyHandshakeResponse(addr net.UDPAddr, msg []byte) bool {
	if len(c.pubkeys) == 0 {
		return true
	}
	logger := slog.With("addr", addr.String())
	pubkey := c.matchPubkey(msg)
	if pubkey == nil {
		logger.Warn("invalid mac1 in handshake response")
		return false
	}
	return true
}

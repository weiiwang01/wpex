package analyzer

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/weiiwang01/wpex/internal/exchange"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	cookieSize              = 16
	macSize                 = 16
	handshakeInitiationSize = 148
	handshakeResponseSize   = 92
	cookieReplySize         = 64
)

type unverifiedEndpoint struct {
	cookie [cookieSize]byte
	ttl    time.Time
}

type unverifiedEndpoints struct {
	mu        sync.Mutex
	endpoints map[string]unverifiedEndpoint
}

func (p *unverifiedEndpoints) cleanup() {
	now := time.Now()
	for addr := range p.endpoints {
		if p.endpoints[addr].ttl.Before(now) {
			slog.Debug("remove expired endpoint cookie", "addr", addr)
			delete(p.endpoints, addr)
		}
	}
}

// CreateReply generate a cookie reply for the handshake initiation message.
func (p *unverifiedEndpoints) CreateReply(addr net.UDPAddr, pubkey []byte, index uint32, mac1 []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cleanup()

	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	mac, err := blake2s.New128(secret)
	if err != nil {
		return nil, err
	}
	src, err := addr.AddrPort().MarshalBinary()
	if err != nil {
		return nil, err
	}
	mac.Write(src)
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	hash, _ := blake2s.New256(nil)
	hash.Write([]byte("cookie--"))
	hash.Write(pubkey)
	aead, err := chacha20poly1305.NewX(hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	cookie := mac.Sum(nil)
	p.endpoints[addr.String()] = unverifiedEndpoint{
		cookie: [16]byte(mac.Sum(nil)),
		ttl:    time.Now().Add(time.Duration(10) * time.Second),
	}
	reply := make([]byte, 64)
	reply[0] = 3
	binary.BigEndian.PutUint32(reply[4:8], index)
	copy(reply[8:32], nonce)
	aead.Seal(reply[:32], nonce, cookie, mac1)
	return reply, nil
}

// Verify verifies the mac2 in the handshake initiation message responding the cookie reply.
// Corresponding cookie will be removed if the verification succeed.
func (p *unverifiedEndpoints) Verify(addr net.UDPAddr, msg []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cleanup()

	endpoint, ok := p.endpoints[addr.String()]
	if !ok {
		return false
	}
	mac2 := msg[148-16:]
	mac, _ := blake2s.New128(endpoint.cookie[:])
	mac.Write(msg[:148-16])
	if hmac.Equal(mac2, mac.Sum(nil)) {
		delete(p.endpoints, addr.String())
		slog.Debug("endpoint verified", "addr", addr.String())
		return true
	}
	slog.Debug("endpoint verification failed", "addr", addr.String())
	return false
}

func (p *unverifiedEndpoints) pendingVerify(addr net.UDPAddr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cleanup()

	_, ok := p.endpoints[addr.String()]
	return ok
}

type WireguardAnalyzer struct {
	table      exchange.ExchangeTable
	publicKeys [][]byte
	unverified unverifiedEndpoints
}

func (t *WireguardAnalyzer) matchPubkey(packet []byte) []byte {
	if len(packet) < 32 {
		return nil
	}
	if len(t.publicKeys) == 0 {
		return nil
	}
	l := len(packet)
	mac1 := packet[l-32 : l-16]
	d := packet[:l-32]
	for _, key := range t.publicKeys {
		hash, err := blake2s.New256(nil)
		if err != nil {
			continue
		}
		hash.Write([]byte("mac1----"))
		hash.Write(key)
		mackey := hash.Sum(nil)
		mac, err := blake2s.New128(mackey)
		if err != nil {
			continue
		}
		mac.Write(d)
		if hmac.Equal(mac1, mac.Sum(nil)) {
			return key
		}
	}
	return nil
}

func (t *WireguardAnalyzer) decodeIndex(index []byte) uint32 {
	return binary.BigEndian.Uint32(index)
}

func (t *WireguardAnalyzer) analyseHandshakeInitiation(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, []byte) {
	logger := slog.With("addr", peer.String())
	if len(packet) != handshakeInitiationSize {
		logger.Warn(fmt.Sprintf("invalid handshake initiation: expected length %d, got %d", handshakeInitiationSize, len(packet)))
		return nil, nil
	}
	sender := t.decodeIndex(packet[4:8])
	if len(t.publicKeys) > 0 {
		pubkey := t.matchPubkey(packet)
		if pubkey == nil {
			logger.Warn("invalid mac1 in handshake initiation")
			return nil, nil
		}
		if !t.table.Contains(peer) {
			mac1Start := handshakeInitiationSize - macSize*2
			mac2Start := mac1Start + macSize
			if !t.unverified.Verify(peer, packet) {
				if t.unverified.pendingVerify(peer) {
					logger.Debug("ignore handshake initiation from endpoint pending verification")
					return nil, nil
				}
				reply, err := t.unverified.CreateReply(peer, pubkey, sender, packet[mac1Start:mac2Start])
				if err != nil {
					logger.Error(fmt.Sprintf("fail to create cookie reply: %s", err))
					return nil, nil
				}
				logger.Debug("send cookie reply to unknown endpoint")
				return []net.UDPAddr{peer}, reply
			} else {
				newPacket := make([]byte, handshakeInitiationSize)
				copy(newPacket, packet[:mac2Start])
				packet = newPacket
			}
		}
	}
	if err := t.table.AddPeerAddr(sender, peer); err != nil {
		logger.Error(fmt.Sprintf("fail to add address: %s", err))
		return nil, nil
	}
	addresses := t.table.ListAddrs(peer)
	slog.Debug("handshake initiation message received", "addr", peer.String(), "sender", sender, "broadcast", len(addresses))
	return addresses, packet
}

func (t *WireguardAnalyzer) analyseHandshakeResponse(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, []byte) {
	logger := slog.With("addr", peer.String())
	if len(packet) != handshakeResponseSize {
		logger.Warn(fmt.Sprintf("invalid handshake response: expected length %d, got %d", handshakeResponseSize, len(packet)))
		return nil, nil
	}
	if len(t.publicKeys) > 0 && t.matchPubkey(packet) == nil {
		logger.Warn("incorrect mac1 in handshake response")
		return nil, nil
	}
	sender := t.decodeIndex(packet[4:8])
	if err := t.table.AddPeerAddr(sender, peer); err != nil {
		logger.Error(fmt.Sprintf("failed to add address: %s", err))
		return nil, nil
	}
	receiverIdx := t.decodeIndex(packet[8:12])
	receiver, err := t.table.GetPeerAddr(receiverIdx)
	slog.Debug("handshake response message received", "addr", peer.String(), "sender", sender, "receiver", receiverIdx, "forward", receiver.String())
	if err != nil {
		logger.Warn(fmt.Sprintf("unknown receiver in handshake response: %s", err))
		return nil, nil
	}
	err = t.table.LinkPeers(sender, receiverIdx)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to link peers: %s", err))
		return nil, nil
	}
	return []net.UDPAddr{receiver}, packet
}

func (t *WireguardAnalyzer) analyseCookieReply(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, []byte) {
	logger := slog.With("addr", peer.String())
	if len(packet) != cookieReplySize {
		logger.Warn(fmt.Sprintf("invalid wireguard cookie reply message: expected length %d, got %d", cookieReplySize, len(packet)))
		return nil, nil
	}
	receiverIdx := t.decodeIndex(packet[4:8])
	receiver, err := t.table.GetPeerAddr(receiverIdx)
	slog.Debug("cookie reply message received", "addr", peer.String(), "receiver", receiver, "forward", receiver.String())
	if err != nil {
		logger.Warn(fmt.Sprintf("unknown receiver in cookie reply: %s", err))
		return nil, nil
	}
	return []net.UDPAddr{receiver}, packet
}

func (t *WireguardAnalyzer) analyseTransportData(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, []byte) {
	logger := slog.With("addr", peer.String())
	receiverIdx := t.decodeIndex(packet[4:8])
	receiver, err := t.table.GetPeerAddr(receiverIdx)
	slog.Log(context.TODO(), slog.LevelDebug-4, "transport data message received", "addr", peer.String(), "receiver", receiverIdx, "forward", receiver.String())
	if err != nil {
		logger.Warn(fmt.Sprintf("unknown receiver in transport data: %s", err))
		return nil, nil
	}
	sender, err := t.table.GetPeerCounterpart(receiverIdx)
	if err != nil {
		logger.Warn(fmt.Sprintf("unknown sender in transport data: %s", err))
		return nil, nil
	}
	addr, err := t.table.GetPeerAddr(sender)
	if err != nil {
		logger.Warn(fmt.Sprintf("no sender address record in transport data: %s", err))
		return nil, nil
	}
	if addr.String() != peer.String() {
		slog.Debug("roaming detected in transport data message", "sender", sender, "before", addr.String(), "after", peer.String())
		err := t.table.UpdatePeerAddr(sender, peer)
		if err != nil {
			logger.Warn(fmt.Sprintf("failed to update sender address: %s", err))
			return nil, nil
		}
	}
	return []net.UDPAddr{receiver}, packet
}

// Analyse updates the exchange table with the source address and returns the forwarding address for this packet.
func (t *WireguardAnalyzer) Analyse(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, []byte) {
	logger := slog.With("addr", peer.String())
	const (
		handshakeInitiationType = iota + 1
		handshakeResponseType
		cookieReplyType
		transportDataType
	)
	if len(packet) < 16 {
		logger.Error("invalid wireguard message: too short")
		return nil, nil
	}
	msgType := int(binary.LittleEndian.Uint32(packet[:4]))
	switch msgType {
	case handshakeInitiationType:
		return t.analyseHandshakeInitiation(packet, peer)
	case handshakeResponseType:
		return t.analyseHandshakeResponse(packet, peer)
	case cookieReplyType:
		return t.analyseCookieReply(packet, peer)
	case transportDataType:
		return t.analyseTransportData(packet, peer)
	default:
		logger.Error("unknown message type")
		return nil, nil
	}
}

func MakeWireguardAnalyzer(publicKeys [][]byte) WireguardAnalyzer {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		panic(fmt.Errorf("failed to generate salt: %w", err))
	}
	return WireguardAnalyzer{
		table:      exchange.MakeExchangeTable(),
		publicKeys: publicKeys,
		unverified: unverifiedEndpoints{endpoints: make(map[string]unverifiedEndpoint)},
	}
}

package analyzer

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/weiiwang01/wpex/internal/bloom"
	"github.com/weiiwang01/wpex/internal/exchange"
	"golang.org/x/crypto/blake2s"
	"log/slog"
	"net"
)

type WireguardAnalyzer struct {
	table      exchange.ExchangeTable
	publicKeys [][]byte
	filter     bloom.Filter
}

func (t *WireguardAnalyzer) verifyMac1(packet []byte) error {
	if len(packet) < 32 {
		return errors.New("mac1 validation failed: data too short")
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
			return fmt.Errorf("failed to calculate blake2s hash: %w", err)
		}
		hash.Write([]byte("mac1----"))
		hash.Write(key)
		mackey := hash.Sum(nil)
		mac, err := blake2s.New128(mackey)
		if err != nil {
			return fmt.Errorf("failed to calculate blake2s mac: %w", err)
		}
		mac.Write(d)
		if hmac.Equal(mac1, mac.Sum(nil)) {
			return nil
		}
	}
	return errors.New("invalid mac1")
}

func (t *WireguardAnalyzer) decodeIndex(index []byte) uint32 {
	return binary.BigEndian.Uint32(index)
}

func (t *WireguardAnalyzer) analyseHandshakeInitiation(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, error) {
	if len(packet) != 148 {
		return nil, fmt.Errorf("invalid handshake initiation message: expected length 148, got %d", len(packet))
	}
	if err := t.verifyMac1(packet); err != nil {
		return nil, err
	}
	if t.filter.Contains(packet) {
		return nil, fmt.Errorf("possible duplicated handshake initiation detected")
	}
	t.filter.Add(packet)
	sender := t.decodeIndex(packet[4:8])
	if err := t.table.AddPeerAddr(sender, peer); err != nil {
		return nil, err
	}
	addresses := t.table.ListAddrs(peer)
	slog.Debug("handshake initiation message received", "addr", peer.String(), "sender", sender, "broadcast", len(addresses))
	return addresses, nil
}

func (t *WireguardAnalyzer) analyseHandshakeResponse(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, error) {
	if len(packet) != 92 {
		return nil, fmt.Errorf("invalid handshake response message: expected length 92, got %d", len(packet))
	}
	if err := t.verifyMac1(packet); err != nil {
		return nil, err
	}
	sender := t.decodeIndex(packet[4:8])
	if err := t.table.AddPeerAddr(sender, peer); err != nil {
		return nil, err
	}
	receiverIdx := t.decodeIndex(packet[8:12])
	receiver, err := t.table.GetPeerAddr(receiverIdx)
	slog.Debug("handshake response message received", "addr", peer.String(), "sender", sender, "receiver", receiverIdx, "forward", receiver.String())
	if err != nil {
		return nil, err
	}
	err = t.table.LinkPeers(sender, receiverIdx)
	if err != nil {
		return nil, err
	}
	return []net.UDPAddr{receiver}, nil
}

func (t *WireguardAnalyzer) analyseCookieReply(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, error) {
	if len(packet) != 48 {
		return nil, fmt.Errorf("invalid wireguard cookie reply message: expected length 48, got %d", len(packet))
	}
	receiverIdx := t.decodeIndex(packet[4:8])
	receiver, err := t.table.GetPeerAddr(receiverIdx)
	slog.Debug("cookie reply message received", "addr", peer.String(), "receiver", receiver, "forward", receiver.String())
	if err != nil {
		return nil, err
	}
	return []net.UDPAddr{receiver}, nil
}

func (t *WireguardAnalyzer) analyseTransportData(packet []byte, peer net.UDPAddr) ([]net.UDPAddr, error) {
	receiverIdx := t.decodeIndex(packet[4:8])
	receiver, err := t.table.GetPeerAddr(receiverIdx)
	slog.Log(context.TODO(), slog.LevelDebug-4, "transport data message received", "addr", peer.String(), "receiver", receiverIdx, "forward", receiver.String())
	if err != nil {
		return nil, err
	}
	sender, err := t.table.GetPeerCounterpart(receiverIdx)
	if err != nil {
		return nil, err
	}
	addr, err := t.table.GetPeerAddr(sender)
	if err != nil {
		return nil, err
	}
	if addr.String() != peer.String() {
		slog.Debug("roaming detected in transport data message", "sender", sender, "before", addr.String(), "after", peer.String())
		err := t.table.UpdatePeerAddr(sender, peer)
		if err != nil {
			return nil, err
		}
	}
	return []net.UDPAddr{receiver}, nil
}

// Analyse updates the exchange table with the source address and returns the forwarding address for this packet.
func (t *WireguardAnalyzer) Analyse(packet []byte, peer net.UDPAddr) (addrs []net.UDPAddr, err error) {
	const (
		handshakeInitiationType = iota + 1
		handshakeResponseType
		cookieReplyType
		transportDataType
	)
	if len(packet) < 16 {
		addrs, err = nil, errors.New("invalid wireguard message: too short")
	}
	msgType := int(binary.LittleEndian.Uint32(packet[:4]))
	typeStr := fmt.Sprintf("%d", msgType)
	var header []byte
	switch msgType {
	case handshakeInitiationType:
		typeStr = "Handshake Initiation"
		addrs, err = t.analyseHandshakeInitiation(packet, peer)
		header = packet
	case handshakeResponseType:
		typeStr = "Handshake Response"
		addrs, err = t.analyseHandshakeResponse(packet, peer)
		header = packet
	case cookieReplyType:
		typeStr = "Cookie Reply"
		addrs, err = t.analyseCookieReply(packet, peer)
		header = packet
	case transportDataType:
		typeStr = "Transport Data"
		addrs, err = t.analyseTransportData(packet, peer)
		header = packet[:16]
	default:
		addrs, err = nil, fmt.Errorf("unknown message type")
	}
	if err != nil {
		slog.Error("error while analysing wireguard message", "error", err, "type", typeStr, "addr", peer.String(), "header", base64.StdEncoding.EncodeToString(header))
	}
	return addrs, err
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
		filter:     bloom.MakeFilter(32*1024*1024, 10, salt),
	}
}

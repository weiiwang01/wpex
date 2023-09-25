package analyzer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/weiiwang01/wpex/internal/exchange"
	"log/slog"
	"net"
)

const (
	cookieSize              = 16
	macSize                 = 16
	handshakeInitiationSize = 148
	handshakeResponseSize   = 92
	cookieReplySize         = 64
)

type WireguardAnalyzer struct {
	table   exchange.ExchangeTable
	checker EndpointChecker
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
	if t.table.Contains(peer) {
		goto send
	}
	switch t.checker.VerifyHandshakeInitiation(peer, packet) {
	case illegalEndpoint:
		return nil, nil
	case endpointNotVerified:
		logger.Debug("send cookie reply to unknown endpoint")
		reply, err := t.checker.CreateReply(peer, packet)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to create cookie reply: %s", err))
			return nil, nil
		}
		return []net.UDPAddr{peer}, reply
	case endpointPendingVerification:
		logger.Debug("ignore handshake initiation from endpoint pending verification")
		return nil, nil
	case endpointVerified:
		newPacket := make([]byte, handshakeInitiationSize)
		copy(newPacket, packet[:handshakeInitiationSize-macSize])
		packet = newPacket
	default:
		panic("unknown endpoint verification status")
	}
send:
	if err := t.table.AddPeerAddr(sender, peer); err != nil {
		logger.Error(fmt.Sprintf("failed to add address: %s", err))
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
	if !t.checker.VerifyHandshakeResponse(peer, packet) {
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

func MakeWireguardAnalyzer(pubkeys [][]byte) WireguardAnalyzer {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		panic(fmt.Errorf("failed to generate salt: %w", err))
	}
	return WireguardAnalyzer{
		table: exchange.MakeExchangeTable(),
		checker: EndpointChecker{
			endpoints: make(map[string]unverifiedEndpoint),
			pubkeys:   pubkeys,
		},
	}
}

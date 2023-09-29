package analyzer

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/weiiwang01/wpex/internal/exchange"
	"log/slog"
	"net"
	"time"
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
	checker macChecker
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

	if t.checker.RequireCheck() {
		pubkey := t.checker.MatchPubkey(packet)
		if pubkey == nil {
			logger.Warn("invalid mac1 in handshake initiation")
			return nil, nil
		}
		mac2Ok := t.checker.VerifyMac2(peer, packet)
		known := t.table.Contains(peer)
		if !mac2Ok && !known {
			logger.Debug("send cookie reply to handshake initiation from unknown endpoint")
			reply, err := t.checker.CreateReply(pubkey, peer, packet)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to create cookie reply: %s", err))
				return nil, nil
			}
			return []net.UDPAddr{peer}, reply
		}
		if mac2Ok {
			logger.Debug("strip mac2 from handshake initiation")
			newPacket := make([]byte, handshakeInitiationSize)
			copy(newPacket, packet[:handshakeInitiationSize-macSize])
			packet = newPacket
		}
	}
	sender := t.decodeIndex(packet[4:8])
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
	if t.checker.RequireCheck() {
		if t.checker.MatchPubkey(packet) == nil {
			logger.Warn("invalid mac1 in handshake response")
			return nil, nil
		}
		if t.checker.VerifyMac2(peer, packet) {
			logger.Debug("strip mac2 from handshake response")
		}
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
	err = t.table.AssociatePeers(sender, receiverIdx)
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
	secret, err := token(32)
	if err != nil {
		panic(fmt.Errorf("failed to generate cookie secret: %w", err))
	}
	return WireguardAnalyzer{
		table: exchange.MakeExchangeTable(),
		checker: macChecker{
			pubkeys: pubkeys,
			secret:  [32]byte(secret),
			start:   time.Now(),
		},
	}
}

package relay

import (
	"github.com/weiiwang01/wpex/internal/analyzer"
	"golang.org/x/time/rate"
	"log/slog"
	"net"
)

type udpPacket struct {
	addr        net.UDPAddr
	data        []byte
	source      net.UDPAddr
	isBroadcast bool
}

type Relay struct {
	send     chan udpPacket
	analyzer analyzer.WireguardAnalyzer
	conn     *net.UDPConn
	limit    *rate.Limiter
}

func (r *Relay) sendUDP() {
	for packet := range r.send {
		if packet.isBroadcast {
			if !r.limit.Allow() {
				slog.Warn("broadcast rate limit exceeded", "src", packet.source.String(), "dst", packet.addr.String())
			}
		}
		_, err := r.conn.WriteToUDP(packet.data, &packet.addr)
		if err != nil {
			slog.Error("error while sending UDP packet", "error", err.Error(), "addr", packet.addr.String())
		}
	}
}

func (r *Relay) receiveUDP() {
	for {
		buf := make([]byte, 1500)
		n, remoteAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			slog.Error("error while receiving UDP packet", "error", err.Error(), "addr", remoteAddr)
			continue
		}
		packet := buf[:n]
		peers, send := r.analyzer.Analyse(packet, *remoteAddr)
		for _, peer := range peers {
			r.send <- udpPacket{addr: peer, data: send, source: *remoteAddr, isBroadcast: len(peers) > 1}
		}
	}
}

// Start starts the wireguard packet relay server.
func Start(conn *net.UDPConn, publicKeys [][]byte, broadcastLimit *rate.Limiter) {
	relay := Relay{
		send:     make(chan udpPacket),
		analyzer: analyzer.MakeWireguardAnalyzer(publicKeys),
		conn:     conn,
		limit:    broadcastLimit,
	}
	for i := 0; i < 4; i++ {
		go relay.sendUDP()
		go relay.receiveUDP()
	}
	select {}
}

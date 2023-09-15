package relay

import (
	"github.com/weiiwang01/wpex/internal/analyzer"
	"log/slog"
	"net"
)

type udpPacket struct {
	addr net.UDPAddr
	data []byte
}

type Relay struct {
	send     chan udpPacket
	analyzer analyzer.WireguardAnalyzer
	conn     *net.UDPConn
}

func (r *Relay) sendUDP() {
	for packet := range r.send {
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
		peers, err := r.analyzer.Analyse(packet, *remoteAddr)
		if err != nil {
			continue
		}
		for _, peer := range peers {
			r.send <- udpPacket{addr: peer, data: packet}
		}
	}
}

// Start starts the wireguard packet relay server.
func Start(conn *net.UDPConn, publicKeys [][]byte) {
	relay := Relay{
		send:     make(chan udpPacket),
		analyzer: analyzer.MakeWireguardAnalyzer(publicKeys),
		conn:     conn,
	}
	for i := 0; i < 4; i++ {
		go relay.sendUDP()
		go relay.receiveUDP()
	}
	select {}
}

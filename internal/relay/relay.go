package relay

import (
	"context"
	"fmt"
	"github.com/weiiwang01/wpex/internal/analyzer"
	"golang.org/x/time/rate"
	"log"
	"log/slog"
	"net"
	"runtime"
	"syscall"
)

type udpPacket struct {
	addr        net.Addr
	data        []byte
	source      net.Addr
	isBroadcast bool
}

type Relay struct {
	send     chan udpPacket
	analyzer analyzer.WireguardAnalyzer
	limit    *rate.Limiter
}

func (r *Relay) relay(conn *net.UDPConn) {
	buf := make([]byte, 65536)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			slog.Error("error while receiving UDP packet", "error", err.Error(), "addr", remoteAddr)
			continue
		}
		packet := buf[:n]
		peers, send := r.analyzer.Analyse(packet, *remoteAddr)
		for _, peer := range peers {
			if len(peers) > 1 {
				if !r.limit.Allow() {
					slog.Warn("broadcast rate limit exceeded", "src", remoteAddr.String(), "dst", peer.String())
					continue
				}
			}
			_, err := conn.WriteToUDP(send, &peer)
			if err != nil {
				slog.Error("error while sending UDP packet", "error", err.Error(), "addr", peer.String())
			}
		}
	}
}

// Start starts the wireguard packet relay server.
func Start(address string, publicKeys [][]byte, broadcastLimit *rate.Limiter) {
	slog.Info("server listening", "addr", address)
	var lc = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) { opErr = control(fd) }); err != nil {
				return err
			}
			return opErr
		},
	}
	relay := Relay{
		send:     make(chan udpPacket),
		analyzer: analyzer.MakeWireguardAnalyzer(publicKeys),
		limit:    broadcastLimit,
	}
	for i := 0; i < runtime.NumCPU(); i++ {
		l, err := lc.ListenPacket(context.Background(), "udp", address)
		if err != nil {
			log.Fatal(fmt.Sprintf("failed to listen on %s: %s", address, err))
		}
		conn := l.(*net.UDPConn)
		go relay.relay(conn)
	}
	select {}
}

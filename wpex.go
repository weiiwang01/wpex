package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/weiiwang01/wpex/internal/relay"
	"golang.org/x/time/rate"
	"log/slog"
	"net"
	"os"
	"strings"
)

var version string

type pubKeys []string

func (ks *pubKeys) String() string {
	return strings.Join(*ks, ",")
}

func (ks *pubKeys) Set(s string) error {
	*ks = append(*ks, s)
	return nil
}

func main() {
	bind := flag.String("bind", "", "address to bind to")
	port := flag.Uint("port", 40000, "port number to listen")
	debug := flag.Bool("debug", false, "enable debug messages")
	trace := flag.Bool("trace", false, "enable trace level debug messages")
	broadcastRate := flag.Uint("broadcast-rate", 0, "broadcast rate limit in packet per second")
	versionFlag := flag.Bool("version", false, "show version number and quit")
	var allows pubKeys
	flag.Var(&allows, "allow", "allow a wireguard public key. --allow can be used multiple times for allowing multiple public keys")
	flag.Parse()
	if *versionFlag {
		fmt.Println("wpex", version)
		os.Exit(0)
	}
	loggingLevel := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: loggingLevel}))
	if *debug {
		loggingLevel.Set(slog.LevelDebug)
	}
	if *trace {
		loggingLevel.Set(slog.LevelDebug - 4)
	}
	slog.SetDefault(logger)
	address := fmt.Sprintf("%s:%d", *bind, *port)
	var allowKeys [][]byte
	for _, allow := range allows {
		k, err := base64.StdEncoding.DecodeString(allow)
		if err != nil || len(k) != 32 {
			panic(fmt.Sprintf("invalid wireguard public key: '%s'", allow))
		}
		logger.Debug("allow wireguard public key", "key", allow)
		allowKeys = append(allowKeys, k)
	}
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		panic(fmt.Sprintf("failed to resolve UDP address: %s", err))
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(fmt.Sprintf("failed to listen on UDP: %s", err))
	}
	logger.Info("server listening", "addr", address)
	limit := rate.Limit(*broadcastRate)
	if *broadcastRate == 0 {
		slog.Debug("broadcast rate limit is set to +Inf")
		limit = rate.Inf
	} else {
		slog.Debug(fmt.Sprintf("broadcast rate limit is set to %d", *broadcastRate))
	}
	relay.Start(conn, allowKeys, rate.NewLimiter(limit, int((*broadcastRate)*5)))
}

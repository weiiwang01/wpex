package exchange

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

type peerInfo struct {
	addr        net.UDPAddr
	ttl         time.Time
	established bool
	counterpart uint32
}

// ExchangeTable is a concurrency-safe table that maintains wireguard peer information.
type ExchangeTable struct {
	table map[uint32]peerInfo
	lock  sync.RWMutex
}

// AddPeerAddr adds a new peer's endpoint address to the exchange table
// and automatically removes expired peer information.
func (t *ExchangeTable) AddPeerAddr(index uint32, addr net.UDPAddr) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	now := time.Now()
	for index, peer := range t.table {
		if now.After(peer.ttl) {
			slog.Debug("remove expired peer information", "index", index)
			delete(t.table, index)
		}
	}

	if _, ok := t.table[index]; ok {
		return fmt.Errorf("peer index collision detected on %d", index)
	}

	t.table[index] = peerInfo{
		addr: addr,
		ttl:  time.Now().Add(4 * time.Minute),
	}

	slog.Debug("exchange table updated", "entries", len(t.table))
	return nil
}

// UpdatePeerAddr updates the endpoint address of a peer given its index.
func (t *ExchangeTable) UpdatePeerAddr(index uint32, addr net.UDPAddr) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	peer, ok := t.table[index]
	if !ok {
		return fmt.Errorf("failed to update: unknown peer %d", index)
	}

	peer.addr = addr
	t.table[index] = peer
	return nil
}

// GetPeerAddr retrieves the endpoint address of a peer using its index.
func (t *ExchangeTable) GetPeerAddr(index uint32) (net.UDPAddr, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	peer, ok := t.table[index]
	if !ok {
		return net.UDPAddr{}, fmt.Errorf("unknown peer %d", index)
	}

	return peer.addr, nil
}

// ListAddrs returns all known endpoint addresses from the exchange table.
func (t *ExchangeTable) ListAddrs(exclude net.UDPAddr) []net.UDPAddr {
	t.lock.RLock()
	defer t.lock.RUnlock()

	var addrs []net.UDPAddr
	excludes := map[string]struct{}{
		exclude.String(): {},
	}

	for _, peer := range t.table {
		addrStr := peer.addr.String()
		if _, ok := excludes[addrStr]; !ok {
			addrs = append(addrs, peer.addr)
			excludes[addrStr] = struct{}{}
		}
	}

	return addrs
}

// LinkPeers associates two peers in the same wireguard session.
// After linking, the counterpart peer can be retrieved using GetPeerCounterpart.
func (t *ExchangeTable) LinkPeers(sender, receiver uint32) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	s, ok := t.table[sender]
	if !ok {
		return fmt.Errorf("failed to link peers: unknown sender %d", sender)
	}

	r, ok := t.table[receiver]
	if !ok {
		return fmt.Errorf("failed to link peers: unknown receiver %d", receiver)
	}

	s.established = true
	s.counterpart = receiver
	t.table[sender] = s

	r.established = true
	r.counterpart = sender
	r.ttl = s.ttl
	t.table[receiver] = r

	return nil
}

// GetPeerCounterpart retrieves the counterpart of a given peer from the same session.
func (t *ExchangeTable) GetPeerCounterpart(index uint32) (uint32, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	peer, ok := t.table[index]
	if !ok || !peer.established {
		return 0, fmt.Errorf("peer %d has no counterpart", index)
	}

	return peer.counterpart, nil
}

func MakeExchangeTable() ExchangeTable {
	return ExchangeTable{
		table: make(map[uint32]peerInfo),
	}
}

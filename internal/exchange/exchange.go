package exchange

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	endpointTTL  = 1 * time.Minute
	handshakeTTL = 5 * time.Second
	sessionTTL   = 3 * time.Minute
)

type endpointInfo struct {
	refs      int
	addr      net.UDPAddr
	expiredAt time.Time
}

func (e *endpointInfo) isExpired() bool {
	if e.refs <= 0 && e.expiredAt.Before(time.Now()) {
		return true
	}
	return false
}

type peerInfo struct {
	index       uint32
	addr        *endpointInfo
	established bool
	counterpart uint32
	expiredAt   time.Time
}

func (p *peerInfo) isExpired() bool {
	return p.isExpiredAt(time.Now())
}

func (p *peerInfo) isExpiredAt(t time.Time) bool {
	if p.expiredAt.Before(t) {
		return true
	}
	return false
}

// ExchangeTable is a concurrency-safe table that maintains wireguard peer information.
type ExchangeTable struct {
	mu        sync.RWMutex
	endpoints map[string]*endpointInfo
	peers     map[uint32]peerInfo
}

func (t *ExchangeTable) refEndpoint(addr net.UDPAddr) *endpointInfo {
	addrStr := addr.String()
	e, ok := t.endpoints[addrStr]
	if ok {
		e.refs += 1
		return e
	}
	e = &endpointInfo{
		addr: addr,
		refs: 1,
	}
	t.endpoints[addrStr] = e
	return e
}

func (t *ExchangeTable) derefEndpoint(endpoint *endpointInfo) {
	endpoint.refs -= 1
	if endpoint.refs <= 0 {
		endpoint.expiredAt = time.Now().Add(endpointTTL)
	}
}

func (t *ExchangeTable) cleanup() {
	now := time.Now()
	for index, peer := range t.peers {
		if peer.isExpiredAt(now) {
			slog.Debug("remove expired peer information", "index", index)
			t.derefEndpoint(peer.addr)
			delete(t.peers, index)
		}
	}
	for addr, endpoint := range t.endpoints {
		if endpoint.isExpired() {
			slog.Debug("remove expired endpoint information", "addr", addr)
			delete(t.endpoints, addr)
		}
	}
}

// AddPeerAddr adds a new peer's endpoint address to the exchange table.
func (t *ExchangeTable) AddPeerAddr(index uint32, addr net.UDPAddr) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.cleanup()
	if _, ok := t.peers[index]; ok {
		return fmt.Errorf("peer index collision detected on %d", index)
	}
	t.peers[index] = peerInfo{
		index:       index,
		addr:        t.refEndpoint(addr),
		established: false,
		counterpart: 0,
		expiredAt:   time.Now().Add(handshakeTTL),
	}
	return nil
}

// UpdatePeerAddr updates the endpoint address of a peer given its index.
func (t *ExchangeTable) UpdatePeerAddr(index uint32, addr net.UDPAddr) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.cleanup()
	peer, ok := t.peers[index]
	if !ok {
		return fmt.Errorf("failed to update: peer %d not found", index)
	}
	t.derefEndpoint(peer.addr)
	peer.addr = t.refEndpoint(addr)
	t.peers[index] = peer
	return nil
}

// GetPeerAddr retrieves the endpoint address of a peer using its index.
func (t *ExchangeTable) GetPeerAddr(index uint32) (net.UDPAddr, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peer, ok := t.peers[index]
	if !ok || peer.isExpired() {
		return net.UDPAddr{}, fmt.Errorf("peer %d not found", index)
	}
	return peer.addr.addr, nil
}

// ListAddrs returns all known endpoint addresses from the exchange table.
func (t *ExchangeTable) ListAddrs(exclude net.UDPAddr) []net.UDPAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var addrs []net.UDPAddr
	for _, endpoint := range t.endpoints {
		if !endpoint.isExpired() && endpoint.addr.String() != exclude.String() {
			addrs = append(addrs, endpoint.addr)
		}
	}
	return addrs
}

// AssociatePeers associates two peers in the same wireguard session.
// After linking, the counterpart peer can be retrieved using GetPeerCounterpart.
func (t *ExchangeTable) AssociatePeers(sender, receiver uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.cleanup()
	s, ok := t.peers[sender]
	if !ok {
		return fmt.Errorf("failed to associate peers: sender %d not found", sender)
	}

	r, ok := t.peers[receiver]
	if !ok {
		return fmt.Errorf("failed to associate peers: receiver %d not found", receiver)
	}

	if s.established && r.established && s.counterpart == receiver && r.counterpart == sender {
		return nil
	}

	if s.established || r.established {
		return fmt.Errorf("sender or receiver has already been assoicated with another peer")
	}

	expiredAt := time.Now().Add(sessionTTL)
	s.established = true
	s.counterpart = receiver
	s.expiredAt = expiredAt
	t.peers[sender] = s

	r.established = true
	r.counterpart = sender
	r.expiredAt = expiredAt
	t.peers[receiver] = r

	return nil
}

// GetPeerCounterpart retrieves the counterpart of a given peer from the same session.
func (t *ExchangeTable) GetPeerCounterpart(index uint32) (uint32, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peer, ok := t.peers[index]
	if !ok || !peer.established || peer.isExpired() {
		return 0, fmt.Errorf("peer %d doesn't exist or has no counterpart", index)
	}

	return peer.counterpart, nil
}

// Contains checks if an address exists in the exchange table.
func (t *ExchangeTable) Contains(addr net.UDPAddr) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	endpoint, ok := t.endpoints[addr.String()]
	if !ok || endpoint.isExpired() {
		return false
	}
	return true
}

func MakeExchangeTable() ExchangeTable {
	return ExchangeTable{
		endpoints: make(map[string]*endpointInfo),
		peers:     make(map[uint32]peerInfo),
	}
}

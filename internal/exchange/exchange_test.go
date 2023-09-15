package exchange

import (
	"net"
	"slices"
	"testing"
	"time"
)

func TestExchangeTable_AddPeerAddr(t *testing.T) {
	table := MakeExchangeTable()
	index := uint32(1)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	now := time.Now()
	if err := table.AddPeerAddr(index, *addr); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	if len(table.table) != 1 {
		t.Errorf("incorrect number of peers in table, expected 1, got %d", len(table.table))
	}
	peer := table.table[index]
	if peer.addr.String() != addr.String() {
		t.Errorf("incorrect address of peer, expected %s, got %s", addr.String(), peer.addr.String())
	}
	if err := table.AddPeerAddr(1, *addr); err == nil {
		t.Errorf("AddPeerAddr didn't return error when adding an existing peer")
	}
	if !peer.ttl.After(now) {
		t.Errorf("incorrect ttl of peer")
	}
}

func TestExchangeTable_GetPeerAddr(t *testing.T) {
	table := MakeExchangeTable()
	index := uint32(1)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	if err := table.AddPeerAddr(index, *addr); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	gotAddr, err := table.GetPeerAddr(index)
	if err != nil {
		t.Errorf("GetPeerAddr failed: %v", err)
	}
	if gotAddr.String() != addr.String() {
		t.Errorf("incorrect address of peer, expected %s, got %s", addr.String(), gotAddr.String())
	}
	_, err = table.GetPeerAddr(0)
	if err == nil {
		t.Errorf("GetPeerAddr didn't return error when accessing an unknown peer")
	}
}

func TestExchangeTable_GetPeerCounterpart(t *testing.T) {
	table := MakeExchangeTable()
	index1 := uint32(1)
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	index2 := uint32(2)
	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51821")
	index3 := uint32(3)
	addr3, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51822")
	if err := table.AddPeerAddr(index1, *addr1); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	if err := table.AddPeerAddr(index2, *addr2); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	if err := table.AddPeerAddr(index3, *addr3); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	if err := table.LinkPeers(index1, index2); err != nil {
		t.Errorf("LinkPeers failed: %v", err)
	}
	c1, err := table.GetPeerCounterpart(index1)
	if err != nil {
		t.Errorf("GetPeerCounterpart failed: %v", err)
	}
	c2, err := table.GetPeerCounterpart(index2)
	if err != nil {
		t.Errorf("GetPeerCounterpart failed: %v", err)
	}
	if c1 != index2 || c2 != index1 {
		t.Errorf("GetPeerCounterpart didn't return correct counterpart")
	}
	if _, err := table.GetPeerCounterpart(index3); err == nil {
		t.Errorf("GetPeerCounterpart didn't return error when retrieve an unknown counterpart")
	}
}

func TestExchangeTable_LinkPeers(t *testing.T) {
	table := MakeExchangeTable()
	index1 := uint32(1)
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	index2 := uint32(2)
	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51821")
	if err := table.AddPeerAddr(index1, *addr1); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	if err := table.AddPeerAddr(index2, *addr2); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	if err := table.LinkPeers(index1, index2); err != nil {
		t.Errorf("LinkPeers failed: %v", err)
	}
	peer1, ok1 := table.table[index1]
	peer2, ok2 := table.table[index2]
	if !ok1 || !ok2 {
		t.Errorf("AddPeerAddr failed, peer doesn't exist in the table")
	}
	if peer1.ttl != peer2.ttl {
		t.Errorf("linked peers don't have same ttl")
	}
	if !peer1.established || !peer2.established {
		t.Errorf("linked peers don't have correct established status")
	}
}

func TestExchangeTable_ListAddrs(t *testing.T) {
	table := MakeExchangeTable()
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51821")

	if err := table.AddPeerAddr(1, *addr1); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	mapAddrs := func(as []net.UDPAddr) []string {
		var strs []string
		for _, a := range as {
			strs = append(strs, a.String())
		}
		slices.Sort(strs)
		return strs
	}
	got := mapAddrs(table.ListAddrs(net.UDPAddr{}))
	expected := []string{"127.0.0.1:51820"}
	if !slices.Equal(got, expected) {
		t.Errorf("ListAddrs returns incorrect values, expected %s, got %s", got, expected)
	}
	got = mapAddrs(table.ListAddrs(*addr1))
	expected = []string{}
	if !slices.Equal(got, expected) {
		t.Errorf("ListAddrs returns incorrect values, expected %s, got %s", got, expected)
	}
	if err := table.AddPeerAddr(2, *addr2); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	got = mapAddrs(table.ListAddrs(*addr1))
	expected = []string{"127.0.0.1:51821"}
	if !slices.Equal(got, expected) {
		t.Errorf("ListAddrs returns incorrect values, expected %s, got %s", got, expected)
	}
	got = mapAddrs(table.ListAddrs(net.UDPAddr{}))
	expected = []string{"127.0.0.1:51820", "127.0.0.1:51821"}
	if !slices.Equal(got, expected) {
		t.Errorf("ListAddrs returns incorrect values, expected %s, got %s", got, expected)
	}
}

func TestExchangeTable_UpdatePeerAddr(t *testing.T) {
	table := MakeExchangeTable()
	index1 := uint32(1)
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	addr12, _ := net.ResolveUDPAddr("udp", "127.0.0.2:51820")
	index2 := uint32(2)
	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51821")
	if err := table.AddPeerAddr(index1, *addr1); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	if err := table.AddPeerAddr(index2, *addr2); err != nil {
		t.Errorf("AddPeerAddr failed: %v", err)
	}
	if err := table.UpdatePeerAddr(index1, *addr12); err != nil {
		t.Errorf("UpdatePeerAddr failed: %v", err)
	}
	got, err := table.GetPeerAddr(index1)
	if err != nil {
		t.Errorf("GetPeerAddr failed: %v", err)
	}
	if got.String() != addr12.String() {
		t.Errorf("update address failed, expected %s, got %s", addr12.String(), got.String())
	}
}

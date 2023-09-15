package analyzer

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"slices"
	"testing"
)

// data obtained from https://gitlab.com/wireshark/wireshark/-/commit/cf9f1cac07130e3da2ef5e51c9232b7c206dcde2
// and https://gitlab.com/wireshark/wireshark/-/commit/e7549372515dbef74f4764a36a6b1a408087cf59
var (
	handshakeInitiationSession1AtoB, _ = hex.DecodeString("01000000d837d0305fcec7c8e5c8e2e3f7989eef60c228d82329d602b6b1e2bb9d068f89cf9d4d4532780f6d27264f7b98701fdc27a4ec00aeb6becdbef2332f1b4084cadb93823935c012ae255e7b25eff13940c321fa6bd66a2a87b061db1430173e937f569349de2856dc5f2616763eeeafc0533b01dd965e7ec76976e28f683d671200000000000000000000000000000000")
	handshakeResponseSession1BtoA, _   = hex.DecodeString("0200000006f47dabd837d030b18d5550bd4042a37a46823ac08db1ec66839bc0ca2d64bc15cd80232b66232faec24af8918de1060ff5c98e865d5f35f272214c5260110dc4c61e32cdd8542100000000000000000000000000000000")
	transportDataSession1AtoB1, _      = hex.DecodeString("0400000006f47dab0000000000000000a4ebc12ee3f990da18033a0789c04e2700f6f5c271d42ac4b4d6262e666549b445a7436e829bffb6ac65f05648bc0c391fe7c5884874376127164940188f03dba67af8388eaab76c593628bf9dc7be03346d912e916dad862545454701364f2d2486d7ced4c8642ce547ddb26ef6a46b")
	transportDataSession1BtoA1, _      = hex.DecodeString("04000000d837d03000000000000000006f4f080e9f52691bbe948535f79c13ed68f09145d523eedb087265f968082f70735729263eda627c7683cdc0b80a3356d9536c9f0e2872797b5c81720ba0b8ea7233c6debf9f0fbee8f10ec18985b824bf350f8b8180d08a64e6be9810089ac3d1363ed5e129ca1e0425cf7e94965659")
	handshakeInitiationSession2AtoB, _ = hex.DecodeString("01000000c541fdbfa1e1ef034d269e52fcda161747e7d7b412165ff3f723ebd205e32b4a87868634d68aad0acd87497bd55230e66ffdeddbb797385abb5e6cf7197083f51999ac2e480ab650bc4ed6329f127b9e6c2074ec13cb3a822bc26ad2f8543988c4247222903c8f56a16019cb88cb7bd99534e87298e2dd3735e7bc33e907895200000000000000000000000000000000")
	pubkeyA, _                         = base64.StdEncoding.DecodeString("Igge9KzRytKNwrgkzDE/8hrLu6Ly0OqVdvOPWhA5KR4=")
	pubkeyB, _                         = base64.StdEncoding.DecodeString("YDCttCs9e1J52/g9vEnwJJa+2x6RqaayAYMpSVQfGEY=")
	fakePubkey, _                      = base64.StdEncoding.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	handshakeInitiationCtoD, _         = hex.DecodeString("01000000029c03c1f30ceb67148dd27c78d52d0196b6b78b71542986f563ac898879353f022f174770c5b3d433cfb49fd3311688284ce67ec72111e655129fc5f6bed2e0a44b8d28c222c6e1479a0833c7a1f6417b733c1ef049fab5e451aff561ea428c2116f7d1023ccdac2b2a00ecbe0273c9f84b1c695032084b58e7d2ff9fcf19fd00000000000000000000000000000000")
)

func mapAddrs(as []net.UDPAddr) []string {
	var strs []string
	for _, a := range as {
		strs = append(strs, a.String())
	}
	slices.Sort(strs)
	return strs
}

func TestWireguardAnalyzer_VerifyMac1(t *testing.T) {
	analyzer := MakeWireguardAnalyzer([][]byte{pubkeyA, pubkeyB})
	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	_, err := analyzer.Analyse(handshakeInitiationSession1AtoB, *addr1)
	if err != nil {
		t.Errorf("mac1 verification failed: %v", err)
	}
	analyzer = MakeWireguardAnalyzer([][]byte{fakePubkey})
	_, err = analyzer.Analyse(handshakeInitiationSession1AtoB, *addr1)
	if err == nil {
		t.Errorf("mac1 verification didn't fail")
	}
}

func TestWireguardAnalyzer_Handshake(t *testing.T) {
	analyzer := MakeWireguardAnalyzer([][]byte{})

	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51821")
	addrC, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51822")

	forward, err := analyzer.Analyse(handshakeInitiationSession1AtoB, *addrA)
	if err != nil {
		t.Errorf("Analysing handshake initiation failed: %v", err)
	}
	var expected []string
	if !slices.Equal(mapAddrs(forward), expected) {
		t.Errorf("Analysing handshake initiation return incorrect forward addresses: expected %s, got %s", expected, mapAddrs(forward))
	}

	expected = []string{addrA.String()}
	forward, err = analyzer.Analyse(handshakeInitiationSession2AtoB, *addrB)
	if err != nil {
		t.Errorf("Analysing handshake initiation failed: %v", err)
	}
	if !slices.Equal(mapAddrs(forward), expected) {
		t.Errorf("Analysing handshake initiation return incorrect forward addresses: expected %s, got %s", expected, mapAddrs(forward))
	}

	expected = []string{addrA.String(), addrB.String()}
	forward, err = analyzer.Analyse(handshakeInitiationCtoD, *addrC)
	if err != nil {
		t.Errorf("Analysing handshake initiation failed: %v", err)
	}
	if !slices.Equal(mapAddrs(forward), expected) {
		t.Errorf("Analysing handshake initiation return incorrect forward addresses: expected %s, got %s", expected, mapAddrs(forward))
	}

	expected = []string{addrA.String()}
	forward, err = analyzer.Analyse(handshakeResponseSession1BtoA, *addrB)
	if err != nil {
		t.Errorf("Analysing handshake response failed: %v", err)
	}
	if !slices.Equal(mapAddrs(forward), expected) {
		t.Errorf("Analysing handshake response return incorrect forward addresses: expected %s, got %s", expected, mapAddrs(forward))
	}

	expected = []string{addrB.String()}
	forward, err = analyzer.Analyse(transportDataSession1AtoB1, *addrA)
	if err != nil {
		t.Errorf("Analysing transport data failed: %v", err)
	}
	if !slices.Equal(mapAddrs(forward), expected) {
		t.Errorf("Analysing transport data return incorrect forward addresses: expected %s, got %s", expected, mapAddrs(forward))
	}

	expected = []string{addrA.String()}
	forward, err = analyzer.Analyse(transportDataSession1BtoA1, *addrB)
	if err != nil {
		t.Errorf("Analysing transport data failed: %v", err)
	}
	if !slices.Equal(mapAddrs(forward), expected) {
		t.Errorf("Analysing transport data return incorrect forward addresses: expected %s, got %s", expected, mapAddrs(forward))
	}
}

func TestWireguardAnalyzer_Roaming(t *testing.T) {
	analyzer := MakeWireguardAnalyzer([][]byte{})

	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51820")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51821")
	addrA2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:51822")

	if _, err := analyzer.Analyse(handshakeInitiationSession1AtoB, *addrA); err != nil {
		t.Errorf("Analysing handshake initiation failed: %v", err)
	}
	if _, err := analyzer.Analyse(handshakeResponseSession1BtoA, *addrB); err != nil {
		t.Errorf("Analysing handshake initiation failed: %v", err)
	}

	expected := []string{addrB.String()}
	forward, err := analyzer.Analyse(transportDataSession1AtoB1, *addrA2)
	if err != nil {
		t.Errorf("Analysing transport data failed: %v", err)
	}
	if !slices.Equal(mapAddrs(forward), expected) {
		t.Errorf("Analysing transport data return incorrect forward addresses: expected %s, got %s", expected, mapAddrs(forward))
	}

	expected = []string{addrA2.String()}
	forward, err = analyzer.Analyse(transportDataSession1BtoA1, *addrB)
	if err != nil {
		t.Errorf("Analysing transport data failed: %v", err)
	}
	if !slices.Equal(mapAddrs(forward), expected) {
		t.Errorf("Analysing transport data return incorrect forward addresses after roaming: expected %s, got %s", expected, mapAddrs(forward))
	}
}

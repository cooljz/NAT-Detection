// NAT behavior discovery per RFC 4787 / RFC 5780 (UDP, IPv4, standard library only).
//
// Usage: go run nat_detect.go [-server host:port]
//
// The STUN server must support RFC 5780 (OTHER-ADDRESS and CHANGE-REQUEST).
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	magic          = 0x2112A442
	typeBindingReq = 0x0001
	typeBindingOK  = 0x0101
	attrMapped     = 0x0001
	attrChangeReq  = 0x0003
	attrChanged    = 0x0005 // RFC 3489 name for OTHER-ADDRESS
	attrXorMapped  = 0x0020
	attrOther      = 0x802C
	flagChangeIP   = 0x04
	flagChangePort = 0x02

	ei  = "Endpoint-Independent"
	ad  = "Address-Dependent"
	apd = "Address and Port-Dependent"
)

type reply struct {
	mapped *net.UDPAddr
	other  *net.UDPAddr
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func buildRequest(flags uint32) ([]byte, [12]byte) {
	var txid [12]byte
	rand.Read(txid[:])
	attrLen := 0
	if flags != 0 {
		attrLen = 8
	}
	buf := make([]byte, 20, 20+attrLen)
	binary.BigEndian.PutUint16(buf[0:], typeBindingReq)
	binary.BigEndian.PutUint16(buf[2:], uint16(attrLen))
	binary.BigEndian.PutUint32(buf[4:], magic)
	copy(buf[8:], txid[:])
	if flags != 0 {
		var a [8]byte
		binary.BigEndian.PutUint16(a[0:], attrChangeReq)
		binary.BigEndian.PutUint16(a[2:], 4)
		binary.BigEndian.PutUint32(a[4:], flags)
		buf = append(buf, a[:]...)
	}
	return buf, txid
}

func parseAddr(v []byte, xor bool) *net.UDPAddr {
	if len(v) < 8 || v[1] != 1 {
		return nil
	}
	port := binary.BigEndian.Uint16(v[2:4])
	ip := make(net.IP, 4)
	copy(ip, v[4:8])
	if xor {
		port ^= uint16(magic >> 16)
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], magic)
		for i := range ip {
			ip[i] ^= c[i]
		}
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}
}

func parseReply(data []byte, txid [12]byte) *reply {
	if len(data) < 20 ||
		binary.BigEndian.Uint16(data[0:]) != typeBindingOK ||
		binary.BigEndian.Uint32(data[4:]) != magic ||
		!bytes.Equal(data[8:20], txid[:]) {
		return nil
	}
	end := 20 + int(binary.BigEndian.Uint16(data[2:]))
	if end > len(data) {
		end = len(data)
	}
	r := &reply{}
	var plain *net.UDPAddr
	for pos := 20; pos+4 <= end; {
		t := binary.BigEndian.Uint16(data[pos:])
		l := int(binary.BigEndian.Uint16(data[pos+2:]))
		if pos+4+l > end {
			break
		}
		v := data[pos+4 : pos+4+l]
		switch t {
		case attrXorMapped:
			r.mapped = parseAddr(v, true)
		case attrMapped:
			plain = parseAddr(v, false)
		case attrOther, attrChanged:
			r.other = parseAddr(v, false)
		}
		pos += 4 + ((l + 3) &^ 3) // attributes are padded to 4 bytes
	}
	if r.mapped == nil {
		r.mapped = plain
	}
	if r.mapped == nil {
		return nil
	}
	return r
}

// transact sends a Binding Request and waits for a matching reply (1 s per try).
// The socket is unconnected, so replies from another IP/port are accepted.
func transact(conn *net.UDPConn, dst *net.UDPAddr, flags uint32, tries int) *reply {
	req, txid := buildRequest(flags)
	buf := make([]byte, 2048)
	for i := 0; i < tries; i++ {
		if _, err := conn.WriteToUDP(req, dst); err != nil {
			return nil
		}
		deadline := time.Now().Add(time.Second)
		for {
			conn.SetReadDeadline(deadline)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if r := parseReply(buf[:n], txid); r != nil {
				return r
			}
		}
	}
	return nil
}

func sameAddr(a, b *net.UDPAddr) bool {
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

func localIP(server *net.UDPAddr) net.IP {
	c, err := net.DialUDP("udp4", nil, server)
	if err != nil {
		return nil
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP
}

// detectMapping is RFC 5780 section 4.3. Every probe uses the same socket.
func detectMapping(conn *net.UDPConn, server *net.UDPAddr, r1 *reply) string {
	altIP := &net.UDPAddr{IP: r1.other.IP, Port: server.Port} // other IP, primary port
	r2 := transact(conn, altIP, 0, 3)
	if r2 == nil {
		return ""
	}
	if sameAddr(r1.mapped, r2.mapped) {
		return ei
	}
	r3 := transact(conn, r1.other, 0, 3) // other IP, other port
	if r3 == nil {
		return ""
	}
	if sameAddr(r2.mapped, r3.mapped) {
		return ad
	}
	return apd
}

// detectFiltering is RFC 5780 section 4.4. It uses a fresh socket so earlier
// probes cannot have opened the filter toward the server's alternate address.
func detectFiltering(server *net.UDPAddr) string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return ""
	}
	defer conn.Close()
	if transact(conn, server, 0, 3) == nil {
		return ""
	}
	if transact(conn, server, flagChangeIP|flagChangePort, 2) != nil {
		return ei
	}
	if transact(conn, server, flagChangePort, 2) != nil {
		return ad
	}
	return apd
}

func legacyName(mapping, filtering string) string {
	switch {
	case mapping == "" || filtering == "":
		return "unknown"
	case mapping != ei:
		return "symmetric"
	case filtering == ei:
		return "full cone"
	case filtering == ad:
		return "restricted cone"
	default:
		return "port-restricted cone"
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown (no reply)"
	}
	return s
}

func main() {
	serverArg := flag.String("server", "stunserver2025.stunprotocol.org:3478", "STUN server host:port (must support RFC 5780)")
	flag.Parse()

	server, err := net.ResolveUDPAddr("udp4", *serverArg)
	if err != nil {
		fatalf("cannot resolve %s: %v", *serverArg, err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		fatalf("cannot open socket: %v", err)
	}
	defer conn.Close()

	r1 := transact(conn, server, 0, 3)
	if r1 == nil {
		fatalf("no STUN reply from %s", server)
	}
	fmt.Printf("Server:  %s\nMapped:  %s\n", server, r1.mapped)
	local := conn.LocalAddr().(*net.UDPAddr)
	if ip := localIP(server); ip != nil && ip.Equal(r1.mapped.IP) && local.Port == r1.mapped.Port {
		fmt.Println("Note:    mapped address equals local address, so no NAT was detected.")
	}
	if r1.other == nil {
		fatalf("The server did not send OTHER-ADDRESS, so it does not support RFC 5780. " +
			"Use a server that does (for example coturn or stunserver2025.stunprotocol.org).")
	}

	mapping := detectMapping(conn, server, r1)
	filtering := detectFiltering(server)
	fmt.Printf("Mapping behavior:   %s\n", orUnknown(mapping))
	fmt.Printf("Filtering behavior: %s\n", orUnknown(filtering))
	fmt.Printf("Legacy name (approximate): %s\n", legacyName(mapping, filtering))
}

// Package fakedns is a UDP name server for tests. It answers A queries for the
// names it was given and NOERROR with no records for everything else, which is
// exactly enough for a resolver under test to prove where its questions went.
package fakedns

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Server answers on Addr until Close.
type Server struct {
	Addr    string
	conn    net.PacketConn
	records map[string]net.IP
}

// Start listens on a loopback port and answers the given name → IPv4 pairs.
func Start(records map[string]string) (*Server, error) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	s := &Server{Addr: conn.LocalAddr().String(), conn: conn, records: map[string]net.IP{}}
	for name, ip := range records {
		v4 := net.ParseIP(ip).To4()
		if v4 == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%s: %q is not an IPv4 address", name, ip)
		}
		s.records[strings.ToLower(strings.TrimSuffix(name, "."))+"."] = v4
	}
	go s.serve()
	return s, nil
}

// Close stops answering.
func (s *Server) Close() error { return s.conn.Close() }

func (s *Server) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if reply, ok := s.answer(buf[:n]); ok {
			_, _ = s.conn.WriteTo(reply, from)
		}
	}
}

func (s *Server) answer(query []byte) ([]byte, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, false
	}
	if err := b.Question(q); err != nil {
		return nil, false
	}
	if err := b.StartAnswers(); err != nil {
		return nil, false
	}
	if ip, ok := s.records[strings.ToLower(q.Name.String())]; ok && q.Type == dnsmessage.TypeA {
		var a [4]byte
		copy(a[:], ip)
		err := b.AResource(
			dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: a},
		)
		if err != nil {
			return nil, false
		}
	}
	out, err := b.Finish()
	return out, err == nil
}

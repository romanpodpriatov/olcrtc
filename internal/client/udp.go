package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/udpwire"
)

const (
	udpReadBufferSize    = 64 * 1024
	udpFlowIdleTimeout   = 2 * time.Minute
	udpFlowSweepInterval = 30 * time.Second
	defaultMaxUDPFlows   = 1024
)

var (
	errSocksUDPShortPacket       = errors.New("short packet")
	errSocksUDPBadReservedBytes  = errors.New("bad reserved bytes")
	errSocksUDPFragmented        = errors.New("fragmentation unsupported")
	errSocksUDPMissingPort       = errors.New("missing port")
	errSocksUDPMissingAddrType   = errors.New("missing address type")
	errSocksUDPShortIPv4         = errors.New("short ipv4 address")
	errSocksUDPMissingDomainSize = errors.New("missing domain length")
	errSocksUDPShortDomain       = errors.New("short domain")
	errSocksUDPShortIPv6         = errors.New("short ipv6 address")
	errTooManyUDPFlows           = errors.New("too many udp flows")
)

type udpAssociationSource struct {
	peerIP    netip.Addr
	requestIP netip.Addr
	port      int
}

//nolint:cyclop // SOCKS5 UDP associate lifecycle has several protocol failure exits.
func (c *Client) handleUDPAssociate(ctx context.Context, tcpConn net.Conn, req socksRequest) {
	if c.udpDisabled {
		_, _ = tcpConn.Write(replyHostUnreachable())
		return
	}
	dg, ok := c.ln.(transport.DatagramTransport)
	if !ok {
		_, _ = tcpConn.Write(replyHostUnreachable())
		return
	}
	if !c.waitSessionReady(ctx) {
		_, _ = tcpConn.Write(replyHostUnreachable())
		return
	}
	allowedSource, err := udpAssociationAllowedSource(tcpConn, req)
	if err != nil {
		logger.Debugf("socks udp associate source invalid: %v", err)
		_, _ = tcpConn.Write(replyHostUnreachable())
		return
	}

	udpConn, err := listenUDPAssociate(tcpConn)
	if err != nil {
		logger.Warnf("socks udp associate listen failed: %v", err)
		_, _ = tcpConn.Write(replyHostUnreachable())
		return
	}
	defer func() {
		c.removeUDPFlowsForConn(udpConn)
		_ = udpConn.Close()
	}()
	assocCtx, cancelAssoc := context.WithCancel(ctx)
	defer cancelAssoc()
	go c.sweepUDPFlows(assocCtx, udpConn)

	addr := udpConn.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert // net.ListenUDP returns UDPAddr
	if _, err := tcpConn.Write(replySuccessUDP(addr)); err != nil {
		return
	}
	logger.Infof("SOCKS5 UDP associate listening on %s", addr.String())

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, tcpConn)
		close(done)
		_ = udpConn.Close()
	}()

	buf := make([]byte, udpReadBufferSize)
	for {
		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
			case <-done:
			default:
				if !errors.Is(err, net.ErrClosed) {
					logger.Debugf("socks udp read failed: %v", err)
				}
			}
			return
		}
		if !allowedSource.allows(src) {
			logger.Debugf("drop socks udp packet from unbound source: %s", src.String())
			continue
		}
		c.forwardLocalUDP(ctx, dg, udpConn, src, buf[:n])
	}
}

func udpAssociationAllowedSource(tcpConn net.Conn, req socksRequest) (udpAssociationSource, error) {
	remote, ok := tcpConn.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP == nil {
		return udpAssociationSource{}, ErrUnsupportedAddressType
	}
	peerIP, err := netip.ParseAddr(remote.IP.String())
	if err != nil {
		return udpAssociationSource{}, fmt.Errorf("parse tcp peer ip: %w", err)
	}
	allowed := udpAssociationSource{peerIP: peerIP.Unmap(), port: req.port}
	if req.addr == "" {
		return allowed, nil
	}
	reqIP, ok := parseUDPRequestIP(req.addr)
	if !ok {
		return allowed, nil
	}
	allowed.requestIP = reqIP.Unmap()
	return allowed, nil
}

func parseUDPRequestIP(addr string) (netip.Addr, bool) {
	reqIP, err := netip.ParseAddr(addr)
	if err != nil || reqIP.IsUnspecified() {
		return netip.Addr{}, false
	}
	return reqIP, true
}

func (s udpAssociationSource) allows(src *net.UDPAddr) bool {
	if src == nil || src.AddrPort().Addr().Unmap() != s.peerIP {
		return false
	}
	if s.requestIP.IsValid() && src.AddrPort().Addr().Unmap() != s.requestIP {
		return false
	}
	return s.port == 0 || src.Port == s.port
}

func listenUDPAssociate(tcpConn net.Conn) (*net.UDPConn, error) {
	ip := net.IPv4(127, 0, 0, 1)
	if addr, ok := tcpConn.LocalAddr().(*net.TCPAddr); ok && addr.IP != nil && !addr.IP.IsUnspecified() {
		ip = addr.IP
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	if err != nil {
		return nil, fmt.Errorf("listen udp associate: %w", err)
	}
	return conn, nil
}

func (c *Client) forwardLocalUDP(
	ctx context.Context,
	dg transport.DatagramTransport,
	udpConn *net.UDPConn,
	src *net.UDPAddr,
	packet []byte,
) {
	target, payload, err := parseSocksUDP(packet)
	if err != nil {
		logger.Debugf("drop malformed socks udp packet: %v", err)
		return
	}
	flowID, ok := c.udpFlowID(udpConn, src, target)
	if !ok {
		logger.Debugf("drop udp packet: %v", errTooManyUDPFlows)
		return
	}
	frame := udpwire.Frame{
		Type:     udpwire.FrameTypePacket,
		FlowID:   flowID,
		Endpoint: target,
		Payload:  payload,
	}
	wire, err := udpwire.Encode(frame)
	if err != nil {
		logger.Debugf("drop udp packet encode failed: %v", err)
		return
	}
	enc, err := c.cipher.Encrypt(wire)
	if err != nil {
		logger.Debugf("drop udp packet encrypt failed: %v", err)
		return
	}
	if !waitDatagramReady(ctx, dg) {
		return
	}
	if err := dg.SendDatagram(enc); err != nil {
		logger.Debugf("send udp datagram failed: %v", err)
	}
}

func (c *Client) onDatagram(ciphertext []byte) {
	if c.udpDisabled {
		return
	}
	wire, err := c.cipher.Decrypt(ciphertext)
	if err != nil {
		logger.Debugf("drop udp datagram decrypt failed: %v", err)
		return
	}
	frame, err := udpwire.Decode(wire)
	if err != nil {
		logger.Debugf("drop udp datagram decode failed: %v", err)
		return
	}
	if frame.Type != udpwire.FrameTypePacket {
		return
	}

	c.udpMu.Lock()
	flow, ok := c.udpFlows[frame.FlowID]
	if ok {
		flow.lastSeen = time.Now()
		c.udpFlows[frame.FlowID] = flow
	}
	c.udpMu.Unlock()
	if !ok {
		return
	}
	packet, err := buildSocksUDP(frame.Endpoint, frame.Payload)
	if err != nil {
		logger.Debugf("drop udp response encode failed: %v", err)
		return
	}
	_, _ = flow.conn.WriteToUDP(packet, flow.clientAddr)
}

func (c *Client) udpFlowID(conn *net.UDPConn, src *net.UDPAddr, target udpwire.Endpoint) (uint64, bool) {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	now := time.Now()
	c.ensureUDPFlowIndexLocked()
	key := clientUDPFlowIndexKey(conn, src, target)
	if id, ok := c.udpFlowIndex[key]; ok {
		flow := c.udpFlows[id]
		flow.lastSeen = now
		c.udpFlows[id] = flow
		return id, true
	}
	if len(c.udpFlows) >= normalizeMaxUDPFlows(c.maxUDPFlows) {
		return 0, false
	}
	for {
		id := randomUDPFlowID()
		if _, exists := c.udpFlows[id]; !exists {
			c.udpFlows[id] = clientUDPFlow{conn: conn, clientAddr: src, target: target, lastSeen: now}
			c.udpFlowIndex[key] = id
			return id, true
		}
	}
}

func (c *Client) ensureUDPFlowIndexLocked() {
	if c.udpFlowIndex != nil {
		return
	}
	c.udpFlowIndex = make(map[clientUDPFlowKey]uint64, len(c.udpFlows))
	for id, flow := range c.udpFlows {
		c.udpFlowIndex[clientUDPFlowIndexKey(flow.conn, flow.clientAddr, flow.target)] = id
	}
}

func clientUDPFlowIndexKey(
	conn *net.UDPConn,
	src *net.UDPAddr,
	target udpwire.Endpoint,
) clientUDPFlowKey {
	return clientUDPFlowKey{conn: conn, clientAddr: src.AddrPort(), target: target}
}

func (c *Client) removeUDPFlowsForConn(conn *net.UDPConn) {
	var closed []uint64
	c.udpMu.Lock()
	c.ensureUDPFlowIndexLocked()
	for id, flow := range c.udpFlows {
		if flow.conn == conn {
			delete(c.udpFlows, id)
			delete(c.udpFlowIndex, clientUDPFlowIndexKey(flow.conn, flow.clientAddr, flow.target))
			closed = append(closed, id)
		}
	}
	c.udpMu.Unlock()
	c.sendUDPFlowCloses(closed)
}

func (c *Client) sweepUDPFlows(ctx context.Context, conn *net.UDPConn) {
	ticker := time.NewTicker(udpFlowSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.removeIdleUDPFlowsForConn(conn, now)
		}
	}
}

func (c *Client) removeIdleUDPFlowsForConn(conn *net.UDPConn, now time.Time) {
	var closed []uint64
	c.udpMu.Lock()
	c.ensureUDPFlowIndexLocked()
	for id, flow := range c.udpFlows {
		if flow.conn == conn && now.Sub(flow.lastSeen) >= udpFlowIdleTimeout {
			delete(c.udpFlows, id)
			delete(c.udpFlowIndex, clientUDPFlowIndexKey(flow.conn, flow.clientAddr, flow.target))
			closed = append(closed, id)
		}
	}
	c.udpMu.Unlock()
	c.sendUDPFlowCloses(closed)
}

func (c *Client) sendUDPFlowCloses(flowIDs []uint64) {
	if c.udpDisabled {
		return
	}
	dg, ok := c.ln.(transport.DatagramTransport)
	if !ok || !dg.DatagramCanSend() {
		return
	}
	for _, flowID := range flowIDs {
		wire, err := udpwire.Encode(udpwire.Frame{Type: udpwire.FrameTypeClose, FlowID: flowID})
		if err != nil {
			continue
		}
		enc, err := c.cipher.Encrypt(wire)
		if err != nil {
			continue
		}
		_ = dg.SendDatagram(enc)
	}
}

func (c *Client) waitSessionReady(ctx context.Context) bool {
	const sessionReadyTimeout = 60 * time.Second
	readyCtx, cancel := context.WithTimeout(ctx, sessionReadyTimeout)
	defer cancel()
	for {
		c.sessMu.RLock()
		sess := c.session
		sid := c.sessionID
		c.sessMu.RUnlock()
		if sess != nil && !sess.IsClosed() && sid != "" {
			return true
		}
		select {
		case <-readyCtx.Done():
			return false
		case <-c.readyChannel():
		}
	}
}

func normalizeMaxUDPFlows(maxFlows int) int {
	if maxFlows <= 0 {
		return defaultMaxUDPFlows
	}
	return maxFlows
}

func waitDatagramReady(ctx context.Context, dg transport.DatagramTransport) bool {
	const pollDelay = 2 * time.Millisecond
	for {
		if dg.DatagramCanSend() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(pollDelay):
		}
	}
}

func parseSocksUDP(packet []byte) (udpwire.Endpoint, []byte, error) {
	if len(packet) < 4 {
		return udpwire.Endpoint{}, nil, errSocksUDPShortPacket
	}
	if packet[0] != 0 || packet[1] != 0 {
		return udpwire.Endpoint{}, nil, errSocksUDPBadReservedBytes
	}
	if packet[2] != 0 {
		return udpwire.Endpoint{}, nil, errSocksUDPFragmented
	}
	host, off, err := parseSocksUDPHost(packet, 3)
	if err != nil {
		return udpwire.Endpoint{}, nil, err
	}
	if len(packet) < off+2 {
		return udpwire.Endpoint{}, nil, errSocksUDPMissingPort
	}
	port := binary.BigEndian.Uint16(packet[off : off+2])
	payload := packet[off+2:]
	return udpwire.Endpoint{Host: host, Port: port}, payload, nil
}

//nolint:cyclop // SOCKS5 address parsing is a compact protocol switch.
func parseSocksUDPHost(packet []byte, off int) (string, int, error) {
	if len(packet) <= off {
		return "", 0, errSocksUDPMissingAddrType
	}
	switch packet[off] {
	case 1:
		if len(packet) < off+1+4 {
			return "", 0, errSocksUDPShortIPv4
		}
		return net.IP(packet[off+1 : off+1+4]).String(), off + 1 + 4, nil
	case 3:
		if len(packet) < off+2 {
			return "", 0, errSocksUDPMissingDomainSize
		}
		size := int(packet[off+1])
		if size == 0 || len(packet) < off+2+size {
			return "", 0, errSocksUDPShortDomain
		}
		return string(packet[off+2 : off+2+size]), off + 2 + size, nil
	case 4:
		if len(packet) < off+1+16 {
			return "", 0, errSocksUDPShortIPv6
		}
		return net.IP(packet[off+1 : off+1+16]).String(), off + 1 + 16, nil
	default:
		return "", 0, fmt.Errorf("%w: %d", ErrUnsupportedAddressType, packet[off])
	}
}

func buildSocksUDP(endpoint udpwire.Endpoint, payload []byte) ([]byte, error) {
	addrType, addr, err := socksAddrBytes(endpoint.Host)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(addr)+2+len(payload))
	out = append(out, 0, 0, 0, addrType)
	if addrType == 3 {
		out = append(out, byte(len(addr))) //nolint:gosec // G115: domain length is capped at 255 by socksAddrBytes.
	}
	out = append(out, addr...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], endpoint.Port)
	out = append(out, port[:]...)
	out = append(out, payload...)
	return out, nil
}

func socksAddrBytes(host string) (byte, []byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return 1, ip4, nil
		}
		if ip16 := ip.To16(); ip16 != nil {
			return 4, ip16, nil
		}
	}
	if len(host) == 0 || len(host) > 255 {
		return 0, nil, ErrUnsupportedAddressType
	}
	return 3, []byte(host), nil
}

func replySuccessUDP(addr *net.UDPAddr) []byte {
	ip := addr.IP.To4()
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(addr.Port)) //nolint:gosec // G115: UDP listener ports are 0..65535.
	return []byte{5, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], port[0], port[1]}
}

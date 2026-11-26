package awg

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

var _ conn.Bind = (*clientBind)(nil)

type clientBind struct {
	ctx            context.Context
	logger         logger.Logger
	dialer         N.Dialer
	connectAddress netip.AddrPort
	access         sync.Mutex
	session        *clientBindSession
}

type clientBindSession struct {
	ctx            context.Context
	cancel         context.CancelFunc
	connectAddress netip.AddrPort
	access         sync.Mutex
	socket         *clientSocket
}

type clientSocket struct {
	net.PacketConn
}

func (c *clientBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.session != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if port != 0 {
		return nil, 0, E.New("listen_port conflicts with detour")
	}
	ctx, cancel := context.WithCancel(c.ctx)
	session := &clientBindSession{ctx: ctx, cancel: cancel, connectAddress: c.connectAddress}
	c.session = session
	return []conn.ReceiveFunc{func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		return c.receive(session, packets, sizes, endpoints)
	}}, 0, nil
}

func (c *clientBind) setConnectAddress(address netip.AddrPort) {
	c.access.Lock()
	c.connectAddress = address
	c.access.Unlock()
}

func (c *clientBind) connect(session *clientBindSession) (*clientSocket, error) {
	session.access.Lock()
	defer session.access.Unlock()
	if session.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if session.socket != nil {
		return session.socket, nil
	}
	var socket net.PacketConn
	if session.connectAddress.IsValid() {
		udpConn, err := c.dialer.DialContext(session.ctx, N.NetworkUDP, M.SocksaddrFromNetIP(session.connectAddress))
		if err != nil {
			return nil, err
		}
		socket = bufio.NewUnbindPacketConn(udpConn)
	} else {
		udpConn, err := c.dialer.ListenPacket(session.ctx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
		if err != nil {
			return nil, err
		}
		socket = udpConn
	}
	session.socket = &clientSocket{PacketConn: socket}
	return session.socket, nil
}

func (c *clientBind) receive(session *clientBindSession, packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
	socket, err := c.connect(session)
	if err == nil {
		size, source, readErr := socket.ReadFrom(packets[0])
		if readErr == nil {
			address := session.connectAddress
			if !address.IsValid() {
				address = M.SocksaddrFromNet(source).Unwrap().AddrPort()
			}
			if !address.IsValid() {
				return 0, nil
			}
			sizes[0] = size
			endpoints[0] = &conn.StdNetEndpoint{AddrPort: address}
			return 1, nil
		}
		session.closeSocket(socket)
		err = readErr
	}
	if session.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	c.logger.Error(E.Cause(err, "receive AmneziaWG packet over detour"))
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-session.ctx.Done():
		return 0, net.ErrClosed
	case <-timer.C:
		return 0, nil
	}
}

func (c *clientBind) Close() error {
	c.access.Lock()
	session := c.session
	c.session = nil
	c.access.Unlock()
	if session != nil {
		session.cancel()
		session.closeSocket(nil)
	}
	return nil
}

func (s *clientBindSession) closeSocket(socket *clientSocket) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.socket != nil && (socket == nil || socket == s.socket) {
		_ = s.socket.Close()
		s.socket = nil
	}
}

func (c *clientBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	destination, ok := endpoint.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	c.access.Lock()
	session := c.session
	c.access.Unlock()
	if session == nil {
		return net.ErrClosed
	}
	// The connected socket ignores the address passed to WriteTo.
	if session.connectAddress.IsValid() && destination.AddrPort != session.connectAddress {
		return E.New("AmneziaWG detour is connected to ", session.connectAddress, ", cannot send to ", destination.AddrPort)
	}
	socket, err := c.connect(session)
	if err != nil {
		return err
	}
	address := M.SocksaddrFromNetIP(destination.AddrPort).UDPAddr()
	for _, packet := range packets {
		if _, err := socket.WriteTo(packet, address); err != nil {
			session.closeSocket(socket)
			return err
		}
	}
	return nil
}

func (*clientBind) SetMark(uint32) error { return nil }

func (*clientBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	return parseBindEndpoint(value)
}

func (*clientBind) BatchSize() int { return 1 }

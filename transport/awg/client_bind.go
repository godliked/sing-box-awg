package awg

import (
	"context"
	"errors"
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
	ctx       context.Context
	logger    logger.Logger
	dialer    N.Dialer
	access    sync.Mutex
	addresses []netip.AddrPort
	session   *clientBindSession
}

type clientBindSession struct {
	ctx          context.Context
	cancel       context.CancelFunc
	destinations map[netip.AddrPort]*clientBindDestination
}

type clientBindDestination struct {
	address netip.AddrPort
	access  sync.Mutex
	socket  *clientSocket
}

type clientSocket struct {
	net.PacketConn
}

type clientEndpoint struct {
	conn.StdNetEndpoint
	bindAddress netip.AddrPort
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
	addresses := c.addresses
	if len(addresses) == 0 {
		addresses = []netip.AddrPort{{}}
	}
	session := &clientBindSession{
		ctx:          ctx,
		cancel:       cancel,
		destinations: make(map[netip.AddrPort]*clientBindDestination, len(addresses)),
	}
	receive := make([]conn.ReceiveFunc, 0, len(addresses))
	for _, address := range addresses {
		if session.destinations[address] != nil {
			continue
		}
		destination := &clientBindDestination{address: address}
		session.destinations[address] = destination
		receive = append(receive, func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			return c.receive(session.ctx, destination, packets, sizes, endpoints)
		})
	}
	c.session = session
	return receive, 0, nil
}

func (c *clientBind) setAddresses(addresses []netip.AddrPort) {
	c.access.Lock()
	c.addresses = addresses
	c.access.Unlock()
}

func (c *clientBind) connect(ctx context.Context, destination *clientBindDestination) (*clientSocket, error) {
	destination.access.Lock()
	defer destination.access.Unlock()
	if ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if destination.socket != nil {
		return destination.socket, nil
	}
	address := M.Socksaddr{Addr: netip.IPv4Unspecified()}
	if destination.address.IsValid() {
		address = M.SocksaddrFromNetIP(destination.address)
	}
	socket, listenErr := c.dialer.ListenPacket(ctx, address)
	if listenErr != nil {
		if !destination.address.IsValid() || ctx.Err() != nil {
			return nil, listenErr
		}
		udpConn, dialErr := c.dialer.DialContext(ctx, N.NetworkUDP, address)
		if dialErr != nil {
			return nil, errors.Join(listenErr, dialErr)
		}
		// Detours that require connected UDP may expose a different remote address.
		socket = bufio.NewUnbindPacketConnWithAddr(udpConn, address)
	}
	destination.socket = &clientSocket{PacketConn: socket}
	return destination.socket, nil
}

func (c *clientBind) receive(ctx context.Context, destination *clientBindDestination, packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
	socket, err := c.connect(ctx, destination)
	if err == nil {
		size, source, readErr := socket.ReadFrom(packets[0])
		if readErr == nil {
			address := M.SocksaddrFromNet(source).Unwrap().AddrPort()
			if !address.IsValid() {
				return 0, nil
			}
			sizes[0] = size
			endpoints[0] = &clientEndpoint{
				StdNetEndpoint: conn.StdNetEndpoint{AddrPort: address},
				bindAddress:    destination.address,
			}
			return 1, nil
		}
		destination.closeSocket(socket)
		err = readErr
	}
	if ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	c.logger.Error(E.Cause(err, "receive AmneziaWG packet over detour"))
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, net.ErrClosed
	case <-timer.C:
	}
	if ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	return 0, nil
}

func (c *clientBind) Close() error {
	c.access.Lock()
	session := c.session
	c.session = nil
	c.access.Unlock()
	if session != nil {
		session.cancel()
		for _, destination := range session.destinations {
			destination.closeSocket(nil)
		}
	}
	return nil
}

func (d *clientBindDestination) closeSocket(socket *clientSocket) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.socket != nil && (socket == nil || socket == d.socket) {
		_ = d.socket.Close()
		d.socket = nil
	}
}

func (c *clientBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	remote, ok := endpoint.(*clientEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	c.access.Lock()
	session := c.session
	c.access.Unlock()
	if session == nil {
		return net.ErrClosed
	}
	// Reply through the same detour socket, even when the peer's address changes.
	destination := session.destinations[remote.bindAddress]
	if destination == nil {
		return E.New("no AmneziaWG detour socket for ", remote.AddrPort)
	}
	socket, err := c.connect(session.ctx, destination)
	if err != nil {
		return err
	}
	udpAddress := M.SocksaddrFromNetIP(remote.AddrPort).UDPAddr()
	for _, packet := range packets {
		if _, err := socket.WriteTo(packet, udpAddress); err != nil {
			destination.closeSocket(socket)
			return err
		}
	}
	return nil
}

func (*clientBind) SetMark(uint32) error { return nil }

func (*clientBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return &clientEndpoint{StdNetEndpoint: conn.StdNetEndpoint{AddrPort: address}, bindAddress: address}, nil
}

func (*clientBind) BatchSize() int { return 1 }

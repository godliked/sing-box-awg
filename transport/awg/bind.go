package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

var _ conn.Bind = (*standardBind)(nil)

type standardBind struct {
	ctx              context.Context
	listenConfig     net.ListenConfig
	listenPort       uint16
	bindAddress4     netip.Addr
	bindAddress6     netip.Addr
	networkNamespace string
	egressPool       *tun.UDPEgressPool
	onRead           func(int)
	onWrite          func(int)
	access           sync.Mutex
	ipv4             *net.UDPConn
	ipv6             *net.UDPConn
}

type standardEndpoint struct {
	conn.StdNetEndpoint
	source atomic.Pointer[udpReplySource]
}

func (e *standardEndpoint) ClearSrc() {
	e.source.Store(nil)
}

func (e *standardEndpoint) SrcIP() netip.Addr {
	if source := e.source.Load(); source != nil {
		return source.address
	}
	return netip.Addr{}
}

func (e *standardEndpoint) SrcToString() string {
	return e.SrcIP().String()
}

func (s *standardBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	// The AWG core supplies zero after a failed rebind. Keep a configured port fixed.
	if s.listenPort != 0 {
		port = s.listenPort
	}
	address4, address6 := s.bindAddress4, s.bindAddress6
	if !address4.IsValid() {
		address4 = netip.IPv4Unspecified()
	}
	if !address6.IsValid() {
		address6 = netip.IPv6Unspecified()
	}
	for attempt := 0; attempt < 100; attempt++ {
		ipv4, receive4, err := s.listen("udp4", address4, port)
		if err != nil {
			return nil, 0, err
		}
		actualPort := port
		if ipv4 != nil {
			actualPort = ipv4.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		}
		ipv6, receive6, err := s.listen("udp6", address6, actualPort)
		if err != nil {
			if ipv4 != nil {
				_ = ipv4.Close()
			}
			if port == 0 && errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
			return nil, 0, err
		}
		var receiveFuncs []conn.ReceiveFunc
		if ipv4 != nil {
			receiveFuncs = append(receiveFuncs, receive4)
		}
		if ipv6 != nil {
			actualPort = ipv6.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			receiveFuncs = append(receiveFuncs, receive6)
		}
		if len(receiveFuncs) == 0 {
			return nil, 0, syscall.EAFNOSUPPORT
		}
		s.ipv4, s.ipv6 = ipv4, ipv6
		if s.egressPool != nil {
			s.egressPool.SetEgressPort(actualPort)
			receiveFuncs = append(receiveFuncs, s.receive(udpPacketReaderWithoutSource(s.egressPool.ReceiveEgress)))
		}
		return receiveFuncs, actualPort, nil
	}
	return nil, 0, syscall.EADDRINUSE
}

func (s *standardBind) listen(network string, address netip.Addr, port uint16) (*net.UDPConn, conn.ReceiveFunc, error) {
	packetConn, err := listener.ListenNetworkNamespace(s.ctx, s.networkNamespace, func() (net.PacketConn, error) {
		return s.listenConfig.ListenPacket(s.ctx, network, netip.AddrPortFrom(address, port).String())
	})
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	udpConn := packetConn.(*net.UDPConn)
	read, err := newUDPPacketReader(udpConn, network)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	return udpConn, s.receive(read), nil
}

func (s *standardBind) receive(read udpPacketReader) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		size, remoteAddress, replySource, err := read(packets[0])
		if err != nil {
			return 0, err
		}
		if s.onRead != nil {
			s.onRead(size)
		}
		endpoint := &standardEndpoint{StdNetEndpoint: conn.StdNetEndpoint{AddrPort: remoteAddress}}
		endpoint.source.Store(replySource)
		sizes[0] = size
		endpoints[0] = endpoint
		return 1, nil
	}
}

func (s *standardBind) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.egressPool != nil {
		s.egressPool.SetEgressPort(0)
	}
	var err4, err6 error
	if s.ipv4 != nil {
		err4 = s.ipv4.Close()
		s.ipv4 = nil
	}
	if s.ipv6 != nil {
		err6 = s.ipv6.Close()
		s.ipv6 = nil
	}
	return errors.Join(err4, err6)
}

func (s *standardBind) SetMark(mark uint32) error {
	s.access.Lock()
	defer s.access.Unlock()
	setMark := control.RoutingMark(mark)
	for _, socket := range []*net.UDPConn{s.ipv4, s.ipv6} {
		if socket == nil {
			continue
		}
		rawConn, err := socket.SyscallConn()
		if err != nil {
			return err
		}
		if err := setMark("udp", socket.LocalAddr().String(), rawConn); err != nil {
			return err
		}
	}
	return nil
}

func (s *standardBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	destination, ok := endpoint.(*standardEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	s.access.Lock()
	socket := s.ipv4
	if destination.DstIP().Is6() {
		socket = s.ipv6
	}
	s.access.Unlock()
	if socket == nil {
		return syscall.EAFNOSUPPORT
	}
	replySource := destination.source.Load()
	if replySource != nil && replySource.socket != socket {
		replySource = nil
	}
	if replySource == nil && s.egressPool != nil {
		if member := s.egressPool.LookupEgress(destination.AddrPort); member != nil {
			socket = member
		}
	}
	for _, packet := range packets {
		var err error
		if replySource != nil {
			_, _, err = socket.WriteMsgUDPAddrPort(packet, replySource.control, destination.AddrPort)
		} else {
			_, err = socket.WriteToUDPAddrPort(packet, destination.AddrPort)
		}
		if err != nil {
			return err
		}
		if s.onWrite != nil {
			s.onWrite(len(packet))
		}
	}
	return nil
}

func (*standardBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return &standardEndpoint{StdNetEndpoint: conn.StdNetEndpoint{AddrPort: address}}, nil
}

func (*standardBind) BatchSize() int { return 1 }

func parseBindEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: address}, nil
}

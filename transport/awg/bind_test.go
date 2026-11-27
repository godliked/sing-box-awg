package awg

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/stretchr/testify/require"
)

func TestStandardBindAddresses(t *testing.T) {
	bind := &standardBind{
		ctx:          t.Context(),
		bindAddress4: netip.MustParseAddr("127.0.0.1"),
		bindAddress6: netip.IPv6Loopback(),
	}
	_, port, err := bind.Open(0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bind.Close()) })
	require.NotZero(t, port)
	if bind.ipv4 != nil {
		require.Equal(t, netip.AddrPortFrom(bind.bindAddress4, port).String(), bind.ipv4.LocalAddr().String())
	}
	if bind.ipv6 != nil {
		require.Equal(t, netip.AddrPortFrom(bind.bindAddress6, port).String(), bind.ipv6.LocalAddr().String())
	}
}

func TestClientBindRepliesToAlternateSource(t *testing.T) {
	configured := netip.MustParseAddrPort("192.0.2.1:51820")
	alternate := netip.MustParseAddrPort("192.0.2.2:51820")
	packetConn := &testDetourPacketConn{source: M.SocksaddrFromNetIP(alternate).UDPAddr()}
	dialer := &testPacketDetour{packetConn: packetConn}
	bind := &clientBind{ctx: t.Context(), logger: logger.NOP(), dialer: dialer, addresses: []netip.AddrPort{configured}}
	receive, _, err := bind.Open(0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bind.Close()) })

	endpoint, err := bind.ParseEndpoint(configured.String())
	require.NoError(t, err)
	require.NoError(t, bind.Send([][]byte{{1}}, endpoint))
	require.Equal(t, configured, dialer.destination.AddrPort())
	require.Equal(t, configured, packetConn.sentTo)

	packets, sizes, endpoints := [][]byte{make([]byte, 1)}, make([]int, 1), make([]conn.Endpoint, 1)
	count, err := receive[0](packets, sizes, endpoints)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, alternate.String(), endpoints[0].DstToString())
	require.NoError(t, bind.Send([][]byte{{2}}, endpoints[0]))
	require.Equal(t, alternate, packetConn.sentTo)
}

type testPacketDetour struct {
	packetConn  net.PacketConn
	destination M.Socksaddr
}

func (*testPacketDetour) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, N.ErrUnknownNetwork
}

func (d *testPacketDetour) ListenPacket(_ context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.destination = destination
	return d.packetConn, nil
}

type testDetourPacketConn struct {
	net.PacketConn
	source *net.UDPAddr
	sentTo netip.AddrPort
}

func (c *testDetourPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	buffer[0] = 1
	return 1, c.source, nil
}

func (c *testDetourPacketConn) WriteTo(packet []byte, destination net.Addr) (int, error) {
	c.sentTo = M.SocksaddrFromNet(destination).AddrPort()
	return len(packet), nil
}

func (*testDetourPacketConn) Close() error { return nil }

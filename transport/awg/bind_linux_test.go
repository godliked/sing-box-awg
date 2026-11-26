package awg

import (
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/stretchr/testify/require"
)

func TestStandardBindReplySource(t *testing.T) {
	t.Run("wildcard", func(t *testing.T) { testStandardBindReplySource(t, netip.Addr{}) })
	t.Run("specific address", func(t *testing.T) { testStandardBindReplySource(t, netip.MustParseAddr("127.0.0.2")) })
}

func testStandardBindReplySource(t *testing.T, bindAddress netip.Addr) {
	t.Helper()
	bind := &standardBind{ctx: t.Context(), bindAddress4: bindAddress}
	receive, port, err := bind.Open(0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bind.Close()) })
	require.NotNil(t, bind.ipv4)
	localAddress := netip.MustParseAddr("127.0.0.2")
	destination := netip.AddrPortFrom(localAddress, port)
	client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(destination))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	deadline := time.Now().Add(3 * time.Second)
	require.NoError(t, client.SetDeadline(deadline))
	require.NoError(t, bind.ipv4.SetReadDeadline(deadline))
	_, err = client.Write([]byte("request"))
	require.NoError(t, err)
	packets := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	count, err := receive[0](packets, sizes, endpoints)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	if bindAddress.IsValid() {
		require.False(t, endpoints[0].SrcIP().IsValid())
	} else {
		require.Equal(t, localAddress, endpoints[0].SrcIP())
	}
	require.NoError(t, bind.Send([][]byte{[]byte("reply")}, endpoints[0]))
	size, err := client.Read(packets[0])
	require.NoError(t, err)
	require.Equal(t, "reply", string(packets[0][:size]))
	endpoints[0].ClearSrc()
	require.False(t, endpoints[0].SrcIP().IsValid())
}

func TestStandardBindMissingNamespace(t *testing.T) {
	bind := &standardBind{ctx: t.Context(), networkNamespace: filepath.Join(t.TempDir(), "missing")}
	_, _, err := bind.Open(0)
	require.ErrorContains(t, err, "get netns")
	require.Nil(t, bind.ipv4)
	require.Nil(t, bind.ipv6)
}

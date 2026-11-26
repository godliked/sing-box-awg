package awg

import (
	"net/netip"
	"testing"

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

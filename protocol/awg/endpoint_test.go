package awg

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

func TestJudgeFlowOnlyBypassesRoutingForLocalAddress(t *testing.T) {
	endpoint := &Endpoint{
		router:         &rejectingRouter{},
		localAddresses: []netip.Prefix{netip.MustParsePrefix("10.201.0.1/24"), netip.MustParsePrefix("fd00:201::1/64")},
	}
	for _, local := range endpoint.localAddresses {
		for _, test := range []struct {
			destination netip.Addr
			want        tun.FlowAction
		}{
			{local.Addr(), tun.ActionAccept},
			{local.Addr().Next(), tun.ActionReject},
		} {
			verdict := endpoint.JudgeFlow(uint8(header.UDPProtocolNumber), netip.AddrPort{}, netip.AddrPortFrom(test.destination, 53), nil)
			require.Equal(t, test.want, verdict.Action, test.destination.String())
		}
	}
}

type rejectingRouter struct{ adapter.Router }

func (*rejectingRouter) PreMatch(adapter.InboundContext, []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{Action: adapter.PreMatchReject}
}

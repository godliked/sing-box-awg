//go:build !with_awg

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerAWGEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.AWGEndpointOptions](registry, C.TypeAWG, func(context.Context, adapter.Router, log.ContextLogger, string, option.AWGEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New("AmneziaWG is unavailable in this build, rebuild with -tags with_awg")
	})
}

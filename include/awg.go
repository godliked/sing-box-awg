//go:build with_awg

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/awg"
)

func registerAWGEndpoint(registry *endpoint.Registry) {
	awg.RegisterEndpoint(registry)
}

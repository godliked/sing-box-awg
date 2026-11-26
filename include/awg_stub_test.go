//go:build !with_awg

package include_test

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

func TestAWGDisabled(t *testing.T) {
	registry := include.EndpointRegistry()
	options, loaded := registry.CreateOptions(C.TypeAWG)
	require.True(t, loaded)
	_, err := registry.Create(t.Context(), nil, logger.NOP(), "awg", C.TypeAWG, options)
	require.ErrorContains(t, err, "with_awg")
}

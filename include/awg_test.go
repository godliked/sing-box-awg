package include_test

import (
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

func TestAWGConfiguration(t *testing.T) {
	const canonical = `{"endpoints":[{"type":"awg","system":true,"peers":[{"pre_shared_key":"test"}],"h1":"12345-12400"}]}`
	const aliases = `{"endpoints":[{"type":"awg","useIntegratedTun":true,"peers":[{"preshared_key":"test"}],"h1":"12345-12400"}]}`
	const both = `{"endpoints":[{"type":"awg","system":true,"useIntegratedTun":true,"peers":[{"pre_shared_key":"test","preshared_key":"test"}],"h1":"12345-12400"}]}`
	ctx := include.Context(t.Context())
	for _, config := range []string{canonical, aliases, both} {
		parsed, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
		require.NoError(t, err)
		formatted, err := json.MarshalContext(ctx, &parsed.Endpoints[0])
		require.NoError(t, err)
		require.JSONEq(t, `{"type":"awg","system":true,"address":null,"private_key":"","peers":[{"pre_shared_key":"test"}],"h1":"12345-12400"}`, string(formatted))
	}
	for _, test := range []struct {
		fields string
		field  string
	}{
		{`"system":false,"useIntegratedTun":true`, "system conflicts with useIntegratedTun"},
		{`"peers":[{"pre_shared_key":"","preshared_key":"test"}]`, "pre_shared_key conflicts with preshared_key"},
		{`"workers":1`, "workers"},
		{`"peers":[{"reserved":[1,2,3]}]`, "reserved"},
	} {
		_, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"endpoints":[{"type":"awg",`+test.fields+`}]}`))
		require.ErrorContains(t, err, test.field)
	}
}

func TestAWGPersistentKeepaliveConfiguration(t *testing.T) {
	ctx := include.Context(t.Context())
	for _, test := range []struct {
		input string
		field string
	}{
		{`25`, `,"persistent_keepalive_interval":25`},
		{`"25"`, `,"persistent_keepalive_interval":25`},
		{`"20-30"`, `,"persistent_keepalive_interval":"20-30"`},
		{`"70000-70010"`, `,"persistent_keepalive_interval":"70000-70010"`},
		{`4294967295`, `,"persistent_keepalive_interval":4294967295`},
		{`"25-25"`, `,"persistent_keepalive_interval":25`},
		{`"off"`, ""},
		{`0`, ""},
		{`null`, ""},
	} {
		parsed, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"endpoints":[{"type":"awg","peers":[{"public_key":"test","persistent_keepalive_interval":`+test.input+`}]}]}`))
		require.NoError(t, err, test.input)
		formatted, err := json.MarshalContext(ctx, &parsed.Endpoints[0])
		require.NoError(t, err)
		require.JSONEq(t, `{"type":"awg","address":null,"private_key":"","peers":[{"public_key":"test"`+test.field+`}]}`, string(formatted))
	}
	for _, invalid := range []string{`""`, `"30-20"`, `"20-"`, `"-20"`, `"20-30-40"`, `"20-4294967296"`, `"0-4294967295"`, `4294967296`, `-1`, `1.5`, `true`} {
		_, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"endpoints":[{"type":"awg","peers":[{"persistent_keepalive_interval":`+invalid+`}]}]}`))
		require.ErrorContains(t, err, "persistent_keepalive_interval", invalid)
	}
}

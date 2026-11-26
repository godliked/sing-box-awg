package option

import (
	"context"
	"math"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

type _AWGEndpointOptions struct {
	System           *bool                            `json:"system,omitempty"`
	UseIntegratedTun *bool                            `json:"useIntegratedTun,omitempty"`
	Name             string                           `json:"name,omitempty"`
	MTU              uint32                           `json:"mtu,omitempty"`
	Address          badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey       string                           `json:"private_key"`
	ListenPort       uint16                           `json:"listen_port,omitempty"`
	Peers            []AWGPeer                        `json:"peers,omitempty"`
	UDPTimeout       badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPMapping       UDPNATBehavior                   `json:"udp_mapping,omitempty"`
	UDPFiltering     UDPNATBehavior                   `json:"udp_filtering,omitempty"`
	UDPNATMax        uint32                           `json:"udp_nat_max,omitempty"`
	AWGParameters
	DialerOptions
}

type AWGEndpointOptions _AWGEndpointOptions

func (o *AWGEndpointOptions) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	var options _AWGEndpointOptions
	if err := json.UnmarshalContextDisallowUnknownFields(ctx, content, &options); err != nil {
		return err
	}
	if options.UseIntegratedTun != nil {
		if options.System != nil && *options.System != *options.UseIntegratedTun {
			return E.New("system conflicts with useIntegratedTun")
		}
		options.System = options.UseIntegratedTun
		options.UseIntegratedTun = nil
	}
	*o = AWGEndpointOptions(options)
	return nil
}

type _AWGPeer struct {
	Address                     string                           `json:"address,omitempty"`
	Port                        uint16                           `json:"port,omitempty"`
	PublicKey                   string                           `json:"public_key,omitempty"`
	PreSharedKey                *string                          `json:"pre_shared_key,omitempty"`
	LegacyPreSharedKey          *string                          `json:"preshared_key,omitempty"`
	AllowedIPs                  badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval AWGKeepaliveInterval             `json:"persistent_keepalive_interval,omitempty,omitzero"`
}

type AWGPeer _AWGPeer

func (p AWGPeer) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	if err := builder.FlattenStruct(node, reflect.TypeFor[_AWGPeer]()); err != nil {
		return nil, err
	}
	return node, nil
}

func (p *AWGPeer) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	var peer _AWGPeer
	if err := json.UnmarshalContextDisallowUnknownFields(ctx, content, &peer); err != nil {
		return err
	}
	if peer.LegacyPreSharedKey != nil {
		if peer.PreSharedKey != nil && *peer.PreSharedKey != *peer.LegacyPreSharedKey {
			return E.New("pre_shared_key conflicts with preshared_key")
		}
		peer.PreSharedKey = peer.LegacyPreSharedKey
		peer.LegacyPreSharedKey = nil
	}
	*p = AWGPeer(peer)
	return nil
}

type AWGKeepaliveInterval struct {
	minimum uint32
	maximum uint32
}

func (i AWGKeepaliveInterval) IsZero() bool {
	return i.maximum == 0
}

func (i AWGKeepaliveInterval) String() string {
	minimum := strconv.FormatUint(uint64(i.minimum), 10)
	if i.minimum == i.maximum {
		return minimum
	}
	return minimum + "-" + strconv.FormatUint(uint64(i.maximum), 10)
}

func (i AWGKeepaliveInterval) MarshalJSON() ([]byte, error) {
	if i.minimum == i.maximum {
		return json.Marshal(i.minimum)
	}
	return json.Marshal(i.String())
}

func (i *AWGKeepaliveInterval) UnmarshalJSON(content []byte) error {
	var seconds uint32
	if err := json.Unmarshal(content, &seconds); err == nil {
		*i = AWGKeepaliveInterval{minimum: seconds, maximum: seconds}
		return nil
	}
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return E.New("persistent_keepalive_interval must be an unsigned 32-bit integer, a range, or \"off\"")
	}
	if value == "off" {
		*i = AWGKeepaliveInterval{}
		return nil
	}
	minimum, maximum, isRange := strings.Cut(value, "-")
	if !isRange {
		maximum = minimum
	}
	lower, err := strconv.ParseUint(minimum, 10, 32)
	if err != nil {
		return E.Cause(err, "invalid persistent_keepalive_interval lower bound")
	}
	upper, err := strconv.ParseUint(maximum, 10, 32)
	if err != nil {
		return E.Cause(err, "invalid persistent_keepalive_interval upper bound")
	}
	if upper < lower {
		return E.New("persistent_keepalive_interval upper bound is less than the lower bound")
	}
	if lower == 0 && upper == math.MaxUint32 {
		return E.New("persistent_keepalive_interval range size exceeds the AmneziaWG timer limit")
	}
	*i = AWGKeepaliveInterval{minimum: uint32(lower), maximum: uint32(upper)}
	return nil
}

func (i AWGKeepaliveInterval) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.AnyOf(
		schema.UnsignedNode(32),
		&schema.Node{Type: "string", Pattern: `^(off|[0-9]+(-[0-9]+)?)$`},
	), nil
}

type AWGParameters struct {
	Jc                     uint32 `json:"jc,omitempty"`
	Jmin                   uint32 `json:"jmin,omitempty"`
	Jmax                   uint32 `json:"jmax,omitempty"`
	S1                     uint16 `json:"s1,omitempty"`
	S2                     uint16 `json:"s2,omitempty"`
	S3                     uint16 `json:"s3,omitempty"`
	S4                     uint16 `json:"s4,omitempty"`
	H1                     string `json:"h1,omitempty"`
	H2                     string `json:"h2,omitempty"`
	H3                     string `json:"h3,omitempty"`
	H4                     string `json:"h4,omitempty"`
	I1                     string `json:"i1,omitempty"`
	I2                     string `json:"i2,omitempty"`
	I3                     string `json:"i3,omitempty"`
	I4                     string `json:"i4,omitempty"`
	I5                     string `json:"i5,omitempty"`
	HeaderProtectionKey    string `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         string `json:"rekey_after_time,omitempty"`
	RekeyTimeout           string `json:"rekey_timeout,omitempty"`
	RejectAfterTime        string `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       string `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   string `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool   `json:"random_trailers,omitempty"`
	DisableCookies         bool   `json:"disable_cookies,omitempty"`
}

package awg

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

func validatePacketSizes(mtu uint32, parameters option.AWGParameters) error {
	if uint64(mtu)+uint64(parameters.S4) > device.MaxContentSize {
		return E.New("mtu and s4 exceed the AmneziaWG transport packet size limit")
	}
	if int(parameters.S1)+device.MessageInitiationSize > device.MaxMessageSize ||
		int(parameters.S2)+device.MessageResponseSize > device.MaxMessageSize ||
		int(parameters.S3)+device.MessageCookieReplySize > device.MaxMessageSize {
		return E.New("handshake padding exceeds the AmneziaWG packet size limit")
	}
	if parameters.Jc != 0 && (parameters.Jmin > parameters.Jmax || parameters.Jmax > device.MaxMessageSize) {
		return E.New("invalid jmin/jmax packet sizes")
	}
	return nil
}

func writeParameters(ipc *strings.Builder, parameters option.AWGParameters) error {
	for _, field := range []struct {
		name  string
		value uint32
	}{
		{"jc", parameters.Jc},
		{"jmin", parameters.Jmin},
		{"jmax", parameters.Jmax},
		{"s1", uint32(parameters.S1)},
		{"s2", uint32(parameters.S2)},
		{"s3", uint32(parameters.S3)},
		{"s4", uint32(parameters.S4)},
	} {
		if field.value != 0 {
			ipc.WriteString("\n" + field.name + "=" + F.ToString(field.value))
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"h1", parameters.H1},
		{"h2", parameters.H2},
		{"h3", parameters.H3},
		{"h4", parameters.H4},
		{"i1", parameters.I1},
		{"i2", parameters.I2},
		{"i3", parameters.I3},
		{"i4", parameters.I4},
		{"i5", parameters.I5},
		{"content_padding_addition", parameters.ContentPaddingAddition},
		{"rekey_after_time", parameters.RekeyAfterTime},
		{"rekey_timeout", parameters.RekeyTimeout},
		{"reject_after_time", parameters.RejectAfterTime},
		{"keepalive_timeout", parameters.KeepaliveTimeout},
		{"max_handshake_attempts", parameters.MaxHandshakeAttempts},
	} {
		if strings.ContainsAny(field.value, "\r\n") {
			return E.New(field.name, " must be a single line")
		}
		if field.value != "" {
			ipc.WriteString("\n" + field.name + "=" + field.value)
		}
	}
	if parameters.HeaderProtectionKey != "" {
		key, err := decodeKey(parameters.HeaderProtectionKey)
		if err != nil {
			return E.Cause(err, "decode header_protection_key")
		}
		ipc.WriteString("\nheader_protection_key=" + key)
	}
	if parameters.RandomTrailers {
		ipc.WriteString("\nrandom_trailers=true")
	}
	if parameters.DisableCookies {
		ipc.WriteString("\ndisable_cookies=true")
	}
	return nil
}

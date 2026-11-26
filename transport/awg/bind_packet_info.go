package awg

import (
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type udpReplySource struct {
	address netip.Addr
	control []byte
	socket  *net.UDPConn
}

type udpPacketReader func([]byte) (int, netip.AddrPort, *udpReplySource, error)

func udpPacketReaderWithoutSource(read func([]byte) (int, netip.AddrPort, error)) udpPacketReader {
	return func(packet []byte) (int, netip.AddrPort, *udpReplySource, error) {
		size, remoteAddress, err := read(packet)
		return size, remoteAddress, nil, err
	}
}

func newUDPPacketReader(socket *net.UDPConn, network string) (udpPacketReader, error) {
	if !socket.LocalAddr().(*net.UDPAddr).AddrPort().Addr().IsUnspecified() {
		return udpPacketReaderWithoutSource(socket.ReadFromUDPAddrPort), nil
	}
	if network == "udp4" {
		const flags = ipv4.FlagDst | ipv4.FlagInterface
		controlBuffer := ipv4.NewControlMessage(flags)
		if len(controlBuffer) == 0 {
			return udpPacketReaderWithoutSource(socket.ReadFromUDPAddrPort), nil
		}
		if err := ipv4.NewPacketConn(socket).SetControlMessage(flags, true); err != nil {
			return nil, err
		}
		return udpMessageReader(socket, controlBuffer, func(control []byte) (*udpReplySource, error) {
			var message ipv4.ControlMessage
			if err := message.Parse(control); err != nil {
				return nil, err
			}
			reply := ipv4.ControlMessage{Src: message.Dst, IfIndex: message.IfIndex}
			return newUDPReplySource(message.Dst, reply.Marshal()), nil
		}), nil
	}
	const flags = ipv6.FlagDst | ipv6.FlagInterface
	controlBuffer := ipv6.NewControlMessage(flags)
	if len(controlBuffer) == 0 {
		return udpPacketReaderWithoutSource(socket.ReadFromUDPAddrPort), nil
	}
	if err := ipv6.NewPacketConn(socket).SetControlMessage(flags, true); err != nil {
		return nil, err
	}
	return udpMessageReader(socket, controlBuffer, func(control []byte) (*udpReplySource, error) {
		var message ipv6.ControlMessage
		if err := message.Parse(control); err != nil {
			return nil, err
		}
		reply := ipv6.ControlMessage{Src: message.Dst, IfIndex: message.IfIndex}
		return newUDPReplySource(message.Dst, reply.Marshal()), nil
	}), nil
}

func udpMessageReader(socket *net.UDPConn, controlBuffer []byte, parseSource func([]byte) (*udpReplySource, error)) udpPacketReader {
	return func(packet []byte) (int, netip.AddrPort, *udpReplySource, error) {
		size, controlSize, _, remoteAddress, err := socket.ReadMsgUDPAddrPort(packet, controlBuffer)
		if err != nil || controlSize == 0 {
			return size, remoteAddress, nil, err
		}
		source, err := parseSource(controlBuffer[:controlSize])
		if source != nil {
			source.socket = socket
		}
		return size, remoteAddress, source, err
	}
}

func newUDPReplySource(ip net.IP, control []byte) *udpReplySource {
	address, valid := netip.AddrFromSlice(ip)
	if !valid || len(control) == 0 {
		return nil
	}
	if !address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast() {
		return nil
	}
	return &udpReplySource{address: address.Unmap(), control: control}
}

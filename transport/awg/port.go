package awg

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

func (e *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	return e.tunDevice.Inet4Address(), e.tunDevice.Inet6Address()
}

func (e *Endpoint) PortMTU() uint32 {
	return e.options.MTU
}

func (e *Endpoint) WritePackets(packets [][]byte) error {
	if !e.ready.Load() {
		return E.New("AmneziaWG device is not ready")
	}
	state := e.returnDevice.state.Load()
	var replies [][]byte
	for _, packet := range packets {
		if len(packet) == 0 {
			continue
		}
		var destination, source netip.Addr
		switch header.IPVersion(packet) {
		case header.IPv4Version:
			if len(packet) < header.IPv4MinimumSize {
				continue
			}
			destination = netip.AddrFrom4([4]byte(header.IPv4(packet).DestinationAddressSlice()))
			source = e.tunDevice.Inet4Address()
		case header.IPv6Version:
			if len(packet) < header.IPv6MinimumSize {
				continue
			}
			destination = netip.AddrFrom16([16]byte(header.IPv6(packet).DestinationAddressSlice()))
			source = e.tunDevice.Inet6Address()
		default:
			continue
		}
		if e.allowedIPs.Contains(destination) {
			e.tunDevice.EnqueuePacket(packet)
			continue
		}
		if state == nil {
			continue
		}
		reply, replyOk := tun.BuildUnreachable(packet, source, state.headroom)
		if replyOk {
			replies = append(replies, reply)
		}
	}
	if len(replies) > 0 {
		state.returnPath.ReturnPackets(replies)
	}
	return nil
}

func (e *Endpoint) AttachReturn(returnPath tun.Return) error {
	headroom := returnPath.ReturnHeadroom()
	if headroom < 0 {
		return E.New("invalid negative return path headroom")
	}
	if headroom > device.MessageTransportOffsetContent {
		return E.New("return path headroom ", headroom, " exceeds available ", device.MessageTransportOffsetContent)
	}
	newState := &returnPathState{
		returnPath: returnPath,
		headroom:   headroom,
	}
	for {
		currentState := e.returnDevice.state.Load()
		if currentState != nil {
			if currentState.returnPath == returnPath {
				return nil
			}
			return E.New("return path already attached")
		}
		if e.returnDevice.state.CompareAndSwap(nil, newState) {
			return nil
		}
	}
}

func (e *Endpoint) DetachReturn(returnPath tun.Return) error {
	currentState := e.returnDevice.state.Load()
	if currentState != nil && currentState.returnPath == returnPath {
		e.returnDevice.state.CompareAndSwap(currentState, nil)
	}
	return nil
}

type returnPathState struct {
	returnPath tun.Return
	headroom   int
}

type returnDeviceWrapper struct {
	Device
	state       atomic.Pointer[returnPathState]
	writeAccess sync.Mutex
}

func (d *returnDeviceWrapper) Write(bufs [][]byte, offset int) (int, error) {
	// The AWG library can deliver packets from different peers concurrently.
	d.writeAccess.Lock()
	defer d.writeAccess.Unlock()
	state := d.state.Load()
	if state == nil || len(bufs) == 0 {
		return d.Device.Write(bufs, offset)
	}
	packets := make([][]byte, len(bufs))
	for i, packet := range bufs {
		// amneziawg-go leaves writable transport header bytes before the packet.
		packets[i] = packet[offset-state.headroom:]
	}
	unconsumed := state.returnPath.ReturnPackets(packets)
	if len(unconsumed) == 0 {
		return 0, nil
	}
	if len(unconsumed) == len(bufs) {
		return d.Device.Write(bufs, offset)
	}
	remaining := make([][]byte, 0, len(unconsumed))
	searchIndex := 0
	for _, packet := range unconsumed {
		for searchIndex < len(bufs) && &packet[0] != &bufs[searchIndex][offset-state.headroom] {
			searchIndex++
		}
		if searchIndex == len(bufs) {
			break
		}
		remaining = append(remaining, bufs[searchIndex])
		searchIndex++
	}
	return d.Device.Write(remaining, offset)
}

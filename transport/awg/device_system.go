package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	awgTun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

var _ Device = (*systemDevice)(nil)

type systemDevice struct {
	options        DeviceOptions
	dialer         N.Dialer
	device         tun.Tun
	batchDevice    tun.LinuxTUN
	events         chan awgTun.Event
	packetOutbound *packetQueue
	readReady      chan systemRead
	readConsumed   chan struct{}
	readerDone     chan struct{}
	closeOnce      sync.Once
	closeErr       error
	inet4Address   netip.Addr
	inet6Address   netip.Addr
}

type systemRead struct {
	packets [][]byte
	err     error
}

func newSystemDevice(options DeviceOptions) (*systemDevice, error) {
	if options.Name == "" {
		options.Name = tun.CalculateInterfaceName("awg")
	}
	var inet4Address netip.Addr
	var inet6Address netip.Addr
	if len(options.Address) > 0 {
		if prefix := common.Find(options.Address, func(it netip.Prefix) bool {
			return it.Addr().Is4()
		}); prefix.IsValid() {
			inet4Address = prefix.Addr()
		}
	}
	if len(options.Address) > 0 {
		if prefix := common.Find(options.Address, func(it netip.Prefix) bool {
			return it.Addr().Is6()
		}); prefix.IsValid() {
			inet6Address = prefix.Addr()
		}
	}
	return &systemDevice{
		options:        options,
		dialer:         options.CreateDialer(options.Name),
		events:         make(chan awgTun.Event, 1),
		packetOutbound: newPacketQueue(options.MTU),
		readReady:      make(chan systemRead),
		readConsumed:   make(chan struct{}),
		inet4Address:   inet4Address,
		inet6Address:   inet6Address,
	}, nil
}

func (w *systemDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return w.dialer.DialContext(ctx, network, destination)
}

func (w *systemDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return w.dialer.ListenPacket(ctx, destination)
}

func (w *systemDevice) Inet4Address() netip.Addr {
	return w.inet4Address
}

func (w *systemDevice) Inet6Address() netip.Addr {
	return w.inet6Address
}

func (w *systemDevice) EnqueuePacket(packetSlices ...[]byte) {
	w.packetOutbound.enqueue(packetSlices)
}

func (w *systemDevice) Start() error {
	networkManager := service.FromContext[adapter.NetworkManager](w.options.Context)
	tunOptions := tun.Options{
		Name: w.options.Name,
		Inet4Address: common.Filter(w.options.Address, func(it netip.Prefix) bool {
			return it.Addr().Is4()
		}),
		Inet6Address: common.Filter(w.options.Address, func(it netip.Prefix) bool {
			return it.Addr().Is6()
		}),
		MTU:            w.options.MTU,
		GSO:            true,
		InterfaceScope: true,
		DNSMode:        tun.DNSModeDisabled,
		Inet4RouteAddress: common.Filter(w.options.AllowedAddress, func(it netip.Prefix) bool {
			return it.Addr().Is4()
		}),
		Inet6RouteAddress: common.Filter(w.options.AllowedAddress, func(it netip.Prefix) bool { return it.Addr().Is6() }),
		InterfaceMonitor:  networkManager.InterfaceMonitor(),
		InterfaceFinder:   networkManager.InterfaceFinder(),
		Logger:            w.options.Logger,
	}
	// works with Linux, macOS with IFSCOPE routes, not tested on Windows
	if runtime.GOOS == "darwin" {
		tunOptions.AutoRoute = true
	}
	tunInterface, err := tun.New(tunOptions)
	if err != nil {
		return err
	}
	err = tunInterface.Start()
	if err != nil {
		tunInterface.Close()
		return err
	}
	w.options.Logger.Info("started at ", w.options.Name)
	w.device = tunInterface
	batchTUN, isBatchTUN := tunInterface.(tun.LinuxTUN)
	if isBatchTUN && batchTUN.BatchSize() > 1 {
		w.batchDevice = batchTUN
	}
	w.readerDone = make(chan struct{})
	go w.readSystemTUN()
	return nil
}

func (w *systemDevice) File() *os.File {
	return nil
}

func (w *systemDevice) readSystemTUN() {
	defer close(w.readerDone)
	batchSize := w.BatchSize()
	buffers := make([][]byte, batchSize)
	packets := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, int(w.options.MTU)+tun.PacketOffset)
	}
	for {
		count, err := w.readSystemBatch(buffers, sizes)
		for i := range count {
			packets[i] = buffers[i][tun.PacketOffset : tun.PacketOffset+sizes[i]]
		}
		select {
		case <-w.packetOutbound.done:
			return
		case w.readReady <- systemRead{packets[:count], err}:
		}
		// Read owns the scratch buffers until the batch has been copied.
		select {
		case <-w.packetOutbound.done:
			return
		case <-w.readConsumed:
		}
		if err != nil && !errors.Is(err, awgTun.ErrTooManySegments) {
			return
		}
	}
}

func (w *systemDevice) readSystemBatch(bufs [][]byte, sizes []int) (count int, err error) {
	if w.batchDevice != nil {
		count, err = w.batchDevice.BatchRead(bufs, 0, sizes)
	} else {
		sizes[0], err = w.device.Read(bufs[0])
		if err == nil {
			sizes[0] = max(0, sizes[0]-tun.PacketOffset)
			count = 1
		}
	}
	if errors.Is(err, tun.ErrTooManySegments) {
		err = awgTun.ErrTooManySegments
	}
	return
}

func (w *systemDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-w.packetOutbound.done:
		return 0, os.ErrClosed
	case packet := <-w.packetOutbound.packets:
		sizes[0] = copyPacket(bufs[0], offset, packet)
		return 1, nil
	case result := <-w.readReady:
		for i, packet := range result.packets {
			sizes[i] = copyPacket(bufs[i], offset, packet)
		}
		select {
		case <-w.packetOutbound.done:
			return 0, os.ErrClosed
		case w.readConsumed <- struct{}{}:
		}
		return len(result.packets), result.err
	}
}

func (w *systemDevice) Write(bufs [][]byte, offset int) (count int, err error) {
	if w.batchDevice != nil {
		return w.batchDevice.BatchWrite(bufs, offset)
	} else {
		for _, packet := range bufs {
			if tun.PacketOffset > 0 {
				clear(packet[offset-tun.PacketOffset : offset])
				tun.PacketFillHeader(packet[offset-tun.PacketOffset:], tun.PacketIPVersion(packet[offset:]))
			}
			_, err = w.device.Write(packet[offset-tun.PacketOffset:])
			if err != nil {
				return
			}
		}
	}
	return
}

func (w *systemDevice) Flush() error {
	return nil
}

func (w *systemDevice) MTU() (int, error) {
	return int(w.options.MTU), nil
}

func (w *systemDevice) Name() (string, error) {
	return w.options.Name, nil
}

func (w *systemDevice) Events() <-chan awgTun.Event {
	return w.events
}

func (w *systemDevice) Close() error {
	w.closeOnce.Do(func() {
		w.packetOutbound.close()
		close(w.events)
		if w.device != nil {
			w.closeErr = w.device.Close()
		}
		if w.readerDone != nil {
			<-w.readerDone
		}
	})
	return w.closeErr
}

func (w *systemDevice) BatchSize() int {
	if w.batchDevice != nil {
		return w.batchDevice.BatchSize()
	}
	return 1
}

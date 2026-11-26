package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/powerreport"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"go4.org/netipx"
)

type Endpoint struct {
	options       EndpointOptions
	ipcConf       string
	peers         []peerConfig
	allowedIPs    *netipx.IPSet
	tunDevice     Device
	returnDevice  *returnDeviceWrapper
	access        sync.Mutex
	device        *device.Device
	clientBind    *clientBind
	egressPool    *tun.UDPEgressPool
	pause         pause.Manager
	pauseCallback *list.Element[pause.Callback]
	ready         atomic.Bool
	closed        bool
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKey, err := decodeKey(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	if options.MTU == 0 {
		options.MTU = 1408
	}
	if err := validatePacketSizes(options.MTU, options.Parameters); err != nil {
		return nil, err
	}
	var ipcConf strings.Builder
	ipcConf.WriteString("private_key=" + privateKey)
	if options.ListenPort != 0 {
		ipcConf.WriteString("\nlisten_port=" + F.ToString(options.ListenPort))
	}
	if err := writeParameters(&ipcConf, options.Parameters); err != nil {
		return nil, err
	}

	peers := make([]peerConfig, 0, len(options.Peers))
	var allowedPrefixBuilder netipx.IPSetBuilder
	for index, rawPeer := range options.Peers {
		peer := peerConfig{
			destination: rawPeer.Endpoint,
			allowedIPs:  rawPeer.AllowedIPs,
			keepalive:   rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.IsIP() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		}
		if peer.destination.IsValid() && peer.destination.Port == 0 {
			return nil, E.New("missing port for peer ", index)
		}
		if !peer.destination.IsValid() && peer.destination.Port != 0 {
			return nil, E.New("missing address for peer ", index)
		}
		peer.publicKeyHex, err = decodeKey(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", index)
		}
		if rawPeer.PreSharedKey != "" {
			peer.preSharedKeyHex, err = decodeKey(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", index)
			}
		}
		if len(peer.allowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", index)
		}
		for _, prefix := range peer.allowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
		peers = append(peers, peer)
	}
	allowedIPs, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	if options.System && options.Name == "" {
		options.Name = tun.CalculateInterfaceName("awg")
		options.EgressPoolOptions.ExcludeInterface = options.Name
	}
	tunDevice, err := NewDevice(DeviceOptions{
		Context:         options.Context,
		Logger:          options.Logger,
		System:          options.System,
		Handler:         options.Handler,
		UDPTimeout:      options.UDPTimeout,
		ICMPTimeout:     options.ICMPTimeout,
		UDPMapping:      options.UDPMapping,
		UDPFiltering:    options.UDPFiltering,
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: options.InterfaceFinder,
		CreateDialer:    options.CreateDialer,
		Name:            options.Name,
		MTU:             options.MTU,
		Address:         options.Address,
		AllowedAddress:  allowedIPs.Prefixes(),
	})
	if err != nil {
		return nil, E.Cause(err, "create AmneziaWG device")
	}
	return &Endpoint{
		options:      options,
		ipcConf:      ipcConf.String(),
		peers:        peers,
		allowedIPs:   allowedIPs,
		tunDevice:    tunDevice,
		returnDevice: &returnDeviceWrapper{Device: tunDevice},
	}, nil
}

func (e *Endpoint) Start(postStart bool) error {
	e.access.Lock()
	defer e.access.Unlock()
	if e.closed {
		return net.ErrClosed
	}
	if e.device != nil || postStart != common.Any(e.peers, func(peer peerConfig) bool { return peer.destination.IsDomain() }) {
		return nil
	}
	var ipcConf strings.Builder
	ipcConf.WriteString(e.ipcConf)
	for index := range e.peers {
		peer := &e.peers[index]
		if peer.destination.IsDomain() {
			endpoint, err := e.resolvePeer(e.options.Context, peer.destination, false)
			if err != nil {
				_ = e.closeLocked()
				return E.Cause(err, "resolve peer ", index)
			}
			peer.endpoint = endpoint
		}
		peer.writeConfig(&ipcConf)
	}

	bind := e.newBind()
	if err := e.tunDevice.Start(); err != nil {
		_ = e.closeLocked()
		return err
	}
	awgDevice := device.NewDevice(e.returnDevice, bind, &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	})
	e.device = awgDevice
	if e.clientBind != nil && len(e.peers) == 1 && e.peers[0].destination.IsDomain() {
		// Only DNS can move this connected detour. Queued packets from the old
		// socket must not restore its address after a refresh.
		awgDevice.DisableSomeRoamingForBrokenMobileSemantics()
	}
	if err := awgDevice.IpcSet(ipcConf.String()); err != nil {
		_ = e.closeLocked()
		return E.Cause(err, "configure AmneziaWG")
	}
	if err := awgDevice.Up(); err != nil {
		_ = e.closeLocked()
		return E.Cause(err, "start AmneziaWG")
	}
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(func(event int) {
			var err error
			switch event {
			case pause.EventNetworkPause:
				err = awgDevice.Down()
			case pause.EventNetworkWake:
				err = awgDevice.Up()
			}
			if err != nil {
				e.options.Logger.Error(E.Cause(err, "update AmneziaWG network state"))
			}
		})
	}
	e.ready.Store(true)
	return nil
}

func (e *Endpoint) newBind() conn.Bind {
	udpListener, isUDPListener := common.Cast[dialer.UDPListener](e.options.Dialer)
	if !isUDPListener {
		var connectAddress netip.AddrPort
		if len(e.peers) == 1 {
			connectAddress = e.peers[0].endpoint
		}
		e.clientBind = &clientBind{
			ctx:            e.options.Context,
			logger:         e.options.Logger,
			dialer:         e.options.Dialer,
			connectAddress: connectAddress,
		}
		return e.clientBind
	}
	listenerControl, egressEnabled := udpListener.UDPListenerControl()
	bind := &standardBind{
		ctx:              e.options.Context,
		listenConfig:     net.ListenConfig{Control: listenerControl},
		listenPort:       e.options.ListenPort,
		bindAddress4:     e.options.BindAddress4,
		bindAddress6:     e.options.BindAddress6,
		networkNamespace: e.options.NetworkNamespace,
	}
	if egressEnabled && bind.networkNamespace == "" && !bind.bindAddress4.IsValid() && !bind.bindAddress6.IsValid() {
		egressOptions := e.options.EgressPoolOptions
		egressOptions.Control = listenerControl
		e.egressPool = tun.NewUDPEgressPool(egressOptions)
		bind.egressPool = e.egressPool
	}
	if manager := service.FromContext[*powerreport.Manager](e.options.Context); manager != nil {
		if recorder := manager.Recorder(); recorder != nil {
			attribution := &powerreport.Attribution{Endpoint: e.options.Tag}
			bind.onRead = func(size int) { recorder.Touch(powerreport.DirectionInbound, size, attribution) }
			bind.onWrite = func(size int) { recorder.Touch(powerreport.DirectionOutbound, size, attribution) }
		}
	}
	return bind
}

func (e *Endpoint) resolvePeer(ctx context.Context, destination M.Socksaddr, refresh bool) (netip.AddrPort, error) {
	if e.options.ResolvePeer == nil {
		return netip.AddrPort{}, E.New("missing AmneziaWG peer resolver")
	}
	addresses, err := e.options.ResolvePeer(ctx, destination.Fqdn, refresh)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, address := range addresses {
		if address.IsValid() {
			return netip.AddrPortFrom(address.Unmap(), destination.Port), nil
		}
	}
	return netip.AddrPort{}, E.New("no IP addresses for ", destination.Fqdn)
}

func (e *Endpoint) BindUpdate(ctx context.Context) error {
	e.access.Lock()
	defer e.access.Unlock()
	if e.device == nil || ctx.Err() != nil {
		return ctx.Err()
	}
	var refreshErrors []error
	for index := range e.peers {
		peer := &e.peers[index]
		if !peer.destination.IsDomain() {
			continue
		}
		endpoint, err := e.resolvePeer(ctx, peer.destination, true)
		if err != nil {
			refreshErrors = append(refreshErrors, E.Cause(err, "refresh peer ", index))
			continue
		}
		if endpoint == peer.endpoint {
			continue
		}
		err = e.device.IpcSet("public_key=" + peer.publicKeyHex + "\nupdate_only=true\nendpoint=" + endpoint.String())
		if err != nil {
			refreshErrors = append(refreshErrors, E.Cause(err, "update peer ", index))
			continue
		}
		peer.endpoint = endpoint
		if e.clientBind != nil && len(e.peers) == 1 {
			e.clientBind.setConnectAddress(endpoint)
		}
	}
	return errors.Join(append(refreshErrors, e.device.BindUpdate())...)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) PreferredAddress(address netip.Addr) bool {
	return e.ready.Load() && e.allowedIPs.Contains(address)
}

func (e *Endpoint) Close() error {
	e.access.Lock()
	defer e.access.Unlock()
	return e.closeLocked()
}

func (e *Endpoint) closeLocked() error {
	if e.closed {
		return nil
	}
	e.closed = true
	e.ready.Store(false)
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
	}
	if e.device != nil {
		e.device.Close()
		e.device = nil
	}
	if e.egressPool != nil {
		e.egressPool.Close()
	}
	return e.tunDevice.Close()
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKeyHex    string
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       option.AWGKeepaliveInterval
}

func (c peerConfig) writeConfig(ipc *strings.Builder) {
	ipc.WriteString("\npublic_key=" + c.publicKeyHex)
	if c.endpoint.IsValid() {
		ipc.WriteString("\nendpoint=" + c.endpoint.String())
	}
	if c.preSharedKeyHex != "" {
		ipc.WriteString("\npreshared_key=" + c.preSharedKeyHex)
	}
	for _, allowedIP := range c.allowedIPs {
		ipc.WriteString("\nallowed_ip=" + allowedIP.String())
	}
	if !c.keepalive.IsZero() {
		ipc.WriteString("\npersistent_keepalive_interval=" + c.keepalive.String())
	}
}

func decodeKey(value string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", E.New("expected a 32-byte key")
	}
	return hex.EncodeToString(key), nil
}

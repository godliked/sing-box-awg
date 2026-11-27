//go:build with_gvisor

package awg

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestAWGLoopback(t *testing.T) {
	t.Run("direct", func(t *testing.T) { exerciseLoopback(t, false, false) })
	t.Run("detour", func(t *testing.T) { exerciseLoopback(t, false, true) })
}

func TestAWGMultiplePeersOverDestinationBoundDetour(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientAddress := netip.MustParsePrefix("10.203.0.1/32")
	serverAddresses := []netip.Prefix{netip.MustParsePrefix("10.203.0.2/32"), netip.MustParsePrefix("10.203.0.3/32")}
	servers := make([]*Endpoint, 0, len(serverAddresses))
	peers := make([]PeerOptions, 0, len(serverAddresses))
	for _, address := range serverAddresses {
		serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		server, err := NewEndpoint(EndpointOptions{
			Context: ctx, Logger: logger.NOP(), Dialer: &testUDPDialer{},
			Address: []netip.Prefix{address}, PrivateKey: base64.StdEncoding.EncodeToString(serverKey.Bytes()),
			Peers: []PeerOptions{{
				PublicKey:  base64.StdEncoding.EncodeToString(clientKey.PublicKey().Bytes()),
				AllowedIPs: []netip.Prefix{clientAddress},
			}},
		})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, server.Close()) })
		require.NoError(t, server.Start(false))
		servers = append(servers, server)
		peers = append(peers, PeerOptions{
			Endpoint:   M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), readAWGListenPort(t, server)),
			PublicKey:  base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
			AllowedIPs: []netip.Prefix{address},
		})
	}
	resolvedAddress := peers[0].Endpoint.Addr
	peers[0].Endpoint = M.ParseSocksaddrHostPort("awg.test", peers[0].Endpoint.Port)
	detour := &testDestinationBoundDialer{destinations: make(chan netip.AddrPort, len(peers)*2)}
	client, err := NewEndpoint(EndpointOptions{
		Context: ctx, Logger: logger.NOP(), Dialer: detour,
		Address: []netip.Prefix{clientAddress}, PrivateKey: base64.StdEncoding.EncodeToString(clientKey.Bytes()),
		Peers: peers,
		ResolvePeer: func(_ context.Context, domain string, _ bool) ([]netip.Addr, error) {
			require.Equal(t, "awg.test", domain)
			return []netip.Addr{resolvedAddress}, nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.NoError(t, client.Start(true))

	checkTraffic := func() {
		for i, server := range servers {
			testDatagram(t, ctx, client, server, serverAddresses[i].Addr())
		}
		destinations := make([]netip.AddrPort, 0, len(peers))
		for range peers {
			select {
			case destination := <-detour.destinations:
				destinations = append(destinations, destination)
			case <-ctx.Done():
				t.Fatal("detour did not dial both peers: ", ctx.Err())
			}
		}
		require.ElementsMatch(t, []netip.AddrPort{
			netip.AddrPortFrom(resolvedAddress, peers[0].Endpoint.Port),
			peers[1].Endpoint.AddrPort(),
		}, destinations)
	}
	checkTraffic()
	resolvedAddress = netip.MustParseAddr("127.0.0.2")
	require.NoError(t, client.BindUpdate(ctx))
	checkTraffic()
}

func TestAWGNetworkWakeDoesNotBlockPauseManager(t *testing.T) {
	ctx := pause.WithDefaultManager(service.ContextWithDefaultRegistry(t.Context()))
	pauseManager := service.FromContext[pause.Manager](ctx)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var blockOpen atomic.Bool
	opening := make(chan struct{})
	continueOpen := make(chan struct{})
	resumeOpen := sync.OnceFunc(func() { close(continueOpen) })
	endpoint, err := NewEndpoint(EndpointOptions{
		Context: ctx, Logger: logger.NOP(),
		Address:    []netip.Prefix{netip.MustParsePrefix("10.202.0.1/32")},
		PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()),
		Dialer: &testUDPDialer{control: func(string, string, syscall.RawConn) error {
			if blockOpen.Swap(false) {
				close(opening)
				<-continueOpen
			}
			return nil
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, endpoint.Close()) })
	defer resumeOpen()
	pauseManager.DevicePause()
	require.NoError(t, endpoint.Start(false))
	bind := endpoint.device.Bind().(*standardBind)
	isOpen := func() bool {
		bind.access.Lock()
		defer bind.access.Unlock()
		return bind.ipv4 != nil || bind.ipv6 != nil
	}
	require.True(t, isOpen())
	pauseManager.NetworkPause()
	require.Eventually(t, func() bool { return !isOpen() }, 5*time.Second, time.Millisecond)
	pauseManager.DeviceWake()
	endpoint.updatePauseState(false)
	require.False(t, isOpen())
	blockOpen.Store(true)
	woke := make(chan struct{})
	go func() {
		pauseManager.NetworkWake()
		close(woke)
	}()
	select {
	case <-opening:
	case <-time.After(5 * time.Second):
		t.Fatal("AWG did not reopen its bind")
	}
	select {
	case <-woke:
	case <-time.After(5 * time.Second):
		t.Fatal("opening the AWG bind blocked the pause manager")
	}
	pauseManager.NetworkPause()
	resumeOpen()
	require.Eventually(t, func() bool { return !isOpen() }, 5*time.Second, time.Millisecond)
	pauseManager.NetworkWake()
	require.Eventually(t, isOpen, 5*time.Second, time.Millisecond)
}

func TestAWGDetourRetryDoesNotWaitForDeviceWake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := pause.WithDefaultManager(service.ContextWithDefaultRegistry(t.Context()))
		manager := service.FromContext[pause.Manager](ctx)
		bind := &clientBind{ctx: ctx, logger: logger.NOP(), dialer: &testDestinationBoundDialer{}}
		receive, _, err := bind.Open(0)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, bind.Close()) })

		result := make(chan error, 1)
		startReceive := func() {
			go func() {
				// The dialer rejects the packet listener, so no buffers are needed.
				_, err := receive[0](nil, nil, nil)
				result <- err
			}()
			synctest.Wait()
		}
		manager.DevicePause()
		startReceive()
		require.Empty(t, result)
		time.Sleep(time.Second)
		synctest.Wait()
		require.Len(t, result, 1)
		require.NoError(t, <-result)

		startReceive()
		require.Empty(t, result)
		require.NoError(t, bind.Close())
		synctest.Wait()
		require.Len(t, result, 1)
		require.ErrorIs(t, <-result, net.ErrClosed)
	})
}

func TestAWGCloseBeforeStart(t *testing.T) {
	address := netip.MustParsePrefix("10.202.0.1/32")
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    t.Context(),
		Logger:     logger.NOP(),
		Address:    []netip.Prefix{address},
		PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, endpoint.Close()) })
	require.Nil(t, endpoint.tunDevice)
	inet4Address, inet6Address := endpoint.PortAddresses()
	require.Equal(t, address.Addr(), inet4Address)
	require.False(t, inet6Address.IsValid())
	require.NoError(t, endpoint.Close())
	require.ErrorIs(t, endpoint.Start(false), net.ErrClosed)
}

func TestAWGFixedListenPortAfterFailedRebind(t *testing.T) {
	reserved, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := uint16(reserved.LocalAddr().(*net.UDPAddr).Port)
	require.NoError(t, reserved.Close())
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var failOpen bool
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    t.Context(),
		Logger:     logger.NOP(),
		Address:    []netip.Prefix{netip.MustParsePrefix("10.202.0.1/32")},
		PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()),
		ListenPort: port,
		Dialer: &testUDPDialer{control: func(string, string, syscall.RawConn) error {
			if failOpen {
				return errors.New("local interface temporarily unavailable")
			}
			return nil
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, endpoint.Close()) })
	require.NoError(t, endpoint.Start(false))
	require.Equal(t, port, readAWGListenPort(t, endpoint))
	failOpen = true
	require.ErrorContains(t, endpoint.BindUpdate(t.Context()), "local interface temporarily unavailable")
	failOpen = false
	require.NoError(t, endpoint.BindUpdate(t.Context()))
	require.Equal(t, port, readAWGListenPort(t, endpoint))
}

func TestAWGParameterReadback(t *testing.T) {
	headerKey := []byte(strings.Repeat("h", 32))
	config, err := json.UnmarshalExtended[option.AWGEndpointOptions]([]byte(`{
		"jc": 1, "jmin": 24, "jmax": 48,
		"s1": 16, "s2": 16, "s3": 16, "s4": 16,
		"h1": "1001-1009", "h2": "2002", "h3": "3003", "h4": "4004",
		"i1": "<b 0x01>", "i2": "<b 0x02>", "i3": "<b 0x03>",
		"i4": "<b 0x04>", "i5": "<b 0x05>",
		"header_protection_key": "` + base64.StdEncoding.EncodeToString(headerKey) + `",
		"content_padding_addition": "4-8", "rekey_after_time": "100-120",
		"rekey_timeout": "5-7", "reject_after_time": "180-200",
		"keepalive_timeout": "10-15", "max_handshake_attempts": "10-20",
		"random_trailers": true, "disable_cookies": true,
		"peers": [{"persistent_keepalive_interval": "20-30"}]
	}`))
	require.NoError(t, err)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	endpoint, err := NewEndpoint(EndpointOptions{
		Context: t.Context(), Logger: logger.NOP(), Dialer: &testUDPDialer{},
		Address:    []netip.Prefix{netip.MustParsePrefix("10.202.0.1/32")},
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey.Bytes()), Parameters: config.AWGParameters,
		Peers: []PeerOptions{{
			PublicKey:                   base64.StdEncoding.EncodeToString(peerKey.PublicKey().Bytes()),
			AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("10.202.0.2/32")},
			PersistentKeepaliveInterval: config.Peers[0].PersistentKeepaliveInterval,
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, endpoint.Close()) })
	require.NoError(t, endpoint.Start(false))
	ipc, err := endpoint.device.IpcGet()
	require.NoError(t, err)
	actual := make(map[string]string)
	for _, line := range strings.Split(ipc, "\n") {
		if key, value, found := strings.Cut(line, "="); found {
			actual[key] = value
		}
	}
	for key, expected := range map[string]string{
		"jc": "1", "jmin": "24", "jmax": "48",
		"s1": "16", "s2": "16", "s3": "16", "s4": "16",
		"h1": "1001-1009", "h2": "2002", "h3": "3003", "h4": "4004",
		"i1": "<b 0x01>", "i2": "<b 0x02>", "i3": "<b 0x03>",
		"i4": "<b 0x04>", "i5": "<b 0x05>",
		"header_protection_key": hex.EncodeToString(headerKey), "content_padding_addition": "4-8",
		"rekey_after_time": "100-120", "rekey_timeout": "5-7", "reject_after_time": "180-200",
		"keepalive_timeout": "10-15", "max_handshake_attempts": "10-20",
		"random_trailers": "1", "disable_cookies": "1", "persistent_keepalive_interval": "20-30",
	} {
		require.Equal(t, expected, actual[key], key)
	}
}

func TestAWGSystemLoopback(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("SING_BOX_TEST_AWG_SYSTEM_TUN") != "1" {
		t.Skip("requires Linux with CAP_NET_ADMIN and SING_BOX_TEST_AWG_SYSTEM_TUN=1")
	}
	exerciseLoopback(t, true, false)
}

func TestAWGSystemAutomaticInterfaceNames(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("SING_BOX_TEST_AWG_SYSTEM_TUN") != "1" {
		t.Skip("requires Linux with CAP_NET_ADMIN and SING_BOX_TEST_AWG_SYSTEM_TUN=1")
	}
	finder := control.NewDefaultInterfaceFinder()
	ctx := service.ContextWithDefaultRegistry(t.Context())
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &testNetworkManager{finder: finder})
	endpoints := make([]*Endpoint, 0, 2)
	for _, address := range []string{"10.202.1.1/32", "10.202.1.2/32"} {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		endpoint, err := NewEndpoint(EndpointOptions{
			Context:    ctx,
			Logger:     logger.NOP(),
			System:     true,
			Address:    []netip.Prefix{netip.MustParsePrefix(address)},
			PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()),
			Dialer:     &testUDPDialer{},
			CreateDialer: func(name string) N.Dialer {
				return &testUDPDialer{control: control.BindToInterface(finder, name, -1)}
			},
		})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, endpoint.Close()) })
		endpoints = append(endpoints, endpoint)
	}
	startErrors := make(chan error, len(endpoints))
	for _, endpoint := range endpoints {
		go func() { startErrors <- endpoint.Start(false) }()
	}
	var startupErrors []error
	for range endpoints {
		startupErrors = append(startupErrors, <-startErrors)
	}
	require.NoError(t, errors.Join(startupErrors...))
	firstName, err := endpoints[0].tunDevice.Name()
	require.NoError(t, err)
	secondName, err := endpoints[1].tunDevice.Name()
	require.NoError(t, err)
	require.NotEqual(t, firstName, secondName)
}

func exerciseLoopback(t *testing.T, system, detour bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	psk := make([]byte, 32)
	_, err = rand.Read(psk)
	require.NoError(t, err)
	parameters := option.AWGParameters{
		Jc: 1, Jmin: 24, Jmax: 48,
		S1: 29, S2: 43, S3: 20, S4: 16,
		H1: "1000041001-1000041009", H2: "2000041002", H3: "3000041003", H4: "4000041004",
		HeaderProtectionKey: base64.StdEncoding.EncodeToString(psk),
	}
	clientAddresses := []netip.Prefix{netip.MustParsePrefix("10.201.0.1/24"), netip.MustParsePrefix("fd00:201::1/64")}
	serverAddresses := []netip.Prefix{netip.MustParsePrefix("10.201.0.2/32"), netip.MustParsePrefix("fd00:201::2/128")}
	server, err := NewEndpoint(EndpointOptions{
		Context: ctx, Logger: logger.NOP(), Dialer: &testUDPDialer{}, Address: serverAddresses,
		PrivateKey: base64.StdEncoding.EncodeToString(serverKey.Bytes()), Parameters: parameters,
		Peers: []PeerOptions{{
			PublicKey: base64.StdEncoding.EncodeToString(clientKey.PublicKey().Bytes()), PreSharedKey: base64.StdEncoding.EncodeToString(psk),
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(clientAddresses[0].Addr(), 32), netip.PrefixFrom(clientAddresses[1].Addr(), 128)},
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	require.NoError(t, server.Start(false))
	port := readAWGListenPort(t, server)

	var resolveErr error
	var resolveCalls int
	resolvedAddress := netip.MustParseAddr("127.0.0.1")
	var finder control.InterfaceFinder
	if system {
		finder = control.NewDefaultInterfaceFinder()
		ctx = service.ContextWith[adapter.NetworkManager](ctx, &testNetworkManager{finder: finder})
	}
	var clientDialer N.Dialer = &testUDPDialer{}
	var detourDialer *testDestinationBoundDialer
	var pauseManager pause.Manager
	if detour {
		ctx = pause.WithDefaultManager(service.ContextWithDefaultRegistry(ctx))
		pauseManager = service.FromContext[pause.Manager](ctx)
		detourDialer = &testDestinationBoundDialer{destinations: make(chan netip.AddrPort, 4)}
		clientDialer = detourDialer
	}
	client, err := NewEndpoint(EndpointOptions{
		Context: ctx, Logger: logger.NOP(), Dialer: clientDialer, Address: clientAddresses,
		PrivateKey: base64.StdEncoding.EncodeToString(clientKey.Bytes()), Parameters: parameters,
		System: system, InterfaceFinder: finder,
		CreateDialer: func(interfaceName string) N.Dialer {
			return &testUDPDialer{control: control.BindToInterface(finder, interfaceName, -1)}
		},
		ResolvePeer: func(_ context.Context, domain string, refresh bool) ([]netip.Addr, error) {
			require.Equal(t, "awg.test", domain)
			require.Equal(t, resolveCalls > 0, refresh)
			resolveCalls++
			return []netip.Addr{resolvedAddress}, resolveErr
		},
		Peers: []PeerOptions{{
			Endpoint:  M.ParseSocksaddrHostPort("awg.test", port),
			PublicKey: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), PreSharedKey: base64.StdEncoding.EncodeToString(psk),
			AllowedIPs: serverAddresses,
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.NoError(t, client.Start(false))
	require.Zero(t, resolveCalls)
	require.Nil(t, client.tunDevice)
	require.NoError(t, client.Start(true))
	require.Equal(t, 1, resolveCalls)
	require.True(t, client.PreferredAddress(serverAddresses[0].Addr()))
	testStream(t, ctx, client, server, serverAddresses[0].Addr())
	if detour {
		detourDialer.checkDestination(t, ctx, netip.AddrPortFrom(resolvedAddress, port))
	}

	resolveErr = errors.New("test lookup failure")
	require.ErrorContains(t, client.BindUpdate(ctx), "test lookup failure")
	require.Equal(t, 2, resolveCalls)
	require.Equal(t, resolvedAddress, client.peers[0].endpoint.Addr())
	if detour {
		testDatagram(t, ctx, client, server, serverAddresses[0].Addr())
		detourDialer.checkDestination(t, ctx, netip.AddrPortFrom(resolvedAddress, port))
	}
	resolveErr = nil
	resolvedAddress = netip.MustParseAddr("127.0.0.2")
	require.NoError(t, client.BindUpdate(ctx))
	require.Equal(t, 3, resolveCalls)
	require.Equal(t, resolvedAddress, client.peers[0].endpoint.Addr())
	testDatagram(t, ctx, client, server, serverAddresses[0].Addr())
	if detour {
		detourDialer.checkDestination(t, ctx, netip.AddrPortFrom(resolvedAddress, port))
		handshake := readAWGLastHandshake(t, client)
		// Let the peer's handshake rate limit elapse before triggering a new one.
		time.Sleep(device.HandshakeInitationRate)
		// Deliver both events before the asynchronous pause worker can run.
		client.access.Lock()
		pauseManager.DevicePause()
		pauseManager.DeviceWake()
		client.access.Unlock()
		detourDialer.checkDestination(t, ctx, netip.AddrPortFrom(resolvedAddress, port))
		testDatagram(t, ctx, client, server, serverAddresses[0].Addr())
		require.True(t, readAWGLastHandshake(t, client).After(handshake))
	}

	returnPath := &testReturn{packets: make(chan []byte, 4)}
	require.NoError(t, client.AttachReturn(returnPath))
	for index, address := range serverAddresses {
		packet := echoRequest(t, clientAddresses[index].Addr(), address.Addr())
		require.NoError(t, client.WritePackets([][]byte{packet}))
		clear(packet)
		reply := readReturnedPacket(t, ctx, returnPath)
		if address.Addr().Is4() {
			require.Equal(t, header.ICMPv4EchoReply, header.ICMPv4(reply[header.IPv4MinimumSize:]).Type())
		} else {
			require.Equal(t, header.ICMPv6EchoReply, header.ICMPv6(reply[header.IPv6MinimumSize:]).Type())
		}
	}
	packet := echoRequest(t, clientAddresses[0].Addr(), netip.MustParseAddr("203.0.113.1"))
	require.NoError(t, client.WritePackets([][]byte{packet}))
	reply := readReturnedPacket(t, ctx, returnPath)
	require.Equal(t, header.ICMPv4DstUnreachable, header.ICMPv4(reply[header.IPv4MinimumSize:]).Type())
	require.NoError(t, client.DetachReturn(returnPath))
	require.NoError(t, client.Close())
	require.Error(t, client.WritePackets([][]byte{packet}))
}

func readAWGListenPort(t *testing.T, endpoint *Endpoint) uint16 {
	t.Helper()
	ipc, err := endpoint.device.IpcGet()
	require.NoError(t, err)
	_, portLine, found := strings.Cut(ipc, "\nlisten_port=")
	require.True(t, found)
	portText, _, _ := strings.Cut(portLine, "\n")
	port, err := strconv.ParseUint(portText, 10, 16)
	require.NoError(t, err)
	return uint16(port)
}

func readAWGLastHandshake(t *testing.T, endpoint *Endpoint) time.Time {
	t.Helper()
	ipc, err := endpoint.device.IpcGet()
	require.NoError(t, err)
	_, fields, found := strings.Cut(ipc, "\nlast_handshake_time_sec=")
	require.True(t, found)
	secondsText, fields, found := strings.Cut(fields, "\nlast_handshake_time_nsec=")
	require.True(t, found)
	nanosecondsText, _, _ := strings.Cut(fields, "\n")
	seconds, err := strconv.ParseInt(secondsText, 10, 64)
	require.NoError(t, err)
	require.Positive(t, seconds)
	nanoseconds, err := strconv.ParseInt(nanosecondsText, 10, 64)
	require.NoError(t, err)
	return time.Unix(seconds, nanoseconds)
}

func testStream(t *testing.T, ctx context.Context, client, server *Endpoint, address netip.Addr) {
	t.Helper()
	listener, err := gonet.ListenTCP(server.tunDevice.(*stackDevice).stack, tcpip.FullAddress{
		NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(address), Port: 8000,
	}, header.IPv4ProtocolNumber)
	require.NoError(t, err)
	defer listener.Close()
	clientConn, err := client.DialContext(ctx, N.NetworkTCP, M.SocksaddrFrom(address, 8000))
	require.NoError(t, err)
	defer clientConn.Close()
	serverConn, err := listener.Accept()
	require.NoError(t, err)
	defer serverConn.Close()
	deadline, _ := ctx.Deadline()
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))
	payload := []byte("AmneziaWG TCP")
	_, err = clientConn.Write(payload)
	require.NoError(t, err)
	buffer := make([]byte, len(payload))
	_, err = io.ReadFull(serverConn, buffer)
	require.NoError(t, err)
	require.Equal(t, payload, buffer)
}

func testDatagram(t *testing.T, ctx context.Context, client, server *Endpoint, address netip.Addr) {
	t.Helper()
	serverConn, err := gonet.DialUDP(server.tunDevice.(*stackDevice).stack, &tcpip.FullAddress{
		NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(address), Port: 8001,
	}, nil, header.IPv4ProtocolNumber)
	require.NoError(t, err)
	defer serverConn.Close()
	destination := M.SocksaddrFrom(address, 8001)
	clientConn, err := client.ListenPacket(ctx, destination)
	require.NoError(t, err)
	defer clientConn.Close()
	deadline, _ := ctx.Deadline()
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))
	payload := []byte("AmneziaWG UDP")
	_, err = clientConn.WriteTo(payload, destination.UDPAddr())
	require.NoError(t, err)
	buffer := make([]byte, 128)
	n, source, err := serverConn.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, payload, buffer[:n])
	_, err = serverConn.WriteTo(payload, source)
	require.NoError(t, err)
	n, _, err = clientConn.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, payload, buffer[:n])
}

func echoRequest(t *testing.T, source, destination netip.Addr) []byte {
	t.Helper()
	message := icmp.Message{Body: &icmp.Echo{ID: 73, Seq: 1, Data: []byte("AmneziaWG ICMP")}}
	if source.Is4() {
		message.Type = ipv4.ICMPTypeEcho
		payload, err := message.Marshal(nil)
		require.NoError(t, err)
		packet := make([]byte, header.IPv4MinimumSize+len(payload))
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.ICMPv4ProtocolNumber), SrcAddr: tun.AddressFromAddr(source), DstAddr: tun.AddressFromAddr(destination)})
		ip.SetChecksum(^checksum.Checksum(packet[:header.IPv4MinimumSize], 0))
		copy(packet[header.IPv4MinimumSize:], payload)
		return packet
	}
	message.Type = ipv6.ICMPTypeEchoRequest
	payload, err := message.Marshal(icmp.IPv6PseudoHeader(source.AsSlice(), destination.AsSlice()))
	require.NoError(t, err)
	packet := make([]byte, header.IPv6MinimumSize+len(payload))
	header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: uint16(len(payload)), TransportProtocol: header.ICMPv6ProtocolNumber, HopLimit: 64, SrcAddr: tun.AddressFromAddr(source), DstAddr: tun.AddressFromAddr(destination)})
	copy(packet[header.IPv6MinimumSize:], payload)
	return packet
}

func readReturnedPacket(t *testing.T, ctx context.Context, returnPath *testReturn) []byte {
	t.Helper()
	select {
	case packet := <-returnPath.packets:
		return packet
	case <-ctx.Done():
		t.Fatal("AWG did not return an IP packet: ", ctx.Err())
		return nil
	}
}

type testReturn struct{ packets chan []byte }

func (*testReturn) ReturnHeadroom() int { return 8 }

func (r *testReturn) ReturnPackets(packets [][]byte) [][]byte {
	var unconsumed [][]byte
	for _, buffer := range packets {
		packet := buffer[r.ReturnHeadroom():]
		isICMP := (header.IPVersion(packet) == 4 && header.IPv4(packet).Protocol() == uint8(header.ICMPv4ProtocolNumber)) ||
			(header.IPVersion(packet) == 6 && header.IPv6(packet).TransportProtocol() == header.ICMPv6ProtocolNumber)
		if !isICMP {
			unconsumed = append(unconsumed, buffer)
			continue
		}
		select {
		case r.packets <- append([]byte(nil), packet...):
		default:
		}
	}
	return unconsumed
}

type testUDPDialer struct{ control control.Func }

func (d *testUDPDialer) UDPListenerControl() (control.Func, bool) { return d.control, false }

func (d *testUDPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer := net.Dialer{Control: d.control}
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *testUDPDialer) ListenPacket(ctx context.Context, network M.Socksaddr) (net.PacketConn, error) {
	listenConfig := net.ListenConfig{Control: d.control}
	return listenConfig.ListenPacket(ctx, "udp4", "0.0.0.0:0")
}

type testDestinationBoundDialer struct {
	destinations chan netip.AddrPort
}

func (d *testDestinationBoundDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	select {
	case d.destinations <- destination.AddrPort():
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Both DNS answers lead to the same loopback server through this detour.
	destination.Addr = netip.MustParseAddr("127.0.0.1")
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (*testDestinationBoundDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test detour requires a connected UDP destination")
}

func (d *testDestinationBoundDialer) checkDestination(t *testing.T, ctx context.Context, expected netip.AddrPort) {
	t.Helper()
	select {
	case destination := <-d.destinations:
		require.Equal(t, expected, destination)
	case <-ctx.Done():
		t.Fatal("detour did not dial the peer: ", ctx.Err())
	}
}

type testNetworkManager struct {
	adapter.NetworkManager
	finder control.InterfaceFinder
}

func (m *testNetworkManager) InterfaceFinder() control.InterfaceFinder { return m.finder }

func (*testNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return testInterfaceMonitor{}
}

type testInterfaceMonitor struct{ tun.DefaultInterfaceMonitor }

func (testInterfaceMonitor) RegisterMyInterface(string) {}

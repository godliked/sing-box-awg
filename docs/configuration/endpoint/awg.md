# AmneziaWG

The `awg` endpoint supports TCP, UDP, ICMP, and raw IP forwarding through an AmneziaWG tunnel.
Release builds include `with_awg`. Custom builds also need `with_gvisor` for the userspace tunnel (`system: false`).

### Structure

```json
{
  "type": "awg",
  "tag": "awg-out",
  "system": false,
  "address": ["10.10.0.2/32"],
  "private_key": "<base64 private key>",
  "peers": [
    {
      "address": "vpn.example.com",
      "port": 51820,
      "public_key": "<base64 peer public key>",
      "allowed_ips": ["0.0.0.0/0"]
    }
  ]
}
```

Use the tunnel addresses, peer keys, and AmneziaWG parameters from your VPN configuration.
The common endpoint, peer, and dialer fields follow the [WireGuard endpoint](wireguard.md).
`workers` and `reserved` are unsupported for `awg`.
With a direct UDP bind on Linux, use the dialer field `routing_mark` for the AmneziaWG `FwMark` setting.
Each peer needs at least one `allowed_ips` prefix. Configure `awg-quick` settings such as DNS and routing in sing-box.

Each peer's `persistent_keepalive_interval` accepts a fixed interval in seconds such as `25`, or a range such as `"20-30"`.
The AmneziaWG core picks an interval from the range each time it schedules a persistent keepalive.
The bounds are unsigned 32-bit integers. The full range from `0` through `4294967295` exceeds the core's timer range size.
Use `0` or `"off"` to disable persistent keepalives.

Amnezia Box configurations can use `useIntegratedTun` for `system` and `preshared_key` for `pre_shared_key` under each peer.
If both names are present, their values must match. Configuration formatting emits `system` and `pre_shared_key`.

### AmneziaWG parameters

Set these optional fields at the endpoint level. Omitted fields use the AmneziaWG library defaults.

| Fields | JSON type | Meaning |
| --- | --- | --- |
| `jc`, `jmin`, `jmax` | Integer | Number of junk packets and their minimum and maximum sizes in bytes. |
| `s1`, `s2`, `s3`, `s4` | Integer | Padding sizes for initiation, response, cookie, and transport messages in bytes. |
| `h1`, `h2`, `h3`, `h4` | String | Message header values or ranges for initiation, response, cookie, and transport messages. |
| `i1`, `i2`, `i3`, `i4`, `i5` | String | AmneziaWG pre-handshake packet specifications. |
| `header_protection_key` | String | Base64-encoded 32-byte header protection key. Requires `s1` through `s4` to be at least 12. |
| `content_padding_addition` | String | Additional transport padding value or range in bytes. |
| `rekey_after_time`, `rekey_timeout`, `reject_after_time`, `keepalive_timeout` | String | Timing values or ranges in seconds. |
| `max_handshake_attempts` | String | Handshake attempt limit or range. |
| `random_trailers`, `disable_cookies` | Boolean | Enable random trailers or disable handshake cookies, respectively. |

Peer hostnames use the configured dialer DNS resolver. AWG selects the first resolved IP at startup and bypasses the DNS cache on network changes.

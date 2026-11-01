# proxy-singbox

Standalone Rust library that renders sing-box JSON from the same xray-shaped
`settings` and `stream` values accepted by `proxy-clash`. It performs no file
or network I/O. Every input becomes either a generated outbound or an explicit
entry in `Report::skipped_nodes` with a per-node reason.

## Supported mappings

| Family | Mappings |
| --- | --- |
| VLESS | TCP/raw, WebSocket, gRPC, HTTP, HTTPUpgrade; TLS and Reality; `xtls-rprx-vision` flow |
| VMess | TCP/raw, WebSocket, gRPC, HTTP, HTTPUpgrade; supported sing-box VMess security methods; TLS |
| Shadowsocks | sing-box documented legacy, AEAD and AEAD 2022 methods; no SIP003 plugin mapping |
| Trojan | TCP/raw, WebSocket, gRPC, HTTP, HTTPUpgrade; TLS |
| Hysteria v1 | UDP mode, authentication, required bandwidth, TLS, xplus password obfuscation, port hopping |
| Hysteria2 | TLS, authentication, Salamander (password required) or Gecko obfuscation, bandwidth, port hopping |

Transports use sing-box V2Ray transport fields (`ws`, `grpc`, `http`, and
`httpupgrade`). `raw` and `tcp` use the protocol's default stream. mKCP, V2Ray
QUIC transport, XHTTP/SplitHTTP, SSR, Shadowsocks SIP003 plugins, unknown input
fields, and any option without a behavior-preserving mapping are skipped with a
reason. Reality is converted only for VLESS. VMess HTTP/2 is represented as
sing-box's HTTP transport. Unsupported options are never silently discarded.

The emitted names follow the current sing-box outbound schema, including
`server_port`, `alter_id`, `auth_str`, `server_ports`, and `tls.server_name`.
TLS verification stays enabled unless the input explicitly requests insecure
verification. The schema field `tls.insecure` carries that explicit choice.

## API

```rust
use proxy_singbox::{render, Options, Source};
use serde_json::json;

let source = Source {
    proto: "vless".into(),
    name: "edge".into(),
    server: "proxy.example".into(),
    port: 443,
    country: "DE".into(),
    settings: json!({ "id": "00000000-0000-0000-0000-000000000000" }),
    stream: Some(json!({
        "network": "ws",
        "security": "tls",
        "tlsSettings": { "serverName": "front.example" },
        "wsSettings": { "path": "/ws", "headers": { "Host": "front.example" } }
    })),
};

let (json_config, report) = render(&[source], &Options::default())?;
assert_eq!(report.supported_count(), 1);
assert_eq!(report.skipped_count(), 0);
# Ok::<(), anyhow::Error>(())
```

`render` returns `(pretty_json, Report)`. `Report.supported` lists each
generated node with its unique outbound `tag`; `Report.skipped_nodes` lists
each rejected node with its original protocol/name and a reason. The generated
config includes a mixed local inbound, a direct outbound, a manual `proxy`
selector when at least one node is supported, and a route final matching the
selector (or `direct` for an empty result).

## Use from the root project

Add `proxy-singbox` as a workspace member and path dependency in the root
manifest, then construct this crate's `Source` from the root proxy model and
call `proxy_singbox::render(&sources, &Options::default())`. Keeping the source
types local to this crate avoids a dependency on the application package and
allows its conversion tests to run independently.

## Verify

From the repository root, once the crate is a workspace member:

```sh
cargo fmt -p proxy-singbox --check
cargo test -p proxy-singbox
cargo clippy -p proxy-singbox --all-targets -- -D warnings
```

Schema references: [VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/),
[VMess](https://sing-box.sagernet.org/configuration/outbound/vmess/),
[Shadowsocks](https://sing-box.sagernet.org/configuration/outbound/shadowsocks/),
[Trojan](https://sing-box.sagernet.org/configuration/outbound/trojan/),
[Hysteria](https://sing-box.sagernet.org/configuration/outbound/hysteria/),
[Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/),
[TLS](https://sing-box.sagernet.org/configuration/shared/tls/), and
[V2Ray transports](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/).

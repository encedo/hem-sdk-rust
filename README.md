# hem-sdk-rust

Rust client for the [Encedo HEM](https://encedo.com) hardware key vault,
firmware 1.3 and later. The Rust counterpart of
[hem-sdk-js](https://github.com/encedo/hem-sdk-js): same flows, same error
codes, same wire format. Private keys never leave the device.

Status: early (0.1 in progress). See [docs/DESIGN.md](docs/DESIGN.md) for the
design and the roadmap.

```rust
use hem_sdk::{AuthOptions, Hem, HemOptions};

let hem = Hem::new("https://my.ence.do", HemOptions::default())?;
println!("{}", hem.get_version(None).await?);
let token = hem
    .authorize_password(Some("password"), "keymgmt:list", AuthOptions::default())
    .await?;
```

## Build

```bash
cargo build
cargo test
```

Needs a C compiler for `ring` (rustls). On Windows with the GNU toolchain put
MinGW-w64 (`gcc`, `dlltool`) on PATH.

## Licence

MIT, see [LICENSE](LICENSE).

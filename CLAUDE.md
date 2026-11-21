# CLAUDE.md - hem-sdk-rust

Instructions for AI agents working in this repository. Design decisions:
[docs/DESIGN.md](docs/DESIGN.md) - read it first.

## Ground rules

- **hem-sdk-js is the reference.** Before adding or changing a method, read
  the matching method in hem-sdk-js (`encedo-manager/sdk/hem-sdk.js` in a
  sibling checkout, or github.com/encedo/hem-sdk-js) and its `CLAUDE.md`.
  Same flow, same request shape, same error codes. Do not invent payloads.
- **The firmware API reference is the spec**:
  `encedo_firmware/docs/HEM_API_reference_1.3.x.md` (sibling checkout) -
  fields, limits, status codes, check order. `hem-api-tester` is the
  reference implementation run against real hardware.
- **Anything the device checks cryptographically gets a vector** recorded
  from hem-sdk-js (`tests/vectors/gen.mjs`). Never "fix" a vector by hand.
- **Commits:** no `Co-Authored-By` or any other AI attribution trailer.
  Author `Krzysztof Rutecki <krzysztof@encedo.com>` (the global git identity
  on the dev machine is a placeholder - pass it with `-c user.name/-c user.email`).
- **Push only on the owner's explicit go.** The owner usually pushes.
- Consumers take this repo as a git submodule (hem-ssh-agent). A breaking
  change is fine in 0.x, but say it in the commit message.

## Build and test

```bash
cargo build
cargo test                                   # offline: unit + vectors
HEM_URL=https://ssh-agent-tester.playground.ence.do cargo test --test live
cargo clippy --all-targets -- -D warnings
```

Windows (GNU toolchain): `~/.cargo/bin` and `C:\mingw64\bin` must be on PATH
(`ring` needs gcc, `windows-sys` needs dlltool).

## Test device

`https://ssh-agent-tester.playground.ence.do` - a HEM simulator
(`fwv ... v1.3.2-sim`) for this project. Not a secret; it is here
temporarily and goes away when the project has its own fixture.

Initialised 2026-11-21 as hem-api-tester T-2 does: the user and admin
passphrases are the tester's (`config.php`); pass the user one as
`HEM_PASSWORD`. Policy `raw_ecdh_enabled, pubkey_in_search, pubkey_in_list`.

## Conventions

- Public method = thin wrapper over `Http::request`: shape the body, unwrap
  the field. Optional values in an options struct with `Default`, never
  positional `Option`s piling up.
- Binary in / binary out (`&[u8]` / `Vec<u8>`); base64 inside the method.
- Device limits as named constants with the API reference section they come from.
- Document the required token scope on every method.
- No `unsafe`.

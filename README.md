# WireGuard Config Studio (Rust)

A Rust rewrite of `wireguard_manager.py` + `wireguard_gui.py`: a desktop tool
for building WireGuard tunnel configurations for multiple offices/clients,
without hand-writing `.conf` files.

Two crates:

- **`wgcore`** — library port of `wireguard_manager.py`. Key generation
  (X25519 via `x25519-dalek`), `WireGuardHost` / `Peer` models, an
  `IpAddressPool` for auto-assigning client addresses, `.conf` parsing,
  RouterOS (MikroTik) export, and the optional `WireGuardNetwork`
  convenience layer for scripting a whole topology at once.
- **`gui`** (binary name `wireguard-studio`) — desktop GUI port of
  `wireguard_gui.py`, built on `egui`/`eframe`. Same two-level tab layout
  (one tab per host, a nested tab per client), the same LuCI-inspired
  color theme, the same keyboard shortcuts, and a project `.json` format
  that's field-for-field compatible with the Python version's — a project
  saved by either app opens in the other.

## Building

Requires a recent stable Rust toolchain (`rustup` is the easiest way to get
one: <https://rustup.rs>). This was written and reviewed without network
access to `crates.io`, so **it has not actually been compiled or run** —
build it locally and treat the first `cargo build` as the real test:

```sh
cd wireguard-studio
cargo build --release
```

Run the GUI:

```sh
cargo run -p wireguard-studio-gui --release
```

Run the library's demo script (a Rust port of the Python file's
`if __name__ == "__main__":` block — builds a small office+branch+3-clients
topology and writes it to `./wireguard-configs/`):

```sh
cargo run -p wgcore --example demo
```

Run the library's unit tests:

```sh
cargo test -p wgcore
```

On Linux, `eframe` needs the usual GUI dev packages (X11/Wayland, OpenGL) —
if the build fails looking for those, install your distro's equivalents of
`libxkbcommon-dev`, `libgtk-3-dev`, and `libssl-dev`.

## Cross-platform builds

The code itself needs no changes to build on macOS, Windows, or Linux — the
only OS-conditional code is the `.conf` file permission tightening in
`wgcore/src/host.rs`, which already has both a `#[cfg(unix)]` branch (chmod
0600) and a `#[cfg(not(unix))]` no-op fallback for Windows. Everything else
(`wgcore`'s logic, and `egui`/`eframe`/`rfd` in the GUI) is portable by
design.

What doesn't work well is cross-*compiling* a GUI binary for one OS from a
different one — `eframe` links against each platform's native windowing
libraries (Cocoa, Win32, X11/Wayland), and dragging in `osxcross` or
`mingw-w64` to target the other two from a single machine is fragile,
especially for a macOS build you'd also want signed. The straightforward
approach is to build natively on each OS, which in practice means running
`cargo build --release --workspace` once per platform (locally or in CI).

`.github/workflows/build.yml` sets this up as a GitHub Actions matrix that
builds on `ubuntu-latest`, `macos-latest`, and `windows-latest` in parallel
and uploads each platform's binary as an artifact. Push it to a repo with
that workflow file in place and it builds all three on every push/PR.

## What's intentionally different from the Python version

- **No `wg` CLI fallback for key generation.** The Python original used
  the `cryptography` package with a subprocess fallback to the `wg`
  binary. Rust uses `x25519-dalek` directly and unconditionally — there's
  no "not installed" case to fall back from.
- **Keyboard shortcuts are scoped more coarsely.** Tk could tell exactly
  which widget had keyboard focus, so Ctrl+W/Ctrl+T/Ctrl+1-9 in the Python
  app could tell "focus is inside this host's client area" vs. not. egui
  doesn't expose an equivalent focus tree, so here these shortcuts act on
  whichever host tab is currently *selected* instead. This covers the
  common case (acting on whatever's on screen) but isn't a byte-for-byte
  behavioral match in every edge case.
- **A RouterOS endpoint edge case was fixed, not ported as-is.** If a
  peer's `Endpoint` has no `:port` at all, the Python original's
  `rpartition(":")` logic silently drops it (adds no `endpoint-address`
  line). The Rust port adds it as a bare `endpoint-address` instead, which
  seemed clearly more useful than reproducing the original's omission.

Everything else — key handling, config rendering/parsing, the IP pool
allocation strategy, the RouterOS/EoIP script generation (including its
deterministic tunnel-id hashing and collision handling), the host/client
form fields and their auto-fill/manual-override toggles, and the project
JSON schema — is a deliberately faithful, field-for-field port.

## Project layout

```
wireguard-studio/
├── Cargo.toml              workspace manifest
├── wgcore/                 library
│   ├── src/
│   │   ├── lib.rs
│   │   ├── keys.rs         key generation/validation
│   │   ├── peer.rs         Peer model
│   │   ├── host.rs         WireGuardHost model + .conf rendering
│   │   ├── pool.rs         IpAddressPool
│   │   ├── parse.rs        .conf -> WireGuardHost
│   │   ├── dict.rs         WireGuardHost <-> plain-dict (for project JSON)
│   │   ├── routeros.rs     MikroTik/RouterOS + EoIP script export
│   │   ├── network.rs      WireGuardNetwork (multi-host convenience layer)
│   │   └── error.rs        WgError
│   └── examples/demo.rs    port of wireguard_manager.py's __main__ demo
└── gui/                    desktop app (binary: wireguard-studio)
    └── src/
        ├── main.rs
        ├── app.rs          top-level state, header, keyboard shortcuts
        ├── host_tab.rs     per-host state + model-sync logic
        ├── host_ui.rs      per-host egui rendering
        ├── client_tab.rs   per-client state + model-sync logic
        ├── client_ui.rs    per-client egui rendering
        ├── project.rs      project .json schema (matches the Python app's)
        ├── modal.rs        info/error/preview popup state
        ├── theme.rs        LuCI-inspired color theme
        └── util.rs         small shared helpers
```

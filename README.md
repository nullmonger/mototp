# mototp

Local-only, cross-platform TOTP authenticator. Secrets stay on the device, and
sync happens only between your own devices over the local network, never through
a cloud. A replacement for Google Authenticator once it started syncing through
the internet.

A TOTP second factor is meant to be local, tied to the device. If the secrets
live in a cloud behind an account password, the second factor collapses back
into a password.

## Features

- TOTP (RFC 6238) and HOTP (RFC 4226): SHA-1/256/512, 6 or 8 digits, custom period
- otpauth:// import via QR (phone camera, desktop screenshot picker) or manual entry
- encrypted dump of the whole secret set into a single master-password file,
  moved between devices by hand
- master password with unlock-for-N-minutes, optionally disabled
- LAN sync: mDNS discovery, QR/PIN pairing, encrypted channel, started by hand
- tags, so an account can belong to several groups; editing and search
- service icons with a letter and color fallback derived from the name
- interoperable export: Aegis / 2FAS, otpauth list, per-account QR, plain text

## Non-goals

- cloud sync, as a matter of principle
- password storage; this is not a password manager
- U2F / FIDO2 / WebAuthn
- SMS / email 2FA
- push-based auth (Duo-style)

## Status

Early development. The crate is set up, and the feature set above is the target
for the first release rather than what ships today.

## Built with

Rust and Dioxus, targeting Linux desktop and Android in the MVP, with macOS,
Windows and iOS to follow.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

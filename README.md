# herdogrelay

`herdogrelay` is a secure, device-scoped QUIC relay for connecting Core to Herdr sessions on a remote machine.

## What it does

- Serves one configurable UDP endpoint for one remote Herdr device.
- Maintains one authenticated QUIC connection per device.
- Provides one control stream and isolated session streams.
- Validates session authority and the destination Herdr Unix socket before forwarding data.
- Supports bounded resource usage and fail-closed connection handling.
- Runs as a user-level service on supported macOS and Linux environments.

## Security model

- QUIC TLS 1.3 is always used.
- Production deployments require certificate verification and mutual TLS.
- The Relay uses the fixed ALPN `herdr-dog-relay-quic/1`.
- Session failures are isolated from other sessions on the same device.
- Credentials, session tokens and private key material are not included in releases or logged by the Relay.

## Protocol boundary

The Relay is an opaque byte bridge. It does not interpret Herdr protocol messages, provide a Herdr API, run Core, expose arbitrary commands or provide a general-purpose proxy.

The App connects to Core. Core owns Target state, Herdr protocol interpretation, recovery and action safety.

## Supported platforms

Published releases currently target supported macOS and Linux architectures listed in the release notes. Windows service and credential integration are not part of the current release scope.

## Installation and releases

Installers and release archives are published with the project releases. Use the release instructions and configuration template that match the installed version. Certificate and private-key material must be provisioned separately and must never be copied into the repository or release archive.

## Limitations

The Relay does not enable Herdr writes, subscriptions, healthy `Online + Current`, Core actions, arbitrary passthrough or automatic retry by itself. These behaviors remain owned and controlled by Core.

## License

Licensed under the GNU Affero General Public License, version 3 or later. See [`LICENSE`](LICENSE).

# herdogrelay

`herdogrelay` is an iroh application Relay for connecting Core to Herdr sessions on a remote machine.

## What it does

- Owns one iroh `Endpoint` and `Router` for bounded Core connections.
- Authenticates peers with iroh `EndpointId` and the fixed application ALPN `herdr-dog-iroh/1`.
- Provides one control stream and isolated session streams per Core connection.
- Validates session authority and the destination Herdr Unix socket before forwarding data.
- Supports bounded resource usage and fail-closed connection handling.
- Runs as a user-level service on supported macOS and Linux environments.

## Security model

- `EndpointTicket` is bootstrap input; application pairing is required before normal sessions are admitted.
- The application Relay is separate from iroh network-relay infrastructure.
- The iroh runtime has no certificate or Quinn fallback.
- `herdogrelay run` without `development_recovery_directory` uses a per-process disposable generated identity with no restart persistence for local development/tests only. Store-backed startup is the path for restart-safe local recovery; missing or corrupt records remain fail-closed.
- Credentials, session tokens and private key material are not returned in status or logged by the Relay.

## Protocol boundary

The Relay is an opaque byte bridge. It does not interpret Herdr protocol messages, provide a Herdr API, run Core, expose arbitrary commands or provide a general-purpose proxy.

The App connects to Core. Core owns Target state, Herdr protocol interpretation, recovery and action safety.

## Supported platforms

Published releases currently target supported macOS and Linux architectures listed in the release notes. Windows service and credential integration are not part of the current release scope.

## Installation and releases

Installers and release archives are published with the project releases. Use the release instructions and iroh configuration template that match the installed version. Inspect the template with `herdogrelay --print-default-config`; a user-level run uses `herdogrelay --config ~/.config/herdr-dog/iroh-relay.toml`. Do not place credentials, tickets, pairing codes or private key material in the repository or release archive.

## Limitations

The Relay does not enable Herdr writes, subscriptions, healthy `Online + Current`, Core actions, arbitrary passthrough or automatic retry by itself. These behaviors remain owned and controlled by Core.

## License

Licensed under the GNU Affero General Public License, version 3 or later. See [`LICENSE`](LICENSE).

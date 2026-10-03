# Laputa Mirror

`laputa-mirror` serves the Laputa PM repository format from an S3-compatible
bucket and exposes authenticated `PUT` publishing for:

- `index.json`
- `packages/<arch>/<name>/<name>-<ver>-<rel>.tar.gz`
- `metadata/<arch>/<name>/<name>-<ver>-<rel>.json`
- `sources/<name>/<name>-<ver>-<rel>-<arch>-src.tar.bz2`

The mirror accepts the older `packages/<name>/...` object path for existing
arm64 packages, but new PM uploads use the arch-qualified path. Source mirrors
are target-architecture-specific and their paths are derived from the package
index entry; the index does not store a source filename.

This guide stands up a new mirror at `https://laputa.17166969.xyz/` using
Cloudflare R2 for object storage and a Cloudflare Tunnel for the only public
origin path. With this tunnel-only setup, leave `R2_PUBLIC_URL` unset so package
downloads are served through `laputa-mirror` instead of redirecting clients to a
public R2 URL.

## Architecture

```text
Laputa PM clients
  -> https://laputa.17166969.xyz
  -> Cloudflare Tunnel
  -> cloudflared on the server
  -> http://127.0.0.1:3000
  -> laputa-mirror
  -> Cloudflare R2 bucket: laputa-mirror
```

The server does not need inbound ports open. `cloudflared` makes outbound
connections to Cloudflare and forwards the public hostname to the local mirror.

## Build Machine Prerequisites

On the machine where you build the `.deb`:

```sh
sudo apt-get update
sudo apt-get install -y build-essential curl pkg-config unzip dpkg-dev docker.io
```

Install [Deno](https://deno.com) and [Node.js](https://nodejs.org/) for the frontend build. `make build-frontend` uses Deno to install the pinned pnpm CLI, then uses pnpm to install frontend dependencies and build the assets. The pnpm executable is stored under `target/pnpm`; Deno caches its package globally.

Install Rust with rustup if it is not already present:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustup default stable
```

Install `cloudflared` using Cloudflare's package instructions for Debian/Ubuntu,
or install the binary at `/usr/bin/cloudflared` on the server.

## R2 Bucket

You already created the bucket:

```text
laputa-mirror
```

Create an R2 API token with object read/write access to that bucket. You need:

```text
S3_ENDPOINT=https://<account_id>.r2.cloudflarestorage.com
S3_BUCKET=laputa-mirror
S3_ACCESS_KEY_ID=<r2_access_key_id>
S3_SECRET_ACCESS_KEY=<r2_secret_access_key>
S3_REGION=auto
```

Do not configure `R2_PUBLIC_URL` for the tunnel-only setup.

## Build The Debian Package

`make deb` builds release `x86_64-unknown-linux-musl` binaries inside a clean
Alpine Linux Docker container and packages them as `amd64`. Only the output
binaries are persisted on the host; the Rust toolchain and build artifacts stay
inside the ephemeral container.

```sh
cd /path/to/laputa-systems/mirror
make deb
```

The first build downloads the Rust toolchain and compiles all dependencies from
scratch. Subsequent builds also start from a fresh container.

Output:

```text
laputa-mirror_0.1.0_amd64.deb
```

Deploy the package to the configured `oracle` host and restart the service:

```sh
make deploy
DEPLOY_HOST=another-host make deploy
```

The target requires SSH access and passwordless or available `sudo` on the
remote host. It installs the package, reloads systemd, restarts and enables the
mirror service, and prints its status.

The package includes:

- `/usr/bin/laputa-mirror`
- `/usr/bin/laputa-mirror-publish`
- `/usr/share/laputa-mirror/static`
- `/lib/systemd/system/laputa-mirror.service`
- `/etc/laputa-mirror/env.example`

Copy the package to the server:

```sh
scp laputa-mirror_0.1.0_amd64.deb root@<server>:/tmp/
```

## Install The Mirror Service On The Server

Install the package:

```sh
sudo dpkg -i /tmp/laputa-mirror_0.1.0_amd64.deb
```

The package post-install creates the `laputa-mirror` service user, creates
`/var/lib/laputa-mirror`, and copies `/etc/laputa-mirror/env.example` to
`/etc/laputa-mirror/env` if that file does not already exist.

Edit the env file:

```sh
sudo editor /etc/laputa-mirror/env
```

Minimum tunnel-only config:

```sh
LISTEN_ADDR=127.0.0.1:3000

S3_ENDPOINT=https://<account_id>.r2.cloudflarestorage.com
S3_BUCKET=laputa-mirror
S3_ACCESS_KEY_ID=<r2_access_key_id>
S3_SECRET_ACCESS_KEY=<r2_secret_access_key>
S3_REGION=auto

DB_PATH=/var/lib/laputa-mirror/auth.db
ALLOWED_USERS=josh
RP_ID=laputa.17166969.xyz
RP_ORIGIN=https://laputa.17166969.xyz
```

Set `ALLOWED_USERS` to the usernames allowed to register passkeys. Comma
separate multiple users.

Start the local service:

```sh
# sudo systemctl daemon-reload
sudo systemctl restart laputa-mirror
sudo systemctl enable --now laputa-mirror
sudo systemctl status laputa-mirror
```

Local check:

```sh
curl -fsSL http://127.0.0.1:3000/health
```

## Create The Cloudflare Tunnel

This guide uses a locally-managed tunnel because it is easy to reproduce from
the CLI. Cloudflare recommends remotely-managed tunnels for most production
deployments; the origin service and hostname are the same either way.

Authenticate `cloudflared`:

```sh
cloudflared tunnel login
```

Create the tunnel:

```sh
cloudflared tunnel create laputa-mirror
```

Record the tunnel UUID from the output. The command also creates:

```text
~/.cloudflared/<tunnel-uuid>.json
```

Install the tunnel credentials:

```sh
export TUNNEL_ID=<tunnel-uuid>

sudo install -d -m 755 /etc/cloudflared
sudo install -m 600 "$HOME/.cloudflared/$TUNNEL_ID.json" "/etc/cloudflared/$TUNNEL_ID.json"
```

Create `/etc/cloudflared/config.yml`:

```sh
sudo tee /etc/cloudflared/config.yml >/dev/null <<EOF
tunnel: $TUNNEL_ID
credentials-file: /etc/cloudflared/$TUNNEL_ID.json

ingress:
  - hostname: laputa.17166969.xyz
    service: http://127.0.0.1:3000
  - service: http_status:404
EOF
```

Create the DNS route:

```sh
cloudflared tunnel route dns laputa-mirror laputa.17166969.xyz
```

Install and start `cloudflared` as a service:

```sh
sudo cloudflared service install
sudo systemctl enable --now cloudflared
sudo systemctl status cloudflared
```

Public check:

```sh
curl -fsSL https://laputa.17166969.xyz/health
```

## Create The First Publisher Token

Open:

```text
https://laputa.17166969.xyz/auth
```

Register a passkey using a username from `ALLOWED_USERS`.

Then open:

```text
https://laputa.17166969.xyz/auth/settings
```

Create a named token, for example `github-actions`, and store it once. Tokens
are shown only at creation time.

## Publish The Bootstrap Repo

Set the publisher environment:

```sh
export LAPUTA_MIRROR_URL=https://laputa.17166969.xyz
export LAPUTA_MIRROR_TOKEN=<token_from_settings>
```

Publish an existing exported PM repo:

```sh
cargo run --bin laputa-mirror-publish -- \
  .out/laputa-bootstrap-build-essential-native-repo
```

The publisher:

1. Uploads every package tarball from `packages/<arch>/`.
2. Uploads package metadata sidecars from `metadata/<arch>/`.
3. Maps `.out/source-mirrors/<pkg>-<ver>-<rel>-<arch>.tar.bz2` to
   `sources/<pkg>/<pkg>-<ver>-<rel>-<arch>-src.tar.bz2`.
4. Recomputes package/source sha256 and package size metadata.
5. Uploads `index.json` last.

Large package and source uploads are split into smaller chunk requests to avoid
Cloudflare Tunnel request body limits. The publisher only talks to
`laputa-mirror`; the mirror service is the only component that writes to R2.

Verify:

```sh
curl -fsSL https://laputa.17166969.xyz/index.json | jq '.[].name'
curl -I https://laputa.17166969.xyz/packages/aarch64/build-essential-native/build-essential-native-1-2.tar.gz
curl -I https://laputa.17166969.xyz/metadata/aarch64/build-essential-native/build-essential-native-1-2.json
curl -I https://laputa.17166969.xyz/sources/linux/linux-7.0.5-33-x86_64-src.tar.bz2
```

## GitHub Actions Publishing

Add repository secrets:

```text
LAPUTA_MIRROR_TOKEN=<token_from_settings>
```

Run the manual workflow:

```text
Laputa Mirror Publish ARM64
```

Use the workflow run ID that produced:

```text
laputa-bootstrap-build-essential-native-repo-arm64
```

The workflow downloads that artifact, validates the expected repo layout,
publishes it, then checks the public `index.json` and a known package URL.

## Configure PM Clients

Use the mirror as the public repo:

```sh
export XSH_PM_PUBLIC_REPO=https://laputa.17166969.xyz
```

For uploads from local PM tooling, use:

```sh
export XSH_PM_REPO=https://laputa.17166969.xyz
export LAPUTA_TOKEN=<token_from_settings>
```

## Operations

Check services:

```sh
sudo systemctl status laputa-mirror
sudo systemctl status cloudflared
```

Logs:

```sh
sudo journalctl -u laputa-mirror -f
sudo journalctl -u cloudflared -f
```

Restart after env changes:

```sh
sudo systemctl restart laputa-mirror
```

Restart after tunnel config changes:

```sh
sudo systemctl restart cloudflared
```

## Notes

- Keep `/etc/laputa-mirror/env` mode `0600`; it contains R2 credentials.
- Keep `/etc/cloudflared/<tunnel-uuid>.json` mode `0600`; it is the tunnel
  credential.
- Large package/source uploads are chunked through `laputa-mirror`; CI does not
  receive or use R2 credentials.

# Optional self-hosted container

The supported primary runtime is unprivileged Android Termux on AArch64. The repository also retains a portable, provider-neutral Linux container image as an optional self-hosted deployment target. No managed hosting service, infrastructure-as-code SDK or cloud account is required.

Build the pinned-image Dockerfile from the repository root:

```sh
docker build --build-arg HUNTSMAN_BUILD_SHA="$(git rev-parse HEAD)" -t huntsman-recon:local .
docker run --rm --name huntsman-recon -p 127.0.0.1:18080:8080 \
  -v huntsman-data:/data -e HSE_AUTH_TOKEN="YOUR_SECRET_TOKEN" \
  huntsman-recon:local
```

Only bind the host loopback interface in the sample. The container internally listens on port 8080. The generic entrypoint validates `PORT`, explicitly sets `HSE_BIND`, runs the offline startup acceptance, and runs the binary without root as uid 10001. It forwards stop signals and preserves state under `/data`. If a bearer token is not provided, it creates and saves a 256-bit random token privately at `/data/.huntsman/container-auth-token`; the secret itself is not printed. Attach durable storage if that token and scan data must survive container replacement. To inspect it locally, access the mounted volume rather than the deployment logs.

Health: `http://127.0.0.1:18080/api/health`. To verify authenticated endpoints, supply the token and execute:

```sh
HUNTSMAN_CONTAINER_URL=http://127.0.0.1:18080 HSE_AUTH_TOKEN="YOUR_SECRET_TOKEN" \
HUNTSMAN_EXPECTED_SHA="$(git rev-parse HEAD)" \
  bash scripts/container-live-acceptance.sh
```

The harness permits plain HTTP only on loopback; remote hosts require HTTPS. Local and Termux `serve` operations remain loopback-only unless explicitly configured with `--bind` or `HSE_BIND`; no container platform variable can silently widen the bind.

## Railway

The same image runs on [Railway](https://railway.com) with no provider-specific code: `railway.toml` at the repository root is the deployment profile Railway reads (the Dockerfile as the builder, `/api/health` as the health route, one replica, no application sleeping, restart on failure), and the generic entrypoint already honours the `PORT` Railway injects, binds `0.0.0.0:$PORT` and keeps its state under `/data`. Railway remains optional: nothing in the image or the server depends on it.

1. **Deploy from the repository.** New Project, Deploy from GitHub repo, choose this repository and the branch to follow. Railway builds the root Dockerfile; the dependency layer is cached, so a later deploy compiles the crate alone.
2. **Variables** (Service, Variables). Set `HSE_AUTH_TOKEN` to a long random secret: a public domain is a non-loopback bind, which needs the token, and a token the entrypoint generates lives only under `/data` and is never printed, so without the variable there is nothing to type into the page. Set `HUNTSMAN_SOURCE_SHA` to `${{RAILWAY_GIT_COMMIT_SHA}}` so the build embeds the deployed commit and `/api/health` reports it as `build_sha`, which the acceptance script checks. Add provider keys as `HUNTSMAN_*_KEY` variables where a keyed source is wanted; the keyless legs need none.
3. **Volume.** Add a volume mounted at `/data`: it keeps the saved scans, the threat feeds, the sanctions lists, DFAT's workbook and the AEC archive the lookups keep on the device, and the generated token when `HSE_AUTH_TOKEN` is not set. A volume attaches to one replica, which is all the store supports.
4. **Networking.** Generate a public domain. Railway terminates TLS and forwards plain HTTP to the service's `PORT`; the page and the API are served over HTTPS at the domain. Open `https://DOMAIN/#token=VALUE` once to hand the page its token, or call the API with `Authorization: Bearer` and `X-Huntsman-Lookup: 1` as the API reference describes. A lookup may take up to 150 seconds; a scan started from the page runs on the service and is read back under Scans.
5. **Accept the deployment** from any machine with the repository checked out at the deployed commit, over HTTPS:

```sh
HUNTSMAN_CONTAINER_URL=https://DOMAIN HSE_AUTH_TOKEN="YOUR_SECRET_TOKEN" \
HUNTSMAN_EXPECTED_SHA="$(git rev-parse HEAD)" \
  bash scripts/container-live-acceptance.sh
```

A redeploy stops the running service with SIGTERM, which the entrypoint hands to the server; a scan still running then reads `ABORTED` after the restart, saved with what it had found. Rotate the token by changing the variable and redeploying.

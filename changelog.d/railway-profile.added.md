- A Railway deployment profile, `railway.toml`, deploys the provider-neutral container image
  through config as code alone: the Dockerfile as the builder, `/api/health` as the health route,
  one replica (the saved-scan store has one owner per directory), no application sleeping (a long
  scan is not stopped mid-way) and restart on failure. The container guide's Railway section
  names the variables a deployment needs (`HSE_AUTH_TOKEN`; `HUNTSMAN_SOURCE_SHA` set to Railway's
  commit so `/api/health` reports the deployed commit), the volume at `/data` and the acceptance
  run over HTTPS. The image, the entrypoint and the server stay free of the provider.

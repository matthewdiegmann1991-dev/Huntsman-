- New `ipapi_is` IP source, run by `ip`, IP scans and `/api/lookup`. Keyless, it records the
  address's owner, origin AS and location (30 lookups a day). With the optional free
  `HUNTSMAN_IPAPI_IS_KEY` (1,000 a day, commercial use included) it adds hosting, VPN, proxy, Tor,
  crawler and recent-abuse flags, the hosting provider, the VPN service and the network's abuse
  desk. A keyless answer carries `detection=not_checked`, so the absence of a `vpn` or `proxy` tag
  is never read as a clean result. Bogon addresses are a valid zero, and an answer naming another
  address is rejected.

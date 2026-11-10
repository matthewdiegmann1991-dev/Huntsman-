- The container entrypoint binds every interface on `PORT` over both address families where the
  kernel offers IPv6 (`[::]:PORT`, which answers IPv4 too), else over IPv4 alone, and logs which;
  an explicit `HSE_BIND` is handed on as given. A platform whose private network is IPv6-only
  (Railway's is) reaches the service at its internal name without a public domain; the container
  guide's Railway section says so.

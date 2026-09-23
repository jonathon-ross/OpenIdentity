# OpenIdentity public site

Deploy this directory as a Cloudflare Pages static site. No build command is required.

Resources:
- `/` — landing page
- `/ns` — vocabulary documentation
- `/ns/v1` — immutable JSON-LD context
- `/ns/v1.sha256` — checksum

Context SHA-256: `458c07e5af8e9119dabc5ed752ad85edb4ac06123718b831a2665d93bca236bd`

After deployment:

```bash
curl -I https://openidentity.foundation/ns/v1
curl -sS https://openidentity.foundation/ns/v1 -o v1.jsonld
curl -sS https://openidentity.foundation/ns/v1.sha256 -o v1.sha256
sha256sum -c v1.sha256
```

Never modify `/ns/v1` after publication. Use `/ns/v2` for an incompatible future context.

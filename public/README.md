# OpenIdentity public site

Deploy this directory as a Cloudflare Pages static site. No build command is required.

Resources:
- `/` — landing page
- `/ns` — vocabulary documentation
- `/ns/v1` — immutable JSON-LD context v1
- `/ns/v1.sha256` — v1 checksum
- `/ns/v2` — immutable cumulative JSON-LD context v2 for OI-003
- `/ns/v2.sha256` — v2 checksum
- `/test/credentials/basic/v1/context` — immutable Basic Credential Profile v1 JSON-LD context
- `/test/credentials/basic/v1/context.sha256` — Basic v1 context checksum

Context v2 SHA-256: `b3ad060c4a1841a3c4a7f7c9f96c11e62e8da54542e68eb1c383897eb19fda88`

Basic Credential Profile v1 context SHA-256: `416881790ed3914b8b0c5b982e7dbab978b4e2dea55a2004c4e08c88be2965d1`

After deployment:

```bash
curl -I https://openidentity.foundation/ns/v2
curl -sS https://openidentity.foundation/ns/v2 -o v2.jsonld
curl -sS https://openidentity.foundation/ns/v2.sha256 -o v2.sha256
sha256sum -c v2.sha256

curl -I https://openidentity.foundation/test/credentials/basic/v1/context
curl -sS https://openidentity.foundation/test/credentials/basic/v1/context -o context
curl -sS https://openidentity.foundation/test/credentials/basic/v1/context.sha256 -o context.sha256
sha256sum -c context.sha256
```

Published versioned contexts are immutable. Never modify `/ns/v1` or `/ns/v2`
after publication. Future incompatible context changes require a new version.

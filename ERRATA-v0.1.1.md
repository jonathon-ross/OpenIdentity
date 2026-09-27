# Protocol v0.1.1 Errata

This document records non-normative corrections discovered after the immutable
OpenIdentity Protocol v0.1.1 release tag was published.

## IdentityId vector checksum

The v0.1.1 tag contains the correct normative artifact:

`test-vectors/identity-id-v0.1.json`

but its adjacent checksum file contains a stale SHA-256 value.

The SHA-256 of the exact artifact published in the v0.1.1 tag is:

```text
625a795a02f2ffed3fb88c8187937a68f0b97ef5cfe61f76c632f1ef5a2abd92  identity-id-v0.1.json
```

The stale checksum recorded in the immutable v0.1.1 tag is:

```text
d417d4c68233df46535fabeaebb6f31af8d34e62b2c3b587d24c11bed56378f4
```

The normative JSON artifact itself is unchanged. The checksum file on `main`
has been corrected. The v0.1.1 tag is intentionally not rewritten.

Implementations targeting Protocol v0.1.1 SHOULD verify the IdentityId vector
artifact against the corrected digest above.

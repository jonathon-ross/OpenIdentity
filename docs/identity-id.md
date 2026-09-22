# OpenIdentity Identity Identifier Specification

**Document:** `identity-id.md`
**Story:** OI-001 — Define Identity ID
**Status:** OI-001 Complete - Protocol Draft v0.1
**Protocol:** OpenIdentity
**Normative Keywords:** MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY

---

# 1. Purpose

This document defines the permanent root identifier used by the OpenIdentity protocol.

An OpenIdentity identifier represents a persistent digital identity independently of:

* cryptographic keys;
* cryptographic algorithms;
* devices;
* identity providers;
* applications;
* blockchain networks;
* registry implementations;
* storage providers;
* credential issuers; and
* OpenIdentity infrastructure providers.

The identifier MUST remain stable throughout the lifetime of the identity.

An identity MAY change its cryptographic controllers, devices, recovery configuration, registry implementation, or underlying decentralized ledger without changing its OpenIdentity identifier.

---

# 2. Design Principle

An OpenIdentity identifier identifies the **identity**, not the mechanism currently controlling the identity.

The following concepts MUST remain separate:

```text
Identity
   │
   ├── Identifier
   │
   ├── Controller Policy
   │      └── Cryptographic Keys
   │
   ├── Recovery Policy
   │
   ├── Registry State
   │
   └── Credentials
```

Changing state beneath the identifier MUST NOT change the identifier itself.

---

# 3. DID Method

OpenIdentity SHALL use the W3C Decentralized Identifier URI model.

The canonical form is:

```text
did:open:<method-specific-id>
```

For OpenIdentity v0.1:

```text
<method-specific-id> =
    "z" + base58btc(identifier-bytes)
```

where:

```text
identifier-bytes = exactly 32 bytes
```

generated using a cryptographically secure random-number generator.

Therefore:

```text
OpenIdentity DID
        │
        ▼
did:open:z<base58btc-data>
```

---

# 4. Canonical Identifier Format

OpenIdentity v0.1 SHALL use:

| Property                | Value     |
| ----------------------- | --------- |
| URI scheme              | `did`     |
| DID method              | `open`    |
| Identifier entropy      | 256 bits  |
| Identifier size         | 32 bytes  |
| Encoding system         | Multibase |
| Canonical base          | base58btc |
| Multibase prefix        | `z`       |
| Multicodec              | None      |
| Multihash               | None      |
| Cryptographic algorithm | None      |
| Ledger identifier       | None      |
| Infrastructure provider | None      |

The canonical identifier therefore has the form:

```text
did:open:z<base58btc-encoded-32-byte-value>
```

Example structure:

```text
did:open:z7D82F91...
│   │   │
│   │   └── base58btc encoded identifier bytes
│   │
│   └────── Multibase prefix: base58btc
│
└────────── W3C DID + OpenIdentity method
```

---

# 5. Identifier Generation

A compliant implementation MUST generate exactly:

```text
32 bytes
```

of cryptographically secure random data.

Conceptually:

```text
CSPRNG
  │
  ▼
32 random bytes
  │
  ▼
base58btc encode
  │
  ▼
prepend "z"
  │
  ▼
prepend "did:open:"
  │
  ▼
OpenIdentity DID
```

Pseudocode:

```text
bytes = CSPRNG(32)

encoded = BASE58BTC_ENCODE(bytes)

methodSpecificId = "z" + encoded

did = "did:open:" + methodSpecificId
```

Generation MUST NOT require contacting:

* Paralax;
* Solana;
* another blockchain;
* an OpenIdentity registry;
* an OpenIdentity resolver;
* an OpenIdentity gateway; or
* any centralized identifier-allocation service.

The identifier MAY therefore be generated completely offline.

---

# 6. Why the Identifier Is Random

The identifier MUST NOT be derived from:

* controller public keys;
* private keys;
* blockchain addresses;
* email addresses;
* names;
* usernames;
* phone numbers;
* device identifiers;
* government identifiers;
* credentials;
* passwords; or
* predictable counters.

For example, this is prohibited:

```text
identifier = SHA256(controllerPublicKey)
```

even though such an identifier might appear random.

The permanent identity MUST remain independent of the cryptographic key currently controlling it.

Instead:

```text
identifier = CSPRNG(32)
```

---

# 7. Multibase Encoding

OpenIdentity v0.1 MUST use Multibase base58btc encoding.

The Multibase prefix for base58btc is:

```text
z
```

Therefore:

```text
did:open:z...
```

The `z` identifies the textual representation as base58btc.

OpenIdentity v0.1 MUST NOT accept alternative Multibase representations as canonical root identifiers.

For example, an equivalent 32-byte value represented using base64url MUST NOT be treated as a valid OpenIdentity v0.1 DID.

This prevents multiple textual representations from identifying the same OpenIdentity.

Therefore:

```text
did:open:zABC...
```

and:

```text
did:open:uXYZ...
```

MUST NOT both represent the same valid OpenIdentity v0.1 root identifier.

Only the canonical base58btc representation is valid.

---

# 8. Base58btc Alphabet

OpenIdentity SHALL use the Bitcoin base58 alphabet:

```text
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

The following visually ambiguous characters are excluded:

```text
0
O
I
l
```

The encoding MUST preserve leading zero bytes according to base58btc rules.

Each leading zero byte SHALL be represented by the character:

```text
1
```

after the Multibase prefix.

---

# 9. Normative Syntax

The following ABNF-style grammar describes the OpenIdentity v0.1 DID syntax.

```text
openidentity-did =
    "did:open:" openidentity-method-id

openidentity-method-id =
    "z" base58btc-value

base58btc-value =
    1*base58btc-char

base58btc-char =
      %x31-39
    / %x41-48
    / %x4A-4E
    / %x50-5A
    / %x61-6B
    / %x6D-7A
```

This grammar represents the allowed base58btc character set but is NOT sufficient by itself to establish validity.

After decoding `base58btc-value`, the result MUST contain exactly:

```text
32 bytes
```

An implementation MUST therefore perform both:

```text
syntactic validation
        +
binary-length validation
```

before accepting an OpenIdentity identifier.

---

# 10. Normative Validation Algorithm

A compliant OpenIdentity v0.1 implementation MUST perform the following validation procedure.

Given:

```text
candidate
```

### Step 1 — Verify DID prefix

The candidate MUST begin exactly with:

```text
did:open:
```

Comparison is case-sensitive.

The following is invalid:

```text
DID:OPEN:
```

---

### Step 2 — Extract method-specific identifier

Remove:

```text
did:open:
```

The remaining value MUST NOT be empty.

---

### Step 3 — Verify Multibase prefix

The first character MUST be:

```text
z
```

Any other Multibase prefix MUST be rejected for OpenIdentity v0.1.

---

### Step 4 — Extract base58btc payload

Remove the leading:

```text
z
```

The remaining payload MUST NOT be empty.

---

### Step 5 — Validate alphabet

Every character MUST belong to:

```text
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Characters including:

```text
0
O
I
l
```

MUST cause validation failure.

---

### Step 6 — Decode base58btc

Decode the payload using standard base58btc decoding.

If decoding fails, validation MUST fail.

---

### Step 7 — Verify decoded length

The decoded byte array MUST contain exactly:

```text
32 bytes
```

Values decoding to:

```text
31 bytes
```

or:

```text
33 bytes
```

MUST be rejected.

---

### Step 8 — Verify canonical encoding

The implementation MUST re-encode the decoded 32 bytes using canonical base58btc.

The resulting payload MUST exactly equal the supplied payload.

If:

```text
BASE58BTC_ENCODE(decoded) != suppliedPayload
```

the identifier MUST be rejected.

This prevents non-canonical alternate textual representations.

---

### Step 9 — Accept

If all previous checks succeed, the identifier is a syntactically valid OpenIdentity v0.1 root DID.

Validation does NOT prove:

* the identity is registered;
* the identity is active;
* the presenter controls the identity;
* the identity represents a specific person; or
* the identity possesses particular credentials.

Those properties require resolution and cryptographic verification.

---

# 11. Identifier and Controller Separation

An OpenIdentity identifier MUST NOT function as the controller key.

Instead:

```text
did:open:zABC
       │
       ▼
Identity State
       │
       ▼
Controller Policy
       │
       ├── Verification Method A
       └── Verification Method B
```

Controller keys MAY change without changing:

```text
did:open:zABC
```

---

# 12. Cryptographic Agility

OpenIdentity identifiers MUST remain independent of cryptographic algorithms.

The identifier MUST NOT encode:

* Ed25519;
* ECDSA;
* RSA;
* ML-DSA;
* SLH-DSA;
* hybrid signature schemes; or
* future cryptographic algorithms.

For example:

```text
2027

did:open:zABC
      │
      └── Ed25519
```

may later become:

```text
2032

did:open:zABC
      │
      ├── Ed25519
      └── ML-DSA
```

and later:

```text
2035

did:open:zABC
      │
      └── ML-DSA
```

without changing the DID.

Cryptographic agility is formally specified by OI-002.

---

# 13. Ledger Independence

The identifier MUST NOT encode the blockchain, registry, or consensus mechanism storing OpenIdentity state.

The following are invalid designs:

```text
did:open:solana:ABC
did:open:ethereum:ABC
did:open:bitcoin:ABC
```

Instead:

```text
did:open:zABC
```

resolves through the OpenIdentity DID method.

The authoritative registry MAY change during the lifetime of the identity without changing the DID.

---

# 14. Provider Independence

The identifier MUST NOT encode an infrastructure provider.

For example:

```text
did:open:paralax:ABC
```

is prohibited.

The identity MUST remain valid if the infrastructure provider that assisted with its creation ceases to exist.

---

# 15. Root Identity Privacy

The permanent root DID is a potentially correlatable identifier.

It MUST NOT be disclosed to ordinary relying-party applications by default.

The following model is prohibited as the default:

```text
                 did:open:zABC

                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼

       Website A    Website B    Website C

          zABC         zABC         zABC
```

OpenIdentity SHALL instead provide pairwise or pseudonymous subject identifiers.

Conceptually:

```text
                 ROOT IDENTITY

                 did:open:zABC
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼

       Website A    Website B    Website C

          │            │            │
          ▼            ▼            ▼

        ID-A         ID-B         ID-C
```

Unrelated relying parties SHOULD NOT be able to determine from normal authentication identifiers that two pairwise identifiers belong to the same root identity.

Pairwise identifier derivation is specified separately.

---

# 16. Intentional Identity Disclosure

A user MAY intentionally establish a verifiable relationship between their identity and:

* educational credentials;
* professional certifications;
* employment credentials;
* government credentials;
* applications;
* organizations;
* other identities; or
* AI agents.

Such disclosure MUST use an explicit protocol mechanism.

Ordinary authentication MUST NOT implicitly expose the root DID.

---

# 17. Credentials

Credentials MUST NOT be encoded into the identifier.

This is prohibited:

```text
did:open:zABC:security-plus
```

Instead:

```text
did:open:zABC
       │
       ├── Degree Credential
       ├── Professional Certification
       └── Employment Credential
```

Credentials are independently verifiable claims about an identity.

They are not part of the identity identifier.

---

# 18. Resolution

A compliant OpenIdentity resolver SHALL eventually support:

```text
resolve(did:open:zABC)
```

and return authoritative identity-control state.

Conceptually:

```text
did:open:zABC
       │
       ▼
OpenIdentity Resolver
       │
       ▼
Verifiable Registry
       │
       ▼
Identity State
```

The resolver MUST NOT assume that the underlying registry is Solana.

---

# 19. Identity Versus Real-World Person

Generating:

```text
did:open:zABC
```

establishes only a cryptographic identity identifier.

It does NOT establish:

```text
"This is Alice."
```

Real-world claims are established using verifiable credentials or other trust mechanisms.

OpenIdentity therefore distinguishes:

```text
IDENTITY

"A persistent independently
controllable identity exists."
```

from:

```text
CREDENTIAL

"An issuer makes a verifiable
claim about that identity."
```

---

# 20. Security Requirements

Implementations MUST use a cryptographically secure random-number generator.

Identifier generation MUST produce exactly 256 bits of entropy before encoding.

Implementations MUST NOT derive identifiers from predictable or personally identifying inputs.

Implementations SHOULD avoid logging root DIDs unnecessarily because root DIDs can enable correlation even though they contain no PII.

Implementations MUST treat root DIDs as privacy-sensitive identifiers.

---

# 21. OpenIdentity Identity Invariants

OI-001 establishes the following protocol invariants.

1. **Identity is not a cryptographic key.**
2. **Identity is not a blockchain address.**
3. **Identity is not owned by an infrastructure provider.**
4. **Root identity is not disclosed during ordinary application authentication by default.**
5. **Cryptographic algorithms are replaceable.**
6. **Ledger implementations are replaceable.**
7. **Applications receive pairwise/pseudonymous identifiers by default.**
8. **Private identity attributes are not required in public registry state.**
9. **One OpenIdentity root identity has exactly one canonical textual representation in a given protocol version.**

---

# 22. Normative Test Vectors

The following test vectors are normative for OpenIdentity v0.1.

A conforming implementation MUST produce the exact canonical output shown for each valid vector.

The encoding process is:

```text id="fj0i3h"
32 identifier bytes
        ↓
base58btc
        ↓
prepend "z"
        ↓
prepend "did:open:"
```

No Multicodec or Multihash bytes are inserted.

---

## 22.1 Valid Vector V01 — 32 Zero Bytes

### Identifier Bytes

Hexadecimal:

```text id="9y3c2a"
0000000000000000000000000000000000000000000000000000000000000000
```

Binary length:

```text id="jzk2s5"
32 bytes
```

Because each leading zero byte is represented by `1` in base58btc, the encoded payload contains exactly 32 `1` characters.

### Base58btc Payload

```text id="8gckga"
11111111111111111111111111111111
```

### Multibase Representation

```text id="mvdbmu"
z11111111111111111111111111111111
```

### Canonical OpenIdentity DID

```text id="x08ymb"
did:open:z11111111111111111111111111111111
```

### Expected Result

```text id="g2z71v"
VALID
```

This vector verifies:

* preservation of leading zero bytes;
* exact 32-byte length validation;
* base58btc encoding;
* Multibase prefix handling; and
* canonical DID construction.

---

## 22.2 Valid Vector V02 — Sequential Bytes

### Identifier Bytes

Hexadecimal:

```text id="ml5flp"
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Binary length:

```text id="48k05d"
32 bytes
```

### Base58btc Payload

```text id="3cyyjt"
1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE
```

### Multibase Representation

```text id="3i9d06"
z1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE
```

### Canonical OpenIdentity DID

```text id="8hk65j"
did:open:z1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE
```

### Expected Result

```text id="0ex2v3"
VALID
```

This vector verifies deterministic encoding of a known 256-bit value containing one leading zero byte.

---

## 22.3 Valid Vector V03 — Maximum 256-bit Value

### Identifier Bytes

Hexadecimal:

```text id="rru8fs"
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

Binary length:

```text id="21mv2s"
32 bytes
```

### Base58btc Payload

```text id="hn75x8"
JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG
```

### Multibase Representation

```text id="urxf9e"
zJEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG
```

### Canonical OpenIdentity DID

```text id="zow6s3"
did:open:zJEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG
```

### Expected Result

```text id="8on1ej"
VALID
```

This vector verifies correct encoding of the maximum possible unsigned 256-bit identifier value.

---

# 23. Invalid Test Vectors

The following test vectors MUST be rejected by a conforming OpenIdentity v0.1 implementation.

Where possible, implementations SHOULD return the specified validation category.

Implementations MAY use implementation-specific exception types or error structures provided they distinguish the same underlying validation failure.

---

## 23.1 Invalid Vector I01 — Wrong URI Scheme

### Input

```text id="40i4qw"
http:open:z11111111111111111111111111111111
```

### Expected Result

```text id="q2vt8d"
INVALID
```

### Expected Error

```text id="tbpqxg"
INVALID_DID_SCHEME
```

---

## 23.2 Invalid Vector I02 — Wrong DID Method

### Input

```text id="2x1jbx"
did:other:z11111111111111111111111111111111
```

### Expected Result

```text id="v3x9k8"
INVALID
```

### Expected Error

```text id="yb7k8r"
INVALID_DID_METHOD
```

---

## 23.3 Invalid Vector I03 — Incorrect Capitalization

### Input

```text id="kl5nkk"
DID:OPEN:z11111111111111111111111111111111
```

### Expected Result

```text id="hjlq4d"
INVALID
```

### Expected Error

```text id="y3l7a7"
INVALID_DID_PREFIX
```

OpenIdentity v0.1 DID validation is case-sensitive.

---

## 23.4 Invalid Vector I04 — Missing Method-Specific Identifier

### Input

```text id="p6srfg"
did:open:
```

### Expected Result

```text id="trgj6x"
INVALID
```

### Expected Error

```text id="2ypzcd"
MISSING_METHOD_ID
```

---

## 23.5 Invalid Vector I05 — Missing Multibase Prefix

### Input

```text id="rd6stt"
did:open:11111111111111111111111111111111
```

### Expected Result

```text id="1x13qw"
INVALID
```

### Expected Error

```text id="2c9esg"
INVALID_MULTIBASE_PREFIX
```

---

## 23.6 Invalid Vector I06 — Unsupported Multibase

### Input

```text id="s83rfz"
did:open:uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

### Expected Result

```text id="rr4sgq"
INVALID
```

### Expected Error

```text id="n29vwi"
UNSUPPORTED_MULTIBASE
```

Even if the value following `u` decodes to exactly 32 bytes using base64url, OpenIdentity v0.1 permits only canonical base58btc representation.

---

## 23.7 Invalid Vector I07 — Illegal Base58btc Character `0`

### Input

```text id="hnk02f"
did:open:z11111111111111111111111111111110
```

### Expected Result

```text id="cy50h2"
INVALID
```

### Expected Error

```text id="nsyu3z"
INVALID_BASE58BTC_CHARACTER
```

---

## 23.8 Invalid Vector I08 — Illegal Base58btc Character `O`

### Input

```text id="h8tyj6"
did:open:z1111111111111111111111111111111O
```

### Expected Result

```text id="op6mxc"
INVALID
```

### Expected Error

```text id="v5smbs"
INVALID_BASE58BTC_CHARACTER
```

---

## 23.9 Invalid Vector I09 — Illegal Base58btc Character `I`

### Input

```text id="mzkcyh"
did:open:z1111111111111111111111111111111I
```

### Expected Result

```text id="1e3wdv"
INVALID
```

### Expected Error

```text id="53pdk7"
INVALID_BASE58BTC_CHARACTER
```

---

## 23.10 Invalid Vector I10 — Illegal Base58btc Character `l`

### Input

```text id="0i3mjj"
did:open:z1111111111111111111111111111111l
```

### Expected Result

```text id="7fn7fm"
INVALID
```

### Expected Error

```text id="fpt3wl"
INVALID_BASE58BTC_CHARACTER
```

---

## 23.11 Invalid Vector I11 — 31-Byte Identifier

### Identifier Bytes

```text id="5g3j6e"
00000000000000000000000000000000000000000000000000000000000000
```

This value contains exactly:

```text id="57gh81"
31 bytes
```

### Base58btc Payload

```text id="1w4kz0"
1111111111111111111111111111111
```

### Multibase Representation

```text id="gl4fvq"
z1111111111111111111111111111111
```

### Input DID

```text id="cglj3f"
did:open:z1111111111111111111111111111111
```

### Expected Result

```text id="vjjif4"
INVALID
```

### Expected Error

```text id="i6whqg"
INVALID_IDENTIFIER_LENGTH
```

### Decoded Length

```text id="gzhq42"
31
```

---

## 23.12 Invalid Vector I12 — 33-Byte Identifier

### Identifier Bytes

```text id="3qfdt4"
000000000000000000000000000000000000000000000000000000000000000000
```

This value contains exactly:

```text id="m8pv09"
33 bytes
```

### Base58btc Payload

```text id="b0rf2y"
111111111111111111111111111111111
```

### Multibase Representation

```text id="bnt4xk"
z111111111111111111111111111111111
```

### Input DID

```text id="dlfx1f"
did:open:z111111111111111111111111111111111
```

### Expected Result

```text id="ewby0f"
INVALID
```

### Expected Error

```text id="u6kugz"
INVALID_IDENTIFIER_LENGTH
```

### Decoded Length

```text id="7by0fn"
33
```

---

## 23.13 Invalid Vector I13 — Cryptographic Algorithm Embedded in Identifier

### Input

```text id="f59t0g"
did:open:ed25519:z11111111111111111111111111111111
```

### Expected Result

```text id="8j9qz2"
INVALID
```

### Expected Error

```text id="k6w5xj"
INVALID_METHOD_ID
```

The cryptographic algorithm controlling an identity MUST NOT be encoded into the root identifier.

---

## 23.14 Invalid Vector I14 — Ledger Embedded in Identifier

### Input

```text id="jblnss"
did:open:solana:z11111111111111111111111111111111
```

### Expected Result

```text id="0js6br"
INVALID
```

### Expected Error

```text id="3dfnpw"
INVALID_METHOD_ID
```

The decentralized registry implementation MUST NOT be encoded into the root identifier.

---

## 23.15 Invalid Vector I15 — Infrastructure Provider Embedded in Identifier

### Input

```text id="gipd4j"
did:open:paralax:z11111111111111111111111111111111
```

### Expected Result

```text id="h0f2tk"
INVALID
```

### Expected Error

```text id="g6o2g1"
INVALID_METHOD_ID
```

The infrastructure provider MUST NOT be encoded into the root identifier.

---

# 24. Machine-Readable Test Vector Format

The canonical OpenIdentity repository SHOULD also publish these vectors in machine-readable form.

The recommended file is:

```text id="p9rxsd"
test-vectors/identity-id-v0.1.json
```

with the following structure:

```json id="oknjhk"
{
  "specification": "OpenIdentity Identity Identifier",
  "version": "0.1",

  "valid": [
    {
      "id": "V01",
      "description": "32 zero bytes",
      "inputHex": "0000000000000000000000000000000000000000000000000000000000000000",
      "base58btc": "11111111111111111111111111111111",
      "multibase": "z11111111111111111111111111111111",
      "did": "did:open:z11111111111111111111111111111111"
    },
    {
      "id": "V02",
      "description": "Sequential bytes 00 through 1f",
      "inputHex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "base58btc": "1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
      "multibase": "z1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
      "did": "did:open:z1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE"
    },
    {
      "id": "V03",
      "description": "Maximum 256-bit value",
      "inputHex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "base58btc": "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG",
      "multibase": "zJEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG",
      "did": "did:open:zJEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"
    }
  ],

  "invalid": [
    {
      "id": "I01",
      "did": "http:open:z11111111111111111111111111111111",
      "error": "INVALID_DID_SCHEME"
    },
    {
      "id": "I02",
      "did": "did:other:z11111111111111111111111111111111",
      "error": "INVALID_DID_METHOD"
    },
    {
      "id": "I03",
      "did": "DID:OPEN:z11111111111111111111111111111111",
      "error": "INVALID_DID_PREFIX"
    },
    {
      "id": "I04",
      "did": "did:open:",
      "error": "MISSING_METHOD_ID"
    },
    {
      "id": "I05",
      "did": "did:open:11111111111111111111111111111111",
      "error": "INVALID_MULTIBASE_PREFIX"
    },
    {
      "id": "I06",
      "did": "did:open:uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "error": "UNSUPPORTED_MULTIBASE"
    },
    {
      "id": "I07",
      "did": "did:open:z11111111111111111111111111111110",
      "error": "INVALID_BASE58BTC_CHARACTER"
    },
    {
      "id": "I08",
      "did": "did:open:z1111111111111111111111111111111O",
      "error": "INVALID_BASE58BTC_CHARACTER"
    },
    {
      "id": "I09",
      "did": "did:open:z1111111111111111111111111111111I",
      "error": "INVALID_BASE58BTC_CHARACTER"
    },
    {
      "id": "I10",
      "did": "did:open:z1111111111111111111111111111111l",
      "error": "INVALID_BASE58BTC_CHARACTER"
    },
    {
      "id": "I11",
      "did": "did:open:z1111111111111111111111111111111",
      "error": "INVALID_IDENTIFIER_LENGTH"
    },
    {
      "id": "I12",
      "did": "did:open:z111111111111111111111111111111111",
      "error": "INVALID_IDENTIFIER_LENGTH"
    },
    {
      "id": "I13",
      "did": "did:open:ed25519:z11111111111111111111111111111111",
      "error": "INVALID_METHOD_ID"
    },
    {
      "id": "I14",
      "did": "did:open:solana:z11111111111111111111111111111111",
      "error": "INVALID_METHOD_ID"
    },
    {
      "id": "I15",
      "did": "did:open:paralax:z11111111111111111111111111111111",
      "error": "INVALID_METHOD_ID"
    }
  ]
}
```

# 25. Conformance Requirement

An OpenIdentity v0.1 implementation MUST:

1. Produce the exact DID shown for V01, V02, and V03.
2. Decode each valid DID back to the exact original 32 bytes.
3. Reject every invalid vector I01 through I15.
4. Preserve leading zero bytes during Base58 encoding and decoding.
5. Reject identifiers that decode to anything other than exactly 32 bytes.
6. Reject non-base58btc Multibase representations.
7. Reject non-canonical representations.
8. Treat DID strings as case-sensitive.
9. Never infer controller algorithms, ledgers, providers, or identity attributes from the root DID.

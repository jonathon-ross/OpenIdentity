# OpenIdentity Documentation Status and Archive Index

This index prevents historical, released, candidate, and supporting documents from being confused with one another.

OpenIdentity generally does **not move or delete published/frozen protocol documents merely because a newer revision exists**. Stable repository paths are part of reproducibility: old release tags, checksums, citations, test tooling, and external references may depend on them.

Archiving therefore means **classifying a document as historical/superseded and directing new readers to its successor**, not rewriting history.

## Status classes

### Current release
Normative for the currently released protocol line. These documents remain authoritative for implementations targeting that release even when a future candidate exists.

### Candidate
Defines protocol evolution that has not yet replaced the current release. Candidate material may be byte-frozen for review while remaining non-normative.

### Historical / superseded
Preserved for compatibility, provenance, old vectors, release reconstruction, or historical explanation. New implementations should not use it as the current definition.

### Supporting
Explanatory, operational, interoperability, legal, or repository guidance. Supporting documents do not override normative specifications.

## Current released protocol — v0.1.1

The released normative line remains the documents under docs/ and spec/ identified by README.md, including spec/cddl/openidentity-operation-v2.cddl and spec/cddl/openidentity-credential-v1.cddl. These use ProtocolVersion 1 semantics and are **not obsolete** merely because ProtocolVersion 2 is being designed. ERRATA-v0.1.1.md remains supporting release-history material.

## Protocol evolution candidate — ProtocolVersion 2 / IdentityState v3

Start with docs/protocol-v2-identity-state-v3-guide.md. Candidate semantic and structural sources are spec/protocol-v2-identity-state-v3.md, spec/cddl/openidentity-operation-v3.cddl, and spec/protocol-v2-v3-conformance-plan.md. Candidate conformance material is test-vectors/generated/protocol-v2-identity-state-v3.json pinned by checksums/protocol-v2-identity-state-v3.json.sha256.

The candidate remains non-normative until explicitly promoted. It does not silently replace v0.1.1.

## Historical / superseded material

### spec/cddl/openidentity-operation-v1.cddl

**Status:** Historical/frozen compatibility schema.

For the released line it is superseded by spec/cddl/openidentity-operation-v2.cddl. For ProtocolVersion 2 candidate work use spec/cddl/openidentity-operation-v3.cddl.

The v1 CDDL remains at its original path because historical vectors, old commits, documentation, or external references may depend on that path. Its header already carries a historical-schema warning.

## Archival rules

1. **Do not delete** a document if it was part of a release, checksum, published reference, or conformance history.
2. **Do not move** it when moving would break stable paths or historical references.
3. Add a prominent HISTORICAL / SUPERSEDED header, identify the release/version it belongs to, and name the successor for new implementations.
4. Add it to the Historical / superseded section of this index.
5. Update README/navigation links so new readers reach the successor first.
6. Preserve its original normative meaning; do not retrofit newer semantics into the historical document.
7. If a document was never released, never externally referenced, and has no reproducibility value, it MAY be physically moved under archive/ after repository-wide link checks.
8. A physical archive move MUST update all live links and MUST NOT alter frozen release tags.

## Physical archive directory

The repository MAY use archive/drafts/, archive/design-notes/, and archive/superseded-unreleased/ only for material that is safe to move.

Do **not** place released normative specifications, released schemas, normative vectors, published contexts, checksums, or errata there merely because a newer protocol version exists.

## How to choose the right document

- Implementing released OpenIdentity: use the v0.1.1 documents and openidentity-operation-v2.cddl.
- Evaluating ProtocolVersion 2 / IdentityState v3: start with protocol-v2-identity-state-v3-guide.md, then the candidate spec and v3 CDDL.
- Reproducing early historical behavior: consult this index and use historical material only for the version it documents.

## Source-of-truth rule

A historical document never overrides the current source for a different protocol version. Likewise, a candidate document does not retroactively change a released protocol. Version context must always be established before interpreting operation codes, proof fields, IdentityState labels, or authority semantics.

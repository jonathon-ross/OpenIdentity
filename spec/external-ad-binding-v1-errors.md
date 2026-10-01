# External Active Directory Binding v1 — Error Taxonomy

Status: DRAFT-PRE-FREEZE.

Provider-neutral binding errors are reused where semantics are identical:
BINDING_NOT_FOUND, BINDING_CONFLICT, BINDING_REVOKED, BINDING_GENERATION_STALE,
IDENTITY_INACTIVE, BINDING_AUTHORIZATION_INVALID, BINDING_CONTEXT_MISMATCH,
BINDING_CHALLENGE_INVALID, BINDING_REPLAY, BINDING_ID_MISMATCH, BINDING_EXPIRED,
ASSURANCE_INSUFFICIENT.

AD-specific errors:

- AD_DIRECTORY_UNTRUSTED — directoryId is not an explicitly trusted configured directory.
- AD_PRINCIPAL_INVALID — authenticated AD principal cannot be resolved to one exact valid objectGUID, or canonical AD input is malformed.
- AD_SERVICE_NOT_ALLOWED — serviceId is not permitted by the selected directory profile.
- AD_AUTH_MECHANISM_NOT_ALLOWED — authentication mechanism is not allowed by policy.
- AD_ACCOUNT_UNUSABLE — directory policy marks the resolved account disabled, locked, expired, deleted, or otherwise unusable.
- AD_CHANNEL_UNTRUSTED — the authenticated directory channel/security context does not satisfy configured integrity/peer-authentication policy.

Error precedence is part of the semantic-vector suite before freeze. Parsers fail closed and do not repair malformed GUIDs, directory IDs, or nondeterministic CBOR.

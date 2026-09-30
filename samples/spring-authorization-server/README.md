# OpenIdentity Spring Authorization Server Sample

This sample hosts the OpenIdentity OAuth 2.0 Delegated Agent Profile v1 adapter in a complete Spring Authorization Server application.

It is intentionally outside the Java SDK Maven reactor. Install the SDK first:

```bash
cd java-sdk
mvn clean install
```

Then run:

```bash
cd ../samples/spring-authorization-server
mvn spring-boot:run
```

The sample is the black-box integration environment for `POST /oauth2/token`. It must not duplicate OpenIdentity protocol verification logic; protocol behavior comes from the SDK modules.

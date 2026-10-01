# OpenIdentity Spring Entra OIDC Sample

This sample performs a real single-tenant Microsoft Entra OIDC login through the provider-neutral OpenIdentity Spring bridge.

Required environment variables:

    OPENIDENTITY_ENTRA_TENANT_ID
    OPENIDENTITY_ENTRA_CLIENT_ID
    OPENIDENTITY_ENTRA_CLIENT_SECRET

Register a Web redirect URI in Microsoft Entra:

    http://localhost:8080/login/oauth2/code/entra

Run after installing the Java SDK artifacts locally:

    cd java-sdk
    mvn install

    cd ../samples/spring-entra-oidc
    mvn spring-boot:run

Then browse to:

    http://localhost:8080/oauth2/authorization/entra

The sample intentionally does not auto-bind an unrecognized Entra account. An unbound account is redirected to /openidentity/link. The next integration step is to connect that endpoint to the already-implemented OI-015 ExternalOidcBindingCeremony.

Do not commit tenant IDs, client IDs, client secrets, ID tokens, authorization codes, or session cookies.

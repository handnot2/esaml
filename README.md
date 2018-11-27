An implementation of the Security Assertion Markup Language (SAML) in Erlang. So far this supports enough of the standard to act as a Service Provider (SP) to perform authentication with SAML. It has been tested extensively against the SimpleSAMLPHP IdP and can be used in production.

### Supported protocols

The SAML standard refers to a flow of request/responses that make up one concrete action as a "protocol". Currently all of the basic Single-Sign-On and Single-Logout protocols are supported. There is no support at present for the optional Artifact Resolution, NameID Management, or NameID Mapping protocols.

Future work may add support for the Assertion Query protocol (which is useful to check if SSO is already available for a user without demanding they authenticate immediately).

Single sign-on protocols:

 * SP: send AuthnRequest (REDIRECT or POST) -> receive Response + Assertion (POST)

Single log-out protocols:

 * SP: send LogoutRequest (REDIRECT) -> receive LogoutResponse (REDIRECT or POST)
 * SP: receive LogoutRequest (REDIRECT OR POST) -> send LogoutResponse (REDIRECT)

esaml supports RSA+SHA1/SHA256 signing of all SP payloads, and validates signatures on all IdP responses. Compatibility flags are available to disable verification where IdP implementations lack support (see the [esaml_sp record](http://arekinath.github.io/esaml/esaml.html#type-sp), and members such as `idp_signs_logout_requests`).

### API documentation

Edoc documentation for the whole API is available at:

http://arekinath.github.io/esaml/

### Licensing

2-clause BSD

### More advanced usage

The `esaml_binding` and `esaml_sp` modules are the interface used by `esaml_cowboy` itself, and contain all the basic primitives to generate and parse SAML payloads.

This is particularly useful if you want to implement SOAP endpoints using SAML.

### Contributions

Pull requests are always welcome for bug fixes and improvements. Fixes that enable compatibility with different IdP implementations are usually welcome, but please ensure they do not come at the expense of compatibility with another IdP. esaml prefers to follow as closely to the SAML standards as possible.

Bugs/issues opened without patches are also welcome, but might take a lot longer to be looked at. ;)

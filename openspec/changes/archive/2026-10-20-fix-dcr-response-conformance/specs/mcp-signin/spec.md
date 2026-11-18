# Spec Delta

## MODIFIED Requirements

### Requirement: Client registration resolves pre-registered, CIMD, then gated DCR clients

Clients are resolved in priority order: pre-registered client id (operator config); a Client ID Metadata Document at a URL-shaped client id; Dynamic Client Registration only if enabled (default off). The CIMD fetch is server-side request forgery surface and MUST be bounded: HTTPS only, allowlisted origins, no redirects, private/loopback/link-local addresses refused, size capped, cached. All clients are public PKCE; no secret is stored; `redirect_uri` MUST be validated against the registration. The registration response document MUST conform to RFC 7591 §3.2.1 (member names and JSON types) in every member it emits, excepting `client_name`, which is emitted as JSON `null` when the registration request carried no client name; `client_id_issued_at`, when present, MUST be a JSON number of seconds since 1970-01-01T00:00:00Z derived from the registration record's stored creation instant.

#### Scenario: CIMD registration without a registration call
- **WHEN** a client presents a URL-shaped client id whose document is served by an allowlisted HTTPS origin
- **THEN** the gateway fetches and caches the document, and later authorization requests are accepted only for redirect URIs that match an entry of the document's `redirect_uris` under the redirect-URI matching rule

#### Scenario: CIMD fetch refused
- **WHEN** the client-id URL is not HTTPS, its origin is not allowlisted, it redirects, or it resolves to a private, loopback, or link-local address
- **THEN** the fetch is refused and the authorization request fails

#### Scenario: Unregistered redirect URI
- **WHEN** an authorization request carries a redirect URI that no entry of the client's resolved registration matches under the redirect-URI matching rule
- **THEN** the request is rejected

#### Scenario: DCR off by default
- **WHEN** DCR is not explicitly enabled and a client POSTs to the registration endpoint
- **THEN** the response is the documented disabled-error (404), and the AS metadata advertises no registration endpoint

#### Scenario: Registration response issued-at is an epoch number
- **WHEN** a client POSTs a registration with DCR enabled and the registration is accepted
- **THEN** the response document conforms to RFC 7591 §3.2.1 in every member it emits (`client_name` excepted as `null` when the request carried no name), and `client_id_issued_at` is a JSON number equal to the stored registration record's creation instant in seconds since 1970-01-01T00:00:00Z

#### Scenario: Re-registration answers the stored instant
- **WHEN** a registration arrives for a client id already in the store and the existing record is returned
- **THEN** the response's `client_id_issued_at` is the JSON number of that record's stored creation instant, not a freshly sampled time

idea for the "two-sign-ins-in-one" for MCP toolset call:
    * we create a simple reverse proxy - "dial-mcp-proxy", doing the following:
        * nginx, that sits on a separate host (or port) and listening /dial/{mcp-name}/mcp endpoint
        * if no token provided, it returns a dynamic challenge response, advertising itself as AS
        * then it proxies /authorize, /token and /register
        * the rest of request simply forwards it to dial
    * when /authorize if called, it performs "federation"
        * redirects to keycloak, forces user to authN (or SSO is used)
        * then calls /token (keycloak) and gets the real user's dial token and stores it (in memory? or better encrypted it and put into the proxy's own minted token that goes down to the client? would not store it in the proxy's state to avoid persistence)
        * then redirects user to MCP AS (Notion's)
        * user authenticates in MCP AS, our proxy gets a code from Notion
        * then proxy calls our /signin, passing keycloak token as a creds and notions code as a body -> thus internal sign-in complete
        * now it mints own token and sends it down to the harness
    * all real mcp traffic it just passes through to dial mcp
    * proxy's token is replaced with dial token which on dial is replaced with notion token
    * thus traffic remains perfectly authenticated: just double authentication is chained: proxy -> dial -> notion, no need to have 2 tokens in one call
    * question: whether or not we should create a "full reverse proxy" for MCP traffic or only own AS?
        * the answer depends on whether "AS only" can somehow know about which MCP the token is being minted for (to pass the code to the right /signin (toolset))
        * if not - we need to fully proxy MCP traffic. if it can know - we can implement only AS
---

*Imported into this repository from the DIAL design archive on 2026-10-17. This copy is the **living** version of this document; the archive copy is a frozen historical record and is not updated. References to the May 2026 toolset authentication design have been replaced with references to the DIAL Core source, because that document predates the MCP specification revision that deprecated Dynamic Client Registration.*

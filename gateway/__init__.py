"""The MCP sign-in gateway.

An OAuth2 authorization server that harnesses authenticate against to establish their
DIAL MCP toolset credential. It sits beside DIAL Core and is *not* on the MCP data path:
toolset traffic reaches Core directly and Core resolves the caller's stored upstream
credential from the identity in the token.
"""

# fix-dcr-response-conformance

Field-defect fix: the registration response forwards the store's ISO-8601 created_at verbatim into client_id_issued_at where RFC 7591 §3.2.1 requires a number, so strict harnesses (Cursor class) reject the whole document and DCR is broken for its target client class. Fix boundary: response-site conversion only; the store's at-rest shape unchanged.

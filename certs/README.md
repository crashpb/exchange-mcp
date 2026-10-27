# Operator CA certificates

No company certificates are distributed. If your IdP, EWS or LDAPS uses a private CA, place only its public PEM root/intermediate certificates here with a .crt extension before building. Never copy private keys. The image runs update-ca-certificates; public CAs work without extra files. Verify hostnames and the complete chain. Do not disable TLS verification.

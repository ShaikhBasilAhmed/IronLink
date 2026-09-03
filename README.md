# IronLink
IronLink lets mobile apps rotate pinned SSL/TLS certificates without shipping a new release. A FastAPI service signs pins with an ECDSA P-256 key stored in HashiCorp Vault; the response is CDN-cacheable, so origin load stays near zero at scale.

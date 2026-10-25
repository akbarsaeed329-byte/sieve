# ADR-013: OIDC single sign-on

**Date:** 2026-10-18 · **Status:** Accepted

Authorization code flow with PKCE (S256), state and nonce in a signed, 10-minute, path-scoped cookie. ID tokens are
verified against the provider's JWKS (RS256/ES256/PS256) for issuer, audience, expiry and nonce. Users are keyed by
issuer + subject, created on first sign-in, and their role is re-derived from groups at every sign-in (the IdP is the
source of truth). `default_role: none` denies users outside the mapped groups. SSO users have no local password.

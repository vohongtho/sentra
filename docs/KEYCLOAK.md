# Keycloak configuration and role mapping

## Client

Create one confidential OIDC client per Sentra deployment:

| Setting | Value |
|---|---|
| Client ID | `sentra` (any value; set `KEYCLOAK_CLIENT_ID`) |
| Client authentication | On (confidential). Put the secret in `KEYCLOAK_CLIENT_SECRET`. |
| Standard flow | On. Implicit flow, direct access grants and service accounts: off. |
| PKCE | `S256` (Sentra always sends a challenge) |
| Valid redirect URI | `https://<APP_ORIGIN host>/api/auth/callback`, exact |
| Valid post-logout redirect URI | `https://<APP_ORIGIN host>/*` |
| Back-channel logout URL | `https://<APP_ORIGIN host>/api/auth/backchannel-logout`, session required: on |
| Group membership mapper | claim `groups`, full path off, in the ID token |

`keycloak/sentra-realm.json` is a working local example: Keycloak 26.0 imported it and a browser login through it succeeded. Its client credential and user passwords are placeholders for laptops only.

Sentra validates the issuer, audience, signature (RS256, PS256 or ES256 via the realm JWKS, refetched when an unknown `kid` appears), expiry with 5 s clock tolerance, state and nonce. The refresh token and ID token are sealed server-side. The browser only holds `sentra_sid` (`__Host-sentra_sid` on HTTPS), HttpOnly with SameSite=Lax.

Session rules: the absolute lifetime is `SESSION_TTL_SECONDS` (8 h default) and the idle timeout is `SESSION_IDLE_SECONDS` (1 h). When the access-token lifetime passes, Sentra refreshes against Keycloak. If Keycloak refuses (session revoked, user disabled), the Sentra session ends.

When the server reaches Keycloak by a different hostname than the browser (Docker networking), set `KEYCLOAK_ISSUER` to the internal URL and `KEYCLOAK_PUBLIC_ISSUER` to the browser-facing one. Token and JWKS calls are rewritten to the internal host.

MFA, password policy, brute-force protection and identity federation are Keycloak realm settings. Sentra has no password system.

## From identity to access

A successful login only creates an identity. Access comes from exactly three sources, evaluated on every login:

1. **Role mappings** (**SSO & access → Keycloak role mapping**): a group (`groups` claim) or client role (`resource_access.<client>.roles`) maps to an organization role, or to a role on one project.
2. **Invitations** by email. These are applied only when Keycloak reports `email_verified: true`.
3. **Manual grants** by an org admin or project owner.

Someone with none of these is signed in but sees "No organization access".

| Org role | Can |
|---|---|
| `org_admin` | Everything, including members, role mappings, settings, secrets, gate policy defaults |
| `security_analyst` | Read all projects; triage, approve exceptions, run investigations, manage rules, schedules, advisories, campaigns, connections |
| `management_viewer` | Read all projects and dashboards |
| `auditor` | Read all projects and the audit trail |
| `member` | Only the projects granted below |

| Project role | Adds |
|---|---|
| `project_owner` | Manage the project, its members, CI tokens, connections, gate policy, agent policy; approve exceptions |
| `tech_lead` | Triage, request exceptions, tickets, deployments, connections |
| `developer` | Update findings, comment, tickets, run investigations |
| `devops` | Inventory imports, deployments, CI tokens, connections |
| `viewer` | Read |

The full matrix is served at `GET /api/org/permissions`.

Role changes take effect on the next request, because permissions are loaded per request. Removing or disabling a member revokes their sessions immediately. Queued agent runs re-derive the requester's permissions before every tool call, so revoked access stops a background investigation mid-run.

CI and connector identities are separate. CI uses project-scoped bearer tokens (`stk_…`, hashed at rest, expiring, revocable, optionally service-scoped) and never a user session. Keycloak service accounts and workload identity for CI are not implemented yet.

## Dedicated realm per customer

The default is one shared realm. Use a dedicated realm, meaning a separate Sentra deployment with its own `KEYCLOAK_ISSUER`, when a customer must control MFA and session policy independently, federate their own IdP without exposing it to other tenants, or keep their user directory out of a shared realm for contractual reasons.

# DialysisSafe security notes

## Passkeys

- Registration and login use WebAuthn with `@simplewebauthn/server`.
- User verification is required.
- The main application route redirects to the passkey menu until a session is established.
- Passkey private keys never reach this application or its server; the server stores only the credential public key and counter.

## API keys and secrets

- Do not put API keys in `index.html`, `auth.html`, JavaScript served to browsers, or committed files.
- Put server-only secrets in environment variables such as `.env` during local development or the deployment platform's secret store in production.
- `.env` and `.env.*` are ignored by git; `.env.example` contains placeholders only.
- If a real API key was previously committed, revoke/rotate it at the provider and remove it from git history. Moving a key to `.env` does not make an already-exposed key safe.

## Production requirements

The current credential/session maps are in-memory demo storage. Before production use, persist WebAuthn credentials in a database, use a shared session store, run behind HTTPS, and set `RP_ID`/`ORIGIN` to the real deployment host.

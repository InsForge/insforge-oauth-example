# InsForge OAuth Example

A simple example showing how third-party apps integrate with InsForge OAuth 2.0.

## The Flow

```
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│   This App      │          │    Browser      │          │   InsForge      │
│   (Port 4000)   │          │                 │          │   (Port 3000)   │
└────────┬────────┘          └────────┬────────┘          └────────┬────────┘
         │                            │                            │
         │ 1. User clicks             │                            │
         │    "Login with InsForge"   │                            │
         │<───────────────────────────│                            │
         │                            │                            │
         │ 2. Generate PKCE           │                            │
         │    Store verifier          │                            │
         │    Redirect to InsForge    │                            │
         │───────────────────────────>│                            │
         │                            │                            │
         │                            │ 3. GET /authorize          │
         │                            │    ?client_id=...          │
         │                            │    &code_challenge=...     │
         │                            │───────────────────────────>│
         │                            │                            │
         │                            │ 4. User logs in            │
         │                            │    User approves           │
         │                            │                            │
         │                            │ 5. Redirect to callback    │
         │                            │    ?code=ABC123            │
         │                            │<───────────────────────────│
         │                            │                            │
         │ 6. GET /auth/callback      │                            │
         │    ?code=ABC123            │                            │
         │<───────────────────────────│                            │
         │                            │                            │
         │ 7. POST /token             │                            │
         │    {code, code_verifier}   │                            │
         │────────────────────────────────────────────────────────>│
         │                            │                            │
         │ 8. {access_token}          │                            │
         │<────────────────────────────────────────────────────────│
         │                            │                            │
         │ 9. Store tokens            │                            │
         │    Redirect to home        │                            │
         │───────────────────────────>│                            │
         │                            │                            │
         │         USER IS NOW LOGGED IN                           │
```

## Setup

Migrate backend first!!!

### 1. Register your app in InsForge

First, register an OAuth client in InsForge to get your credentials:

```bash
curl -X POST http://localhost:3000/api/oauth/v1/clients/register \
  -H "Authorization: Bearer YOUR_INSFORGE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Example App",
    "redirect_uris": ["http://localhost:4000/auth/callback"],
    "allowed_scopes": ["user:read", "organizations:read", "projects:read", "projects:write"],
    "client_type": "confidential"
  }'
```

You'll receive:
```json
{
  "client_id": "abc123",
  "client_secret": "secret_xyz789"
}
```

### 2. Configure this app

Set environment variables or edit `src/server.js`:

```bash
export INSFORGE_CLIENT_ID="your_client_id"
export INSFORGE_CLIENT_SECRET="your_client_secret"
export INSFORGE_URL="http://localhost:3000"
export CALLBACK_URL="http://localhost:4000/auth/callback"
```

### 3. Install and run

```bash
npm install
npm start
```

### 4. Test the flow

1. Open http://localhost:4000
2. Click "Login with InsForge"
3. Log in to InsForge (if not already)
4. Approve the permissions
5. You're redirected back, logged in!

## Key Files

```
src/
└── server.js    # Complete OAuth implementation
```

## Important Concepts

### PKCE (Proof Key for Code Exchange)

```javascript
// 1. Generate random verifier (secret, stays on server)
const codeVerifier = crypto.randomBytes(32).toString('base64url');

// 2. Generate challenge (public, sent to InsForge)
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

// 3. Send challenge in /authorize request
// 4. Send verifier in /token request
// 5. InsForge verifies: SHA256(verifier) === challenge
```

### State Parameter (CSRF Protection)

```javascript
// Generate random state before redirect
const state = crypto.randomBytes(16).toString('hex');
req.session.oauthState = state;

// Verify it matches in callback
if (state !== req.session.oauthState) {
  return res.status(400).send('CSRF attack detected');
}
```

### Token Exchange (Server-to-Server)

The code exchange happens server-to-server, never exposing secrets to the browser:

```javascript
const response = await fetch('https://api.insforge.com/api/oauth/v1/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code: code,                    // From callback URL
    redirect_uri: CALLBACK_URL,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,  // Never exposed to browser
    code_verifier: codeVerifier,   // Never exposed to browser
  }),
});
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Home page (shows login button or user info) |
| `GET /auth/login` | Starts OAuth flow, redirects to InsForge |
| `GET /auth/callback` | Handles InsForge redirect, exchanges code |
| `GET /auth/logout` | Clears session |
| `GET /api/organizations` | Example API call using access token |

## Security Notes

1. **Never expose `client_secret`** - It stays on your server
2. **Never expose `code_verifier`** - It stays on your server
3. **Always verify `state`** - Prevents CSRF attacks
4. **Use HTTPS in production** - Protects all traffic
5. **Store tokens securely** - Use encrypted sessions/database

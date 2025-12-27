/**
 * InsForge OAuth Example - Third-Party Client
 *
 * This demonstrates how a third-party app integrates with InsForge OAuth 2.0
 *
 * Flow:
 * 1. User clicks "Login with InsForge"
 * 2. App redirects to InsForge /authorize with PKCE
 * 3. User logs in and approves on InsForge
 * 4. InsForge redirects back with authorization code
 * 5. App exchanges code for tokens (server-to-server)
 * 6. User is logged in
 */

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');

const app = express();

// =============================================================================
// Configuration
// =============================================================================

const config = {
  // Your InsForge OAuth credentials (get these from InsForge dashboard)
  INSFORGE_CLIENT_ID: process.env.INSFORGE_CLIENT_ID || 'your_client_id',
  INSFORGE_CLIENT_SECRET: process.env.INSFORGE_CLIENT_SECRET || 'your_client_secret',

  // InsForge URLs
  INSFORGE_URL: process.env.INSFORGE_URL || 'http://localhost:3000',

  // Your app's callback URL (must match registered redirect_uri)
  CALLBACK_URL: process.env.CALLBACK_URL || 'http://localhost:4000/auth/callback',

  // Scopes to request (user:read for profile, others for org/project access)
  SCOPES: 'user:read organizations:read projects:read projects:write',

  // Server port
  PORT: process.env.PORT || 4000,
};

// =============================================================================
// Middleware
// =============================================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-session-secret-change-in-production',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// =============================================================================
// PKCE Helpers
// =============================================================================

/**
 * Generate a random code verifier for PKCE
 */
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Generate code challenge from verifier (SHA256)
 */
function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Generate random state for CSRF protection
 */
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

// =============================================================================
// Routes
// =============================================================================

/**
 * Home page
 */
app.get('/', async (req, res) => {
  const user = req.session.user;
  const accessToken = req.session.accessToken;
  const pendingOAuth = req.session.pendingOAuth; // For popup mode

  // Fetch organizations and projects if logged in
  let organizations = [];
  if (accessToken) {
    try {
      const response = await fetch(`${config.INSFORGE_URL}/organizations/v1`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        organizations = data.organizations || [];

        // Fetch projects for each organization
        for (const org of organizations) {
          try {
            const projRes = await fetch(`${config.INSFORGE_URL}/organizations/v1/${org.id}/projects`, {
              headers: { 'Authorization': `Bearer ${accessToken}` },
            });
            if (projRes.ok) {
              const projData = await projRes.json();
              org.projects = projData.projects || [];

              // Fetch API key for each project
              for (const proj of org.projects) {
                try {
                  const keyRes = await fetch(`${config.INSFORGE_URL}/projects/v1/${proj.id}/access-api-key`, {
                    headers: { 'Authorization': `Bearer ${accessToken}` },
                  });
                  if (keyRes.ok) {
                    const keyData = await keyRes.json();
                    proj.access_api_key = keyData.access_api_key;
                  }
                } catch (e) {
                  // Ignore
                }
              }
            }
          } catch (e) {
            org.projects = [];
          }
        }
      }
    } catch (err) {
      console.error('Failed to fetch organizations:', err);
    }
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>InsForge OAuth Example</title>
      <style>
        * { box-sizing: border-box; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #0a0a0a;
          color: #e5e5e5;
          margin: 0;
          padding: 0;
          min-height: 100vh;
        }
        .container {
          max-width: 900px;
          margin: 0 auto;
          padding: 40px 24px;
        }
        .header {
          text-align: center;
          margin-bottom: 48px;
        }
        .header h1 {
          font-size: 28px;
          font-weight: 600;
          margin: 0 0 8px 0;
          color: #fff;
        }
        .header p {
          color: #737373;
          margin: 0;
        }
        .btn {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          background: #22c55e;
          color: #000;
          text-decoration: none;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          border: none;
          cursor: pointer;
          transition: background 0.2s;
        }
        .btn:hover { background: #16a34a; }
        .btn-secondary {
          background: #262626;
          color: #e5e5e5;
          border: 1px solid #404040;
        }
        .btn-secondary:hover { background: #333; }
        .btn-logout {
          background: transparent;
          border: 1px solid #404040;
          color: #e5e5e5;
          padding: 8px 16px;
          font-size: 13px;
        }
        .btn-logout:hover { background: #262626; border-color: #525252; }

        .card {
          background: #171717;
          border: 1px solid #262626;
          border-radius: 12px;
          padding: 24px;
          margin-bottom: 24px;
        }
        .user-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }
        .user-header h3 {
          margin: 0;
          font-size: 16px;
          color: #fff;
        }
        .user-details {
          display: grid;
          grid-template-columns: auto 1fr;
          gap: 8px 16px;
          font-size: 14px;
        }
        .user-details dt { color: #737373; }
        .user-details dd { margin: 0; color: #e5e5e5; font-family: monospace; }

        .section-title {
          font-size: 18px;
          font-weight: 600;
          color: #fff;
          margin: 0 0 20px 0;
        }

        .org-card {
          background: #1a1a1a;
          border: 1px solid #262626;
          border-radius: 10px;
          padding: 20px;
          margin-bottom: 16px;
        }
        .org-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 12px;
        }
        .org-header h4 {
          margin: 0;
          font-size: 16px;
          color: #fff;
        }
        .org-type {
          display: inline-block;
          padding: 4px 10px;
          background: #22c55e20;
          color: #22c55e;
          border-radius: 6px;
          font-size: 12px;
          font-weight: 500;
        }
        .org-desc {
          color: #737373;
          font-size: 14px;
          margin: 0 0 16px 0;
        }

        .projects-section {
          border-top: 1px solid #262626;
          padding-top: 16px;
        }
        .projects-title {
          font-size: 13px;
          font-weight: 600;
          color: #a3a3a3;
          margin: 0 0 12px 0;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .project-card {
          background: #0a0a0a;
          border: 1px solid #262626;
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 12px;
        }
        .project-card:last-child { margin-bottom: 0; }
        .project-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }
        .project-name {
          font-weight: 600;
          color: #fff;
          font-size: 14px;
        }
        .project-status {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 12px;
          color: #22c55e;
        }
        .project-status::before {
          content: '';
          width: 8px;
          height: 8px;
          background: #22c55e;
          border-radius: 50%;
        }
        .project-details {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        .detail-row {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .detail-label {
          font-size: 12px;
          color: #737373;
          min-width: 70px;
        }
        .detail-value {
          font-family: 'SF Mono', Monaco, monospace;
          font-size: 12px;
          color: #e5e5e5;
          background: #262626;
          padding: 6px 10px;
          border-radius: 6px;
          flex: 1;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .detail-value.url { color: #60a5fa; }
        .detail-value.key { color: #fbbf24; }

        .token-section {
          margin-top: 32px;
        }
        .token-box {
          background: #0a0a0a;
          border: 1px solid #262626;
          border-radius: 8px;
          padding: 16px;
          font-family: 'SF Mono', Monaco, monospace;
          font-size: 12px;
          color: #737373;
          word-break: break-all;
          line-height: 1.6;
        }

        .login-hero {
          text-align: center;
          padding: 80px 20px;
        }
        .login-hero p {
          color: #737373;
          margin: 0 0 32px 0;
          font-size: 16px;
        }
        .how-it-works {
          margin-top: 48px;
        }
        .how-it-works h3 {
          font-size: 16px;
          color: #fff;
          margin: 0 0 16px 0;
        }
        .how-it-works ol {
          color: #a3a3a3;
          line-height: 1.8;
          padding-left: 20px;
        }
        .no-data {
          color: #525252;
          font-size: 14px;
          text-align: center;
          padding: 24px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>InsForge OAuth Demo</h1>
          <p>Third-party application using InsForge OAuth 2.0</p>
        </div>

        ${user ? `
          <div class="card">
            <div class="user-header">
              <h3>Authenticated User</h3>
              <a href="/auth/logout" class="btn btn-logout">Sign Out</a>
            </div>
            <dl class="user-details">
              <dt>User ID</dt>
              <dd>${user.id || 'N/A'}</dd>
              <dt>Email</dt>
              <dd>${user.email || 'N/A'}</dd>
            </dl>
          </div>

          <h2 class="section-title">Organizations (${organizations.length})</h2>
          ${organizations.length > 0 ? organizations.map(org => `
            <div class="org-card">
              <div class="org-header">
                <h4>${org.name || 'Unnamed'}</h4>
                <span class="org-type">${org.type || 'organization'}</span>
              </div>
              <p class="org-desc">${org.description || 'No description'}</p>

              ${org.projects && org.projects.length > 0 ? `
                <div class="projects-section">
                  <h5 class="projects-title">Projects (${org.projects.length})</h5>
                  ${org.projects.map(proj => `
                    <div class="project-card">
                      <div class="project-header">
                        <span class="project-name">${proj.name}</span>
                        <span class="project-status">${proj.status || 'active'}</span>
                      </div>
                      <div class="project-details">
                        <div class="detail-row">
                          <span class="detail-label">API URL</span>
                          <span class="detail-value url">https://${proj.appkey}.${proj.region}.insforge.app</span>
                        </div>
                        <div class="detail-row">
                          <span class="detail-label">Region</span>
                          <span class="detail-value">${proj.region}</span>
                        </div>
                        ${proj.access_api_key ? `
                          <div class="detail-row">
                            <span class="detail-label">API Key</span>
                            <span class="detail-value key">${proj.access_api_key}</span>
                          </div>
                        ` : ''}
                      </div>
                    </div>
                  `).join('')}
                </div>
              ` : `
                <p class="no-data">No projects in this organization</p>
              `}
            </div>
          `).join('') : `
            <p class="no-data">No organizations found</p>
          `}

          <div class="token-section">
            <h2 class="section-title">Access Token</h2>
            <div class="token-box">${accessToken}</div>
          </div>
        ` : `
          <div class="login-hero">
            <p>Connect your InsForge account to access your organizations and projects</p>
            <div style="display: flex; gap: 16px; justify-content: center; flex-wrap: wrap;">
              <button onclick="openOAuthPopup()" class="btn">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="3" y="3" width="18" height="18" rx="2"/>
                  <path d="M9 3v18"/>
                </svg>
                Popup Mode
              </button>
              <a href="/auth/login" class="btn btn-secondary">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/>
                  <polyline points="10 17 15 12 10 7"/>
                  <line x1="15" y1="12" x2="3" y2="12"/>
                </svg>
                Redirect Mode
              </a>
            </div>
          </div>

          <div class="how-it-works card">
            <h3>OAuth Flow Modes</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
              <div>
                <h4 style="color: #22c55e; margin: 0 0 8px 0;">Popup Mode</h4>
                <ol style="margin: 0; padding-left: 20px;">
                  <li>Opens popup window</li>
                  <li>User stays on your app</li>
                  <li>Uses localStorage event</li>
                  <li>Better UX for SPAs</li>
                </ol>
              </div>
              <div>
                <h4 style="color: #60a5fa; margin: 0 0 8px 0;">Redirect Mode</h4>
                <ol style="margin: 0; padding-left: 20px;">
                  <li>Full page redirect</li>
                  <li>Standard OAuth flow</li>
                  <li>No popup blockers</li>
                  <li>Works everywhere</li>
                </ol>
              </div>
            </div>
          </div>

          <script>
            function openOAuthPopup() {
              const width = 500;
              const height = 700;
              const left = window.screenX + (window.outerWidth - width) / 2;
              const top = window.screenY + (window.outerHeight - height) / 2;

              const popup = window.open(
                '/auth/login-popup',
                'insforge-oauth',
                \`width=\${width},height=\${height},left=\${left},top=\${top},popup=1\`
              );

              // Listen for storage event (works across same-origin windows)
              function handleStorage(event) {
                if (event.key === 'oauth_complete') {
                  console.log('[Parent] OAuth complete via localStorage');
                  localStorage.removeItem('oauth_complete');
                  window.removeEventListener('storage', handleStorage);
                  window.location.reload();
                }
              }
              window.addEventListener('storage', handleStorage);
              console.log('[Parent] Listening for oauth_complete in localStorage...');
            }
          </script>
        `}
      </div>
    </body>
    </html>
  `);
});

/**
 * Step 1: Start OAuth flow (Redirect mode - legacy)
 *
 * - Generate PKCE verifier and challenge
 * - Generate state for CSRF protection
 * - Store verifier and state in session
 * - Redirect to InsForge /authorize
 */
app.get('/auth/login', (req, res) => {
  // Generate PKCE pair
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Generate state for CSRF protection
  const state = generateState();

  // Store in session (needed for callback)
  req.session.oauthState = state;
  req.session.codeVerifier = codeVerifier;

  // Build InsForge authorization URL
  const authUrl = new URL(`${config.INSFORGE_URL}/api/oauth/v1/authorize`);
  authUrl.searchParams.set('client_id', config.INSFORGE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', config.CALLBACK_URL);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', config.SCOPES);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  console.log('Redirecting to InsForge:', authUrl.toString());

  // Redirect user to InsForge
  res.redirect(authUrl.toString());
});

/**
 * Step 1b: Start OAuth flow (Popup mode)
 * Same as /auth/login but for popup window
 * Uses state parameter to encode popup mode (more reliable than sessions)
 */
app.get('/auth/login-popup', (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const stateToken = generateState();

  // Encode popup mode in state (format: "token:popup")
  const state = `${stateToken}:popup`;

  req.session.oauthState = state;
  req.session.codeVerifier = codeVerifier;

  const authUrl = new URL(`${config.INSFORGE_URL}/api/oauth/v1/authorize`);
  authUrl.searchParams.set('client_id', config.INSFORGE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', config.CALLBACK_URL);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', config.SCOPES);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  console.log('Popup: Redirecting to InsForge:', authUrl.toString());
  res.redirect(authUrl.toString());
});

/**
 * Step 2b: OAuth callback for popup mode
 * Called by parent window after receiving postMessage
 */
app.get('/auth/callback-popup', async (req, res) => {
  const { code, state } = req.query;

  if (state && state !== req.session.oauthState) {
    return res.status(400).send('Invalid state');
  }

  const codeVerifier = req.session.codeVerifier;
  if (!codeVerifier) {
    return res.status(400).send('Session expired');
  }

  try {
    const tokenResponse = await fetch(`${config.INSFORGE_URL}/api/oauth/v1/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: config.CALLBACK_URL,
        client_id: config.INSFORGE_CLIENT_ID,
        client_secret: config.INSFORGE_CLIENT_SECRET,
        code_verifier: codeVerifier,
      }),
    });

    const tokens = await tokenResponse.json();
    if (tokens.error) {
      return res.status(400).send(`Token error: ${tokens.error}`);
    }

    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token;
    delete req.session.oauthState;
    delete req.session.codeVerifier;

    const profileResponse = await fetch(`${config.INSFORGE_URL}/auth/v1/profile`, {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` },
    });
    if (profileResponse.ok) {
      const profile = await profileResponse.json();
      req.session.user = profile.user;
    }

    res.redirect('/');
  } catch (err) {
    console.error('Popup token exchange failed:', err);
    res.status(500).send('Token exchange failed');
  }
});

/**
 * Step 2: OAuth callback
 *
 * InsForge redirects here after user approves.
 * This handles BOTH popup mode and redirect mode.
 *
 * - Verify state matches
 * - Exchange code for tokens (server-to-server)
 * - If popup: send postMessage to parent and close
 * - If redirect: redirect to home page
 */
app.get('/auth/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // Helper to send error response
  const sendError = (message) => {
    return res.send(`
      <h1>Authorization Failed</h1>
      <p>${message}</p>
      <a href="/">Go back</a>
    `);
  };

  // Check for errors from InsForge
  if (error) {
    console.error('OAuth error:', error, error_description);
    return sendError(`Error: ${error}. ${error_description || ''}`);
  }

  // Check if this is popup mode (encoded in state as "token:popup")
  const isPopup = state?.endsWith(':popup');

  // Verify state (CSRF protection)
  if (state !== req.session.oauthState) {
    console.error('State mismatch:', state, req.session.oauthState);
    return sendError('Invalid state parameter. Possible CSRF attack.');
  }

  // Get code verifier from session
  const codeVerifier = req.session.codeVerifier;
  if (!codeVerifier) {
    return sendError('Missing code verifier. Session may have expired.');
  }

  try {
    // Exchange code for tokens (server-to-server call)
    console.log('Exchanging code for tokens...');

    const tokenResponse = await fetch(`${config.INSFORGE_URL}/api/oauth/v1/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: config.CALLBACK_URL,
        client_id: config.INSFORGE_CLIENT_ID,
        client_secret: config.INSFORGE_CLIENT_SECRET,
        code_verifier: codeVerifier, // PKCE: proves we started the flow
      }),
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      console.error('Token exchange error:', tokens);
      return sendError(`Token exchange failed: ${tokens.error}. ${tokens.message || ''}`);
    }

    console.log('Tokens received:', {
      access_token: tokens.access_token?.substring(0, 20) + '...',
      refresh_token: tokens.refresh_token?.substring(0, 20) + '...',
      expires_in: tokens.expires_in,
    });

    // Store tokens in session
    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token;

    // Clean up OAuth session data
    delete req.session.oauthState;
    delete req.session.codeVerifier;

    // Fetch user profile using the access token
    const profileResponse = await fetch(`${config.INSFORGE_URL}/auth/v1/profile`, {
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`,
      },
    });

    if (profileResponse.ok) {
      const profile = await profileResponse.json();
      req.session.user = profile.user;
    }

    // If popup mode, notify parent via localStorage and close
    if (isPopup) {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Authorization Complete</title></head>
        <body>
          <h2>Authorization successful!</h2>
          <p>This window will close automatically...</p>
          <script>
            console.log('[Popup] OAuth complete, notifying parent...');

            // Use localStorage to notify parent (storage event fires in other windows)
            localStorage.setItem('oauth_complete', Date.now().toString());
            console.log('[Popup] Set oauth_complete in localStorage');

            // Try to close the popup window
            function closePopup() {
              try {
                window.close();
              } catch (e) {
                console.log('[Popup] Could not close window:', e);
              }
            }

            // Close after a short delay to ensure localStorage event fires
            setTimeout(closePopup, 300);

            // Fallback: if window didn't close after 2 seconds, show a manual close link
            setTimeout(() => {
              if (!window.closed) {
                document.body.innerHTML = '<h2>Authorization successful!</h2><p>You can close this tab and return to the app.</p><button onclick="window.close()" style="padding: 10px 20px; font-size: 16px; cursor: pointer;">Close this tab</button>';
              }
            }, 2000);
          </script>
        </body>
        </html>
      `);
    }

    // Redirect mode - redirect to home page
    res.redirect('/');

  } catch (err) {
    console.error('Token exchange failed:', err);
    res.status(500).send('Failed to exchange code for tokens');
  }
});

/**
 * Logout
 */
app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

/**
 * Example: Fetch organizations using the access token
 */
app.get('/api/organizations', async (req, res) => {
  const accessToken = req.session.accessToken;

  if (!accessToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const response = await fetch(`${config.INSFORGE_URL}/organizations/v1`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    const data = await response.json();
    res.json(data);

  } catch (err) {
    console.error('API call failed:', err);
    res.status(500).json({ error: 'Failed to fetch organizations' });
  }
});

// =============================================================================
// Start Server
// =============================================================================

app.listen(config.PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   InsForge OAuth Example Client                               ║
║                                                               ║
║   Running at: http://localhost:${config.PORT}                      ║
║                                                               ║
║   Callback URL: ${config.CALLBACK_URL}      ║
║                                                               ║
║   Make sure this matches your registered redirect_uri         ║
║   in InsForge!                                                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});

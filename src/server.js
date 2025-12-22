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

  // Scopes to request
  SCOPES: 'user:read organizations:read',

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

  // Fetch organizations if logged in
  let organizations = [];
  if (accessToken) {
    try {
      const response = await fetch(`${config.INSFORGE_URL}/api/organizations/v1`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        organizations = data.organizations || [];
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
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          max-width: 800px;
          margin: 50px auto;
          padding: 20px;
        }
        .header {
          text-align: center;
          margin-bottom: 40px;
        }
        .btn {
          display: inline-block;
          padding: 12px 24px;
          background: #3b82f6;
          color: white;
          text-decoration: none;
          border-radius: 8px;
          font-size: 16px;
          border: none;
          cursor: pointer;
        }
        .btn:hover { background: #2563eb; }
        .btn-logout { background: #ef4444; }
        .btn-logout:hover { background: #dc2626; }
        .user-info {
          background: #f3f4f6;
          padding: 20px;
          border-radius: 8px;
          margin: 20px 0;
        }
        .org-list {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
          gap: 16px;
          margin: 20px 0;
        }
        .org-card {
          background: white;
          border: 1px solid #e5e7eb;
          border-radius: 8px;
          padding: 20px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .org-card h3 {
          margin: 0 0 8px 0;
          color: #111827;
        }
        .org-card p {
          margin: 0;
          color: #6b7280;
          font-size: 14px;
        }
        .org-type {
          display: inline-block;
          padding: 2px 8px;
          background: #dbeafe;
          color: #1d4ed8;
          border-radius: 4px;
          font-size: 12px;
          margin-top: 8px;
        }
        pre {
          background: #1f2937;
          color: #f9fafb;
          padding: 16px;
          border-radius: 8px;
          overflow-x: auto;
          font-size: 12px;
        }
        .section {
          margin: 30px 0;
        }
        .section h2 {
          border-bottom: 2px solid #e5e7eb;
          padding-bottom: 10px;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>InsForge OAuth Example</h1>
        <p>Third-party app integrating with InsForge OAuth 2.0</p>
      </div>

      ${user ? `
        <div class="user-info">
          <h3>Logged in as:</h3>
          <p><strong>User ID:</strong> ${user.id || 'N/A'}</p>
          <p><strong>Email:</strong> ${user.email || 'N/A'}</p>
          <br>
          <a href="/auth/logout" class="btn btn-logout">Logout</a>
        </div>

        <div class="section">
          <h2>Your Organizations (${organizations.length})</h2>
          ${organizations.length > 0 ? `
            <div class="org-list">
              ${organizations.map(org => `
                <div class="org-card">
                  <h3>${org.name || 'Unnamed'}</h3>
                  <p>${org.description || 'No description'}</p>
                  <span class="org-type">${org.type || 'organization'}</span>
                </div>
              `).join('')}
            </div>
          ` : `
            <p>No organizations found.</p>
          `}
        </div>

        <div class="section">
          <h2>Access Token</h2>
          <pre>${accessToken?.substring(0, 80)}...</pre>
        </div>
      ` : `
        <div style="text-align: center; margin: 60px 0;">
          <p>Click below to login with your InsForge account</p>
          <br>
          <a href="/auth/login" class="btn">Login with InsForge</a>
        </div>

        <div class="section">
          <h2>How it works</h2>
          <ol>
            <li>Click "Login with InsForge"</li>
            <li>You're redirected to InsForge to login/approve</li>
            <li>InsForge redirects back with an authorization code</li>
            <li>This app exchanges the code for tokens (server-to-server)</li>
            <li>You're now logged in and can see your organizations!</li>
          </ol>
        </div>
      `}
    </body>
    </html>
  `);
});

/**
 * Step 1: Start OAuth flow
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
 * Step 2: OAuth callback
 *
 * InsForge redirects here after user approves.
 *
 * - Verify state matches
 * - Exchange code for tokens (server-to-server)
 * - Store tokens in session
 */
app.get('/auth/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // Check for errors from InsForge
  if (error) {
    console.error('OAuth error:', error, error_description);
    return res.send(`
      <h1>Authorization Failed</h1>
      <p>Error: ${error}</p>
      <p>${error_description || ''}</p>
      <a href="/">Go back</a>
    `);
  }

  // Verify state (CSRF protection)
  if (state !== req.session.oauthState) {
    console.error('State mismatch:', state, req.session.oauthState);
    return res.status(400).send('Invalid state parameter. Possible CSRF attack.');
  }

  // Get code verifier from session
  const codeVerifier = req.session.codeVerifier;
  if (!codeVerifier) {
    return res.status(400).send('Missing code verifier. Session may have expired.');
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
      return res.send(`
        <h1>Token Exchange Failed</h1>
        <p>Error: ${tokens.error}</p>
        <p>${tokens.message || ''}</p>
        <a href="/">Go back</a>
      `);
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
    const profileResponse = await fetch(`${config.INSFORGE_URL}/api/auth/v1/profile`, {
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`,
      },
    });

    if (profileResponse.ok) {
      const profile = await profileResponse.json();
      req.session.user = profile.user;
    }

    // Redirect to home
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
    const response = await fetch(`${config.INSFORGE_URL}/api/organizations/v1`, {
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

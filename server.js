import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';

const app = express();
app.use(express.json({ limit: '12mb' }));

const PORT = Number(process.env.PORT || 3000);
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const RP_NAME = process.env.RP_NAME || 'DialysisSafe';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
const AUTH_USERNAME = String(process.env.AUTH_USERNAME || '').trim();
const AUTH_PASSWORD_HASH = String(process.env.AUTH_PASSWORD_HASH || '').trim();
const COOKIE_NAME = 'dialysis_safe_session';

const credentials = new Map();
const challenges = new Map();
const sessions = new Map();
const apiKeys = new Map();

function base64url(buffer) { return Buffer.from(buffer).toString('base64url'); }
function randomToken() { return base64url(crypto.randomBytes(32)); }
function hashKey(key) { return crypto.createHash('sha256').update(key).digest('hex'); }
function readCookie(req, name) {
  const row = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return row ? decodeURIComponent(row.slice(name.length + 1)) : null;
}
function sessionUsername(req) {
  const token = readCookie(req, COOKIE_NAME);
  return token ? sessions.get(token) || null : null;
}
function isAuthenticated(req) { return Boolean(sessionUsername(req)); }
function setSession(res, username) {
  const token = randomToken();
  sessions.set(token, username);
  const secure = ORIGIN.startsWith('https://') ? ' Secure;' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=28800`);
}
function requireSession(req, res, next) {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Authentication required' });
  next();
}
function createApiKey(username) {
  const apiKey = `ds_${base64url(crypto.randomBytes(64))}`;
  apiKeys.set(hashKey(apiKey), { username, createdAt: new Date().toISOString() });
  return apiKey;
}

// Passwords are never stored in this file. AUTH_PASSWORD_HASH must be a scrypt hash
// generated with: npm run hash-password -- YourPassword
function verifyPassword(password) {
  if (!AUTH_USERNAME || !AUTH_PASSWORD_HASH || !password) return false;
  const parts = AUTH_PASSWORD_HASH.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  try {
    const salt = Buffer.from(parts[1], 'base64url');
    const expected = Buffer.from(parts[2], 'base64url');
    const actual = crypto.scryptSync(password, salt, expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

app.get('/', (req, res) => res.redirect(isAuthenticated(req) ? '/index.html' : '/auth.html'));

app.get('/auth.html', (req, res) => {
  if (isAuthenticated(req)) return res.redirect('/index.html');
  res.sendFile('auth.html', { root: '.' });
});

app.get('/index.html', async (req, res, next) => {
  if (!isAuthenticated(req)) return res.redirect('/auth.html');
  try {
    const html = await fs.readFile('index.html', 'utf8');
    res.type('html').send(html);
  } catch (error) { next(error); }
});

app.get('/api/auth/status', (req, res) => res.json({
  passwordConfigured: Boolean(AUTH_USERNAME && AUTH_PASSWORD_HASH),
  passkeyConfigured: Boolean(RP_ID && ORIGIN),
  enrolled: credentials.size > 0,
  authenticated: isAuthenticated(req),
  username: sessionUsername(req)
}));

app.post('/api/auth/password/login', (req, res) => {
  const username = String(req.body?.username || '').trim().slice(0, 80);
  const password = String(req.body?.password || '');
  if (!AUTH_USERNAME || !AUTH_PASSWORD_HASH) {
    return res.status(503).json({ error: 'Password login is not configured on the server yet.' });
  }
  if (username !== AUTH_USERNAME || !verifyPassword(password)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }
  setSession(res, AUTH_USERNAME);
  res.json({ verified: true, username: AUTH_USERNAME });
});

app.post('/api/auth/register/options', async (req, res) => {
  const username = String(req.body?.username || '').trim().slice(0, 80);
  if (!username) return res.status(400).json({ error: 'Username is required' });
  const userID = base64url(crypto.createHash('sha256').update(username).digest());
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: username,
    userID,
    attestationType: 'none',
    excludeCredentials: [...credentials.values()].filter(c => c.username === username).map(c => ({ id: c.id })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' }
  });
  challenges.set(`reg:${username}`, options.challenge);
  res.json(options);
});

app.post('/api/auth/register/verify', async (req, res) => {
  const username = String(req.body?.username || '').trim().slice(0, 80);
  const expectedChallenge = challenges.get(`reg:${username}`);
  if (!expectedChallenge) return res.status(400).json({ error: 'Registration challenge expired' });
  try {
    const verification = await verifyRegistrationResponse({
      response: req.body.response,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true
    });
    if (!verification.verified || !verification.registrationInfo) return res.status(400).json({ error: 'Passkey registration failed' });
    const info = verification.registrationInfo;
    credentials.set(info.credential.id, {
      id: info.credential.id,
      publicKey: info.credential.publicKey,
      counter: info.credential.counter,
      username
    });
    challenges.delete(`reg:${username}`);
    setSession(res, username);
    res.json({ verified: true, username, apiKey: createApiKey(username) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/auth/login/options', async (_req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials: [...credentials.values()].map(c => ({ id: c.id, type: 'public-key' }))
  });
  challenges.set('login', options.challenge);
  res.json(options);
});

app.post('/api/auth/login/verify', async (req, res) => {
  const expectedChallenge = challenges.get('login');
  const credential = credentials.get(req.body?.response?.id);
  if (!expectedChallenge) return res.status(400).json({ error: 'Login challenge expired' });
  if (!credential) return res.status(401).json({ error: 'Unknown passkey' });
  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body.response,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: { id: credential.id, publicKey: credential.publicKey, counter: credential.counter },
      requireUserVerification: true
    });
    if (!verification.verified) return res.status(401).json({ error: 'Passkey verification failed' });
    credential.counter = verification.authenticationInfo.newCounter;
    challenges.delete('login');
    setSession(res, credential.username);
    res.json({ verified: true, username: credential.username, apiKey: createApiKey(credential.username) });
  } catch (error) { res.status(401).json({ error: error.message }); }
});

app.post('/api/key/issue', requireSession, (req, res) => res.status(201).json({ apiKey: createApiKey(sessionUsername(req)) }));

app.post('/api/analyze', requireSession, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(503).json({ error: 'Server AI key is not configured' });
  try {
    const parts = Array.isArray(req.body?.parts) ? req.body.parts : [];
    if (!parts.length) return res.status(400).json({ error: 'No analysis content supplied' });
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts }], generationConfig: { responseMimeType: 'application/json' } })
    });
    const data = await response.json();
    if (!response.ok || data.error) return res.status(response.status || 502).json({ error: data.error?.message || 'AI request failed' });
    res.json(data);
  } catch (error) { res.status(502).json({ error: error.message }); }
});

app.post('/api/auth/logout', (req, res) => {
  const token = readCookie(req, COOKIE_NAME);
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
  res.json({ ok: true });
});

app.get('/api/secure-config-check', requireSession, (_req, res) => res.json({ ok: true, message: 'Authenticated server endpoint is working. Secrets remain server-side.' }));

app.use(express.static('.', { index: false }));
app.listen(PORT, () => console.log(`DialysisSafe listening on ${ORIGIN}`));

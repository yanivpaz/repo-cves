/**
 * OWASP Top 10 Security Vulnerabilities Examples
 * This file demonstrates common security vulnerabilities for educational purposes
 * WARNING: These are intentional vulnerabilities for code scanning analysis
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import * as crypto from 'crypto';

// ============================================================================
// 1. BROKEN ACCESS CONTROL - Insecure Direct Object References (IDOR)
// ============================================================================

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
}

// Vulnerable: User can access any user's data by changing ID in URL
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id; // No validation
  const user = getUserFromDatabase(userId);
  res.json(user); // Returns sensitive data without authorization check
});

// Vulnerable: Admin function without proper authorization
function deleteUser(userId: string, requestUser: User) {
  // Missing authorization check - any authenticated user can delete anyone
  const query = `DELETE FROM users WHERE id = '${userId}'`;
  executeQuery(query);
  return { success: true };
}

// ============================================================================
// 2. CRYPTOGRAPHIC FAILURES - Insecure Crypto & Weak Hashing
// ============================================================================

// Vulnerable: Using hardcoded encryption key
const HARDCODED_KEY = 'secretkey123';

function encryptPassword(password: string): string {
  // Vulnerable: Using weak cipher
  const cipher = crypto.createCipher('aes-256-cbc', HARDCODED_KEY);
  let encrypted = cipher.update(password, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Vulnerable: Storing passwords with weak hashing
function storePassword(password: string): string {
  // MD5 is cryptographically broken
  return crypto.createHash('md5').update(password).digest('hex');
}

// Vulnerable: Storing sensitive data in plaintext
function storeSensitiveData(creditCard: string, ssn: string) {
  fs.writeFileSync('user_data.txt', `CC: ${creditCard}, SSN: ${ssn}`);
}

// ============================================================================
// 3. INJECTION - SQL Injection & Command Injection
// ============================================================================

// Vulnerable: SQL Injection
function getUserByEmail(email: string): User {
  const query = `SELECT * FROM users WHERE email = '${email}'`;
  return executeQuery(query); // Direct string interpolation
}

// Vulnerable: SQL Injection with user input
app.post('/search', (req, res) => {
  const searchTerm = req.body.search;
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  const results = executeQuery(query);
  res.json(results);
});

// Vulnerable: OS Command Injection
app.post('/convert-image', (req, res) => {
  const filename = req.body.filename;
  const output = execSync(`convert ${filename} output.jpg`); // Command injection
  res.send(output);
});

// Vulnerable: Template Injection
function renderEmail(userName: string): string {
  const template = `Hello ${userName}, <% if(isAdmin) { %>Admin Panel<% } %>`;
  return eval(template); // Dangerous eval
}

// ============================================================================
// 4. INSECURE DESIGN - Authentication & Session Management Flaws
// ============================================================================

// Vulnerable: Weak password policy
function validatePassword(password: string): boolean {
  return password.length >= 1; // Insufficient validation
}

// Vulnerable: Session fixation vulnerability
app.get('/login', (req, res) => {
  const sessionId = req.query.sid; // Accepting session ID from user
  req.session.id = sessionId;
  res.send('Logged in');
});

// Vulnerable: No CSRF protection
app.post('/transfer-money', (req, res) => {
  const amount = req.body.amount;
  const to = req.body.to;
  transferMoney(amount, to); // No CSRF token validation
  res.send('Transfer successful');
});

// Vulnerable: Predictable password reset tokens
function generateResetToken(userId: string): string {
  return Math.floor(Math.random() * 1000000).toString(); // Weak random
}

// ============================================================================
// 5. SECURITY MISCONFIGURATION - Exposed Sensitive Data
// ============================================================================

// Vulnerable: Exposing sensitive data in response headers
app.use((req, res, next) => {
  res.set('X-Internal-API-Key', 'sk_live_secret123456789');
  res.set('Server', 'Apache/2.4.1'); // Reveals server version
  next();
});

// Vulnerable: Debug information exposed in production
app.use((err: any, req: any, res: any, next: any) => {
  res.json({
    error: err.message,
    stack: err.stack, // Stack trace exposed
    database: process.env.DATABASE_URL,
    apiKey: process.env.API_KEY,
  });
});

// Vulnerable: Using default credentials
const dbConfig = {
  host: 'localhost',
  user: 'admin', // Default username
  password: 'password', // Default password
};

// ============================================================================
// 6. VULNERABLE & OUTDATED COMPONENTS - Unpatched Dependencies
// ============================================================================

// These would come from package.json with vulnerable versions:
// - lodash: "4.17.15" (has known vulnerabilities)
// - express: "3.11.0" (outdated, security issues)
// - request: "*" (deprecated package)

import * as oldLodash from 'lodash'; // Vulnerable version

function processData(data: any) {
  return oldLodash.defaults(data, {});
}

// ============================================================================
// 7. IDENTIFICATION & AUTHENTICATION FAILURES - Weak Auth
// ============================================================================

// Vulnerable: Password stored in code
const ADMIN_PASSWORD = 'admin123';

function verifyAdmin(password: string): boolean {
  return password === ADMIN_PASSWORD;
}

// Vulnerable: No account lockout after failed attempts
let loginAttempts: { [key: string]: number } = {};

function authenticateUser(username: string, password: string): boolean {
  const user = findUserByUsername(username);
  if (!user || user.password !== hashPassword(password)) {
    loginAttempts[username] = (loginAttempts[username] || 0) + 1;
    return false; // No lockout mechanism
  }
  return true;
}

// Vulnerable: JWT token with no expiration
function generateJWT(userId: string): string {
  const payload = { userId, iat: Date.now() }; // No exp field
  return require('jsonwebtoken').sign(payload, 'weak-secret');
}

// ============================================================================
// 8. DATA INTEGRITY & VERIFICATION FAILURES - Insecure Deserialization
// ============================================================================

// Vulnerable: Deserialization of untrusted data
app.post('/import-data', (req, res) => {
  const data = req.body.data;
  const parsed = JSON.parse(data); // Could contain malicious code
  eval(parsed.code); // Remote code execution
  res.send('Data imported');
});

// Vulnerable: No integrity checking
function processUserFile(filePath: string) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  lines.forEach((line: string) => {
    const [key, value] = line.split('=');
    process.env[key] = value; // Setting env vars from file without validation
  });
}

// ============================================================================
// 9. LOGGING & MONITORING FAILURES - Insufficient Logging
// ============================================================================

// Vulnerable: No logging of security events
app.post('/api/sensitive-action', (req, res) => {
  const action = req.body.action;
  performSensitiveAction(action);
  // No audit log, no logging of who did what
  res.send('Action completed');
});

// Vulnerable: Sensitive data in logs
function handleLogin(email: string, password: string) {
  console.log(`User login attempt: ${email}:${password}`); // Password in logs
  const user = authenticateUser(email, password);
  return user;
}

// Vulnerable: Logs not monitored for security events
const logs: string[] = [];

function logEvent(event: string) {
  logs.push(event);
  // Logs are never reviewed or monitored
}

// ============================================================================
// 10. SERVER-SIDE REQUEST FORGERY (SSRF) - Unsafe HTTP Requests
// ============================================================================

// Vulnerable: SSRF vulnerability
app.post('/fetch-content', async (req, res) => {
  const url = req.body.url; // User-controlled URL
  const fetch = require('node-fetch');
  const response = await fetch(url); // No URL validation
  const content = await response.text();
  res.send(content);
});

// Vulnerable: No URL validation
async function fetchFromURL(userProvidedURL: string) {
  // Could allow access to internal URLs like http://localhost:8080
  // or http://169.254.169.254/latest/meta-data/ (AWS metadata)
  const response = await fetch(userProvidedURL);
  return response.json();
}

// ============================================================================
// ADDITIONAL COMMON VULNERABILITIES
// ============================================================================

// Cross-Site Scripting (XSS) - Reflected
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Results for: ${query}</h1>`); // User input directly in HTML
});

// XSS - Stored
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  storeInDatabase(comment); // No sanitization
  res.send('Comment saved');
});

// Path Traversal
app.get('/download/:file', (req, res) => {
  const file = req.params.file;
  res.download(`./uploads/${file}`); // Could be ../../etc/passwd
});

// Insecure Randomness
function generateSessionId(): string {
  return Math.random().toString(36).substring(7); // Weak randomness
}

// Missing Security Headers
app.use((req, res, next) => {
  // Missing: Content-Security-Policy, X-Frame-Options, etc.
  next();
});

// Helper functions (stubs for demonstration)
function getUserFromDatabase(id: string): User {
  return { id, name: '', email: '', role: '' };
}

function executeQuery(query: string): any {
  return null;
}

function transferMoney(amount: number, to: string): void {}

function findUserByUsername(username: string): User | null {
  return null;
}

function hashPassword(password: string): string {
  return '';
}

function performSensitiveAction(action: string): void {}

function storeInDatabase(data: any): void {}

// Express app stub
const app = {
  get: (path: string, handler: any) => {},
  post: (path: string, handler: any) => {},
  use: (handler: any) => {},
};

export { app };

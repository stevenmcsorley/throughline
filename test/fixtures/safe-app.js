// Negative fixture: idiomatic, safe versions of the patterns the scanner hunts.
// Findings here are false positives, so this file guards against rule over-reach.
const { execFile } = require('child_process');
const crypto = require('crypto');
const path = require('path');

const ALLOWED_HOSTS = new Set(['api.internal.example']);
const BASE_DIR = '/srv/uploads';

function getUser(db, req) {
  // Parameterized — not string interpolation.
  return db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
}

function ping(host, cb) {
  // Argument array — no shell.
  execFile('ping', ['-c', '1', host], cb);
}

function render(el, userInput) {
  // Text, not markup.
  el.textContent = userInput;
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readUpload(req) {
  const safe = path.resolve(BASE_DIR, path.basename(req.query.name));
  if (!safe.startsWith(BASE_DIR)) throw new Error('Path escape');
  return safe;
}

async function fetchInternal(rawUrl) {
  const url = new URL(rawUrl);
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('Blocked host');
  return fetch(url.toString());
}

const API_KEY = process.env.API_KEY;

module.exports = { getUser, ping, render, hash, readUpload, fetchInternal, API_KEY };

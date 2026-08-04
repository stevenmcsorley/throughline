import { Rule } from '../../types';

function scanPatterns(rule: Rule, filePath: string, content: string, lines: string[]) {
  const { applyPatternRule, buildVariableMap } = require('../../engine/pattern-engine');
  const varMap = buildVariableMap(lines);
  const findings: any[] = [];
  for (const p of rule.patterns || []) {
    findings.push(...applyPatternRule(rule, filePath, lines, p, varMap));
  }
  return findings;
}

export const insecureCryptoRule: Rule = {
  id: 'insecure-crypto',
  name: 'Insecure Cryptography',
  description: 'Use of weak/deprecated cryptographic algorithms, insecure random generation, or improper key management',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-327',
  owasp: 'A02:2021-Cryptographic Failures',
  mitreAttack: { tactic: 'TA0006', technique: 'T1555' },
  references: [
    'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
  ],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs', '.swift', '.kt', '.rs'],
  patterns: [
    { regex: /\b(?:md5|md4|MD5|MD4)\b(?=[\s(.]|$)/g, message: 'MD5/MD4 hash used — cryptographically broken', recommendation: 'Use SHA-256 or SHA-3 (SHA3-256) for general hashing. For passwords, use Argon2id, bcrypt, or scrypt.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\bsha1\b(?=[\s(.]|$)/gi, message: 'SHA1 is cryptographically broken — collision attacks are practical', recommendation: 'Use SHA-256 or stronger. SHA1 should not be used for security purposes.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\b(?:DES|3DES|TripleDES|DESede)\b/gi, message: 'DES/3DES is an obsolete cipher with 56-bit effective key', recommendation: 'Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\b(?:RC4|ARCFOUR|arcfour)\b/gi, message: 'RC4 stream cipher — completely broken, multiple practical attacks exist', recommendation: 'Use AES-256-GCM or ChaCha20-Poly1305 instead of RC4.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\bECB\b(?![a-z])/g, message: 'ECB mode reveals plaintext patterns — NEVER use for encryption', recommendation: 'Use authenticated encryption: AES-256-GCM or AES-256-CBC with HMAC-SHA256.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /Math\.random\s*\(\s*\)/g, message: 'Math.random() is NOT cryptographically secure — predictable output', recommendation: 'Use crypto.randomBytes() (Node.js), crypto.getRandomValues() (browser), or secrets module (Python).', confidence: 'high', falsePositiveRisk: 'medium' },
    { regex: /createCipher\s*\(/gi, message: 'crypto.createCipher() is deprecated — uses weak key derivation', recommendation: 'Use crypto.createCipheriv() with an explicit IV/Nonce and a proper key derivation function.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /createHash\s*\(\s*['"](?:md5|sha1|md4)['"]/gi, message: 'Weak hash algorithm in crypto.createHash call', recommendation: 'Use SHA-256: crypto.createHash("sha256"). For HMAC: crypto.createHmac("sha256", key).', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /hashlib\.(?:md5|sha1)\s*\(/gi, message: 'Python hashlib using weak hash (MD5/SHA1)', recommendation: 'Use hashlib.sha256() or hashlib.sha3_256().', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:\brandom\.(?:choice|randint|randrange|shuffle|sample|random|uniform)\s*\()/g, message: 'Python random module — not cryptographically secure', recommendation: 'Use secrets module: secrets.randbelow(), secrets.choice(), secrets.token_bytes(), etc.', confidence: 'high', falsePositiveRisk: 'medium' },
    { regex: /\b(?:md5|sha1)\s*\(/gi, message: 'PHP weak hash function (MD5/SHA1)', recommendation: 'Use password_hash() for passwords (bcrypt/Argon2). Use hash("sha256", ...) for general hashing.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1)['"]/gi, message: 'Java MessageDigest with weak hash', recommendation: 'Use MessageDigest.getInstance("SHA-256") or SHA3-256.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /Cipher\.getInstance\s*\(\s*['"][^'"]*(?:DES|RC4|ECB)[^'"]*['"]/gi, message: 'Java Cipher with weak algorithm or insecure mode', recommendation: 'Use Cipher.getInstance("AES/GCM/NoPadding") with proper key management.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\b(?:RC2|Blowfish|Camellia)\b/gi, message: 'Obsolete or non-standard cipher algorithm', recommendation: 'Use AES-256-GCM which is widely audited and supported.', confidence: 'medium', falsePositiveRisk: 'medium' },
    // SEED is a real Korean block cipher, but it was matched case-insensitively
    // and so fired on the ordinary word "seed" — `from .seed import seed`,
    // `def seed(db)`, even `seed = random.SystemRandom()`, which is the *secure*
    // RNG. Case-sensitive, and only in a file that does cryptography at all.
    {
      regex: /\bSEED\b/g,
      requiresFileContext: /\b(?:crypto|Crypto|cipher|Cipher|encrypt|decrypt|OpenSSL)\b/,
      message: 'Obsolete or non-standard cipher algorithm (SEED)',
      recommendation: 'Use AES-256-GCM which is widely audited and supported.',
      confidence: 'medium',
      falsePositiveRisk: 'medium',
    },
    { regex: /(?:iv|IV|salt|Salt|nonce)\s*[:=]\s*['"][a-zA-Z0-9+\/=]{8,}['"]/g, message: 'Hardcoded IV, nonce, or salt — each encryption should use a fresh random value', recommendation: 'Generate a new random IV/nonce for each encryption. Store it alongside the ciphertext (it does not need to be secret).', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:pbkdf2|PBKDF2|bcrypt|scrypt|argon2)[^(]*\(\s*[^,]*,[^,]*,\s*(?:[1-9]\d{0,3})\s*[,)]/g, message: 'Low key derivation iteration count — vulnerable to brute force', recommendation: 'Use minimums: PBKDF2-HMAC-SHA256: 310,000+, bcrypt: cost 12+, scrypt: N=2^17+, Argon2id: t=3, m=64MB.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const hardcodedSecretsRule: Rule = {
  id: 'hardcoded-secrets',
  name: 'Hardcoded Secrets',
  description: 'API keys, passwords, tokens, and cryptographic material embedded in source code',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-798',
  owasp: 'A02:2021-Cryptographic Failures',
  mitreAttack: { tactic: 'TA0006', technique: 'T1552' },
  references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  extensions: ['.js', '.ts', '.py', '.java', '.php', '.rb', '.go', '.cs', '.json', '.yml', '.yaml', '.xml',
    '.env', '.cfg', '.conf', '.ini', '.toml', '.properties', '.tf', '.tfvars', '.kt', '.swift', '.rs', '.dart'],
  patterns: [
    // `pass` matters for PHP and Ruby, where `$pass = "..."` is the common
    // idiom. Longer alternatives are listed first so `password` is matched as
    // itself rather than as `pass` followed by a failed `=`.
    //
    // `credentials` was here briefly and had to come out: `fetch(url, {
    // credentials: "same-origin" })` is a standard request option, not a secret,
    // and it fired on ordinary frontend code.
    // The value must be a literal. `password = '${req.body.password}'` inside a
    // query string is a SQL injection — already reported as one — not a
    // hardcoded credential; 219 of Juice Shop's 238 secret findings were this
    // shape. Placeholders (?, $1, :name) are likewise not secrets.
    { regex: /(?:password|passwd|secret|pwd|pass)\s*[:=]\s*['"](?!\s*(?:\$\{|\$\d|:\w|\?|%s|%\()) *[^'"$?%]{3,}['"]\s*[,;\n)]?/gi, message: 'Hardcoded password or secret in source', recommendation: 'Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler).', confidence: 'high', falsePositiveRisk: 'medium', matchInStrings: true },
    { regex: /AKIA[0-9A-Z]{16}/g, message: 'Hardcoded AWS Access Key ID', recommendation: 'Use IAM roles, instance profiles, or environment variables. Never commit AWS keys.', confidence: 'certain', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /(?:ghp_|github_pat_)[A-Za-z0-9_]{36,}/g, message: 'Hardcoded GitHub Personal Access Token', recommendation: 'Use GitHub Actions secrets or environment variables. Rotate this token immediately.', confidence: 'certain', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /gho_[A-Za-z0-9]{36,}/g, message: 'Hardcoded GitHub OAuth Token', recommendation: 'Rotate immediately. Use OAuth Apps with proper secret storage.', confidence: 'certain', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /-----(?:BEGIN|START)\s*(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)\s*PRIVATE\s*KEY-----/g, message: 'Private key embedded in source code — severe credential leak', recommendation: 'Store private keys in hardware security modules (HSMs), key management services, or encrypted vaults. NEVER in source code.', confidence: 'certain', falsePositiveRisk: 'low', matchInStrings: true },
    // The password segment must be a literal. `postgres://user:${DB_PASSWORD}@host`
    // is the *correct* form — the credential is injected at runtime — and
    // reporting it as a hardcoded secret is exactly the noise that gets a
    // scanner switched off. Excludes ${...}, $VAR, %VAR%, {{...}} and <...>.
    { regex: /(?:mongodb|mysql|postgres(?:ql)?|redis|jdbc|sqlserver|mssql):\/\/[^:@\s]+:(?!\$|%|\{\{|<)[^@\s${}%<>]+@/gi, message: 'Database connection string with embedded credentials', recommendation: 'Use environment variables for credentials. Example: DATABASE_URL env var parsed at runtime.', confidence: 'high', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /(?:sk_live_|pk_live_|rk_live_)[A-Za-z0-9]{24,}/g, message: 'Hardcoded Stripe live API key', recommendation: 'Use Stripe restricted API keys with minimal permissions. Use environment variables.', confidence: 'certain', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /xox[bpras]-[A-Za-z0-9-]{10,}/g, message: 'Hardcoded Slack API token', recommendation: 'Rotate this token. Use Slack app credentials stored in environment variables.', confidence: 'certain', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /AIza[0-9A-Za-z\-_]{35}/g, message: 'Hardcoded Google API key', recommendation: 'Restrict API key to specific APIs, IPs, and referrers in Google Cloud Console. Use env vars.', confidence: 'high', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /SK[0-9a-fA-F]{32}/g, message: 'Hardcoded Twilio API key', recommendation: 'Store in environment variables. Use Twilio API key restrictions.', confidence: 'certain', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /(?:api[_-]?key|apikey|api[_-]?secret|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-.]{16,}['"]/gi, message: 'Hardcoded API key or client secret', recommendation: 'Move to environment variables or secrets manager. Rotate if committed to VCS.', confidence: 'high', falsePositiveRisk: 'medium', matchInStrings: true },
    { regex: /(?:jwt[_-]?secret|jwt[_-]?key|token[_-]?secret|session[_-]?secret|encryption[_-]?key)\s*[:=]\s*['"][^'"]{6,}['"]/gi, message: 'Hardcoded cryptographic key or JWT secret', recommendation: 'Generate strong random secrets (256+ bits). Store in env vars or KMS. Rotate on compromise.', confidence: 'high', falsePositiveRisk: 'low', matchInStrings: true },
    { regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, message: 'JWT token in source code — potential leaked credential', recommendation: 'JWTs in source code are typically test tokens. Verify this is not a production token. Remove and use env vars.', confidence: 'medium', falsePositiveRisk: 'high', matchInStrings: true },
    { regex: /Authorization\s*[:=]\s*['"]\s*(?:Bearer|Basic|Digest)\s+\S{8,}['"]/gi, message: 'Hardcoded authorization header — potential credential leak', recommendation: 'Remove hardcoded auth tokens. Use environment variables or credential management.', confidence: 'medium', falsePositiveRisk: 'medium', matchInStrings: true },
  ],
  scan(filePath: string, content: string, lines: string[]) {
    const { applyPatternRule, buildVariableMap } = require('../../engine/pattern-engine');
    const varMap = buildVariableMap(lines);
    const findings: any[] = [];
    for (const p of this.patterns || []) {
      findings.push(...applyPatternRule(this, filePath, lines, p, varMap));
    }
    // Filter out obvious dummy/test values
    return findings.filter(f => {
      const s = f.snippet.toLowerCase();
      return !(s.includes('your_') || s.includes('example') || s.includes('test_') ||
               s.includes('placeholder') || s.includes('xxxx') || s.includes('changeme') ||
               s.includes('todo') || s.includes('your-') || s.includes('dummy') ||
               s.includes('not-a-real') || s.includes('sample'));
    });
  }
};

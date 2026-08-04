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

export const insecureJwtRule: Rule = {
  id: 'insecure-jwt',
  name: 'Insecure JWT Handling',
  description: 'JWT verification bypass, weak secrets, missing algorithm validation',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp: 'A07:2021-Auth Failures',
  mitreAttack: { tactic: 'TA0005', technique: 'T1557' },
  references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /algorithms\s*:\s*\[[^\]]*['"]none['"]/gi, message: 'JWT verification allows "none" algorithm — signature bypass', recommendation: 'Explicitly list allowed algorithms. Never allow "none". Prefer RS256 or ES256.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /jwt\.decode\s*\(\s*(?!.*\{.*algorithms|\{.*verify)/gi, message: 'jwt.decode() used instead of jwt.verify() — no signature check', recommendation: 'Always use jwt.verify(token, secret, { algorithms: ["RS256"] }) to validate signatures.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /jwtSecret\s*=\s*['"][^'"]{1,15}['"]|jwt\.sign\s*\([^,]+,['"]\s*[^'"]{1,15}\s*['"]/gi, message: 'JWT secret too short or appears to be a default value', recommendation: 'Use secrets of at least 256 bits (32 bytes) generated from a CSPRNG. For HMAC: 32+ byte random string.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /jwt\.sign\s*\(\s*\{[^}]*\}\s*,\s*['"]secret['"]/gi, message: 'JWT signed with literal "secret" string — critically weak', recommendation: 'Use a strong, randomly generated secret stored in environment variables. Minimum 32 bytes of randomness.', confidence: 'certain', falsePositiveRisk: 'low' },
    { regex: /(?:ignoreExpiration|ignoreNotBefore)\s*:\s*true/gi, message: 'JWT expiration/not-before check disabled', recommendation: 'Always validate exp, nbf, and iat claims. Never set ignoreExpiration: true in production.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /jwt\.(?:verify|sign)\s*\([^)]*HS256/gi, message: 'JWT using HS256 — symmetric algorithm, secret must be kept private to signer and verifier', recommendation: 'Prefer asymmetric algorithms (RS256, ES256) so the public key can be shared safely.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const csrfRule: Rule = {
  id: 'csrf',
  name: 'Cross-Site Request Forgery (CSRF)',
  description: 'State-changing endpoints without CSRF protection',
  severity: 'medium',
  confidence: 'medium',
  cwe: 'CWE-352',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0001', technique: 'T1189' },
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    {
      regex: /app\.(?:post|put|delete|patch)\s*\([^)]*\)\s*=>?\s*(?!.*csrf|.*xsrf|.*_csrf|.*X-CSRF)/gi,
      // CSRF requires *ambient* credentials — a cookie the browser attaches
      // automatically. An API authenticated by a bearer token, an API key, or a
      // signature is not exploitable this way, because the attacker's page
      // cannot make the victim's browser attach the token. Flagging every
      // token-authenticated POST route is noise.
      requiresFileContext: /\bcookie|\bsession\b/i,
      neutralizedBy: /\bBearer\b|\bauthorization\b|\bapi[-_]?key\b/i,
      message: 'State-changing route without visible CSRF protection',
      recommendation: 'Implement CSRF tokens, SameSite cookies, or custom request header validation.',
      confidence: 'low',
      falsePositiveRisk: 'high',
    },
    { regex: /csrf\s*:\s*false|crsf\s*:\s*false|disable_csrf/gi, message: 'CSRF protection explicitly disabled', recommendation: 'Only disable CSRF for specific, non-state-changing endpoints. Re-enable for all others.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const idorRule: Rule = {
  id: 'idor',
  name: 'Insecure Direct Object Reference (IDOR)',
  description: 'Resource access using predictable identifiers without ownership verification',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-639',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0005', technique: 'T1087' },
  references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /\.(?:findById|findByPk|findByPk|findOne)\s*\(\s*(?:req\.(?:params|query|body)\.(?:id|userId|\w*[Ii]d))|request\.(?:getParameter|getQueryString)/gi, message: 'Database lookup by user-supplied ID without ownership check', recommendation: 'Verify the requesting user owns the requested resource. Compare resource.ownerId against session userId.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /\/:(?:id|userId|accountId|orderId|docId|fileId|recordId)\/?(?:delete|remove|update|edit)/gi, message: 'Route with ID param performing sensitive operation — verify ownership', recommendation: 'Add middleware to verify that the authenticated user has permission to access/modify this resource.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const massAssignmentRule: Rule = {
  id: 'mass-assignment',
  name: 'Mass Assignment',
  description: 'Allowing users to set arbitrary object/record fields — privilege escalation risk',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-915',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0004', technique: 'T1548' },
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /Object\.assign\s*\(\s*(?:\w+)\s*,\s*req\.body\s*\)/gi, message: 'Object.assign with entire request body — mass assignment risk', recommendation: 'Use explicit field allowlists. Example: const { name, email } = req.body; Object.assign(user, { name, email });', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:\.set|\.update|\.create|\.save|\.insert)\s*\(\s*req\.body/gi, message: 'Database create/update with raw request body — mass assignment', recommendation: 'Whitelist allowed fields. Example: User.create({ name: req.body.name, email: req.body.email })', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:update|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate)\s*\(\s*[^,]*,\s*req\.body/gi, message: 'MongoDB/Mongoose update with raw request body', recommendation: 'Use Mongoose schema options: { strict: true }, or explicitly whitelist updatable fields.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:ActiveRecord|Sequelize|Laravel|Django|Rails\.update|\.update_attributes|\.update_all)\s*\([^)]*\b(?:params|request\.|req\.)/gi, message: 'ORM mass update with request params — potential mass assignment', recommendation: 'Use strong parameters / whitelist approach. Define permitted fields explicitly.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const missingAuthRule: Rule = {
  id: 'missing-authz',
  name: 'Missing Authorization',
  description: 'Sensitive operations without authentication or authorization checks',
  severity: 'medium',
  confidence: 'medium',
  cwe: 'CWE-862',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0005', technique: 'T1548' },
  references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /app\.(?:get|post|put|delete|patch)\s*\(\s*['"][^'"]*(?:admin|delete|manage|settings|config|backup)[^'"]*['"]/gi, message: 'Admin/sensitive route — verify auth middleware applied', recommendation: 'Ensure authentication and role-based authorization middleware is applied to all sensitive routes.', confidence: 'low', falsePositiveRisk: 'high' },
    { regex: /@app\.route\s*\(\s*['"][^'"]*(?:admin|delete|manage|settings)[^'"]*['"]/gi, message: 'Flask sensitive route — verify @login_required decorator', recommendation: 'Apply @login_required and role-check decorators to all sensitive endpoints.', confidence: 'low', falsePositiveRisk: 'high' },
    { regex: /(?:delete|drop|truncate)\s+.*\b(?:users|accounts|orders|payments|transactions|sessions)\b/gi, message: 'Destructive database operation — verify authorization context', recommendation: 'Ensure this operation is behind proper authorization with audit logging.', confidence: 'low', falsePositiveRisk: 'high' },
    { regex: /auth\s*:\s*false|authentication\s*:\s*'none'|security\s*:\s*\[\s*\]|authorization\s*:\s*'none'/gi, message: 'Authentication explicitly disabled on endpoint', recommendation: 'Remove auth:false from production endpoints. Every non-public endpoint should require authentication.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

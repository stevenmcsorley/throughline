import { Rule, Finding } from '../../types';

function scanPatterns(rule: Rule, filePath: string, content: string, lines: string[]) {
  const { applyPatternRule, buildVariableMap } = require('../../engine/pattern-engine');
  const varMap = buildVariableMap(lines);
  const findings: any[] = [];
  for (const p of rule.patterns || []) {
    findings.push(...applyPatternRule(rule, filePath, lines, p, varMap));
  }
  return findings;
}

// ─── XSS ───
export const xssRule: Rule = {
  id: 'xss',
  name: 'Cross-Site Scripting (XSS)',
  description: 'User input rendered in HTML/JS context without proper escaping or sanitization',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-79',
  owasp: 'A03:2021-Injection',
  mitreAttack: { tactic: 'TA0001', technique: 'T1189' },
  references: [
    'https://owasp.org/www-community/attacks/xss/',
    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
  ],
  extensions: ['.js', '.ts', '.jsx', '.tsx', '.py', '.php', '.rb', '.java', '.cs', '.html', '.vue', '.svelte', '.ejs', '.hbs', '.pug', '.erb'],
  patterns: [
    { regex: /dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:/g, message: 'React dangerouslySetInnerHTML — bypasses XSS protections', recommendation: 'Use DOMPurify.sanitize() before setting HTML. Avoid dangerouslySetInnerHTML when possible.', fixExample: '// Instead of: <div dangerouslySetInnerHTML={{ __html: userContent }} />\n// Use: <div>{DOMPurify.sanitize(userContent)}</div> or better yet, avoid raw HTML', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\.innerHTML\s*=\s*(?!['"][^'"]*$)/g, message: 'innerHTML with dynamic content — XSS vector', recommendation: 'Use textContent or innerText. If HTML is needed, sanitize with DOMPurify first.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /document\.write\s*\(\s*(?!["'][^"']*["']\s*$)/g, message: 'document.write with dynamic content — DOM XSS', recommendation: 'Use DOM manipulation methods (createElement, appendChild) or set textContent instead.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /eval\s*\(\s*(?:.*innerHTML|.*outerHTML|.*document\.)/gi, message: 'eval with DOM content — code injection via XSS', recommendation: 'Never use eval(). Use JSON.parse() for data or Function constructor with caution.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /echo\s+(?!htmlspecialchars|htmlentities|escape)\$_(?:GET|POST|REQUEST|SERVER|COOKIE)/gi, message: 'PHP echo of raw user input — reflected XSS', recommendation: 'Always use htmlspecialchars($input, ENT_QUOTES, "UTF-8") when outputting to HTML context.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\{\{\s*(?!.*\|[\s]*e[\s}]).*\b(?:request\.|params\.|form\.|query\.|req\.)/gi, message: 'Twig/Jinja2 variable without e(filter) — potential XSS', recommendation: 'Use {{ variable|e }} or enable auto-escaping in the template engine configuration.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /location\s*\.\s*(?:href|search|hash|pathname)\s*=\s*(?!["'][^"']*$)/gi, message: 'location redirect with dynamic content — DOM XSS (javascript: URI)', recommendation: 'Validate URL starts with http:// or https://. Block javascript: and data: URI schemes.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\$\([^)]*\)\s*\.html\s*\(\s*(?!["'][^"']*$)/g, message: 'jQuery .html() with dynamic content — XSS risk', recommendation: 'Use .text() instead. If HTML is needed, use DOMPurify or similar sanitization.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:v-html|ng-bind-html|\[innerHTML\])\s*=/gi, message: 'Framework HTML binding (v-html/ng-bind-html/[innerHTML]) — XSS risk', recommendation: 'Avoid raw HTML bindings. Use text bindings. If essential, sanitize with a trusted library.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(<script[^>]*>.*\$\{|<script[^>]*>.*`.*\$\{)/g, message: 'Template literal in script tag — potential stored/reflected XSS', recommendation: 'Never interpolate user data directly into script tags. Use data attributes and JavaScript to read them.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

// ─── SSRF ───
export const ssrfRule: Rule = {
  id: 'ssrf',
  name: 'Server-Side Request Forgery (SSRF)',
  description: 'HTTP requests to URLs controlled by user input — can access internal services',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-918',
  owasp: 'A10:2021-SSRF',
  mitreAttack: { tactic: 'TA0001', technique: 'T1190' },
  references: ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /(?:fetch|axios|got|request|superagent|needle|node-fetch)\s*\([^)]*\b(?:req\.(?:query|params|body)|request\.(?:query|params|body))/gi, message: 'HTTP request to user-controlled URL — SSRF risk', recommendation: 'Validate URLs against an allowlist. Block internal IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16).', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /https?\.(?:get|request|createServer|Agent)\s*\([^)]*\b(?:req\.|request\.|params|query)/gi, message: 'Node.js http.get/request with user-controlled URL — SSRF', recommendation: 'Parse and validate the hostname before making requests. Use dns.resolve() to check for internal IPs.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:requests\.(?:get|post|put|delete|head|patch|request)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\([^)]*\b(?:request\.(?:args|form|data|json))/gi, message: 'Python HTTP request with user-controlled URL — SSRF', recommendation: 'Validate URLs with urlparse. Reject internal/private hosts. Use a URL allowlist.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /curl_setopt\s*\([^,]*,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)/gi, message: 'PHP cURL URL from user input — SSRF', recommendation: 'Validate URL against allowlist. Use filter_var($url, FILTER_VALIDATE_URL) and check the host before curl_exec.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:HttpURLConnection|HttpClient|RestTemplate|WebClient|OkHttpClient|Retrofit)[^(]*.*\b(?:request\.|req\.|getParameter)/gi, message: 'Java HTTP client with user-controlled URL', recommendation: 'Validate URL hostname. Block internal addresses. Use an HTTP client configured with SSRF protections.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:Net::HTTP|open|URI\.parse|RestClient|HTTParty|Faraday)[^(]*\([^)]*\bparams\[/g, message: 'Ruby HTTP client with user-controlled URL', recommendation: 'Validate URLs with URI.parse. Check host against allowlist. Block internal IP ranges.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

// ─── Open Redirect ───
export const openRedirectRule: Rule = {
  id: 'open-redirect',
  name: 'Open Redirect',
  description: 'Redirect to user-controlled URL without validation — phishing vector',
  severity: 'medium',
  confidence: 'high',
  cwe: 'CWE-601',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0001', technique: 'T1566' },
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\.\w+|request\.(?:query|params|body)\.\w+)/gi, message: 'Express redirect to user-controlled URL — open redirect', recommendation: 'Validate against a URL allowlist. Only allow relative paths (e.g., /dashboard) or known trusted domains.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /header\s*\(\s*['"]Location:\s*[^'"]*(?:\$_|\.\s*\$)/gi, message: 'PHP header redirect with user-controlled destination', recommendation: 'Use a lookup table: redirect tokens → URLs. Never pass raw user input to Location header.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /redirect\s*\(\s*(?:request\.(?:args|form|values)\.(?:get|\[))/gi, message: 'Flask/Django redirect to user-controlled URL', recommendation: 'Use django.utils.http.url_has_allowed_host_and_scheme(). Flask: validate next parameter against allowlist.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /sendRedirect\s*\([^)]*\b(?:request\.|req\.|getParameter)/gi, message: 'Java sendRedirect with user input', recommendation: 'Validate that the redirect URL starts with "/" or matches an allowed domain list.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /redirect_to\s+params\[/g, message: 'Rails redirect_to with raw params — open redirect', recommendation: 'Use redirect_back with allowed fallback. Validate URLs with allowed_hosts configuration.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

// ─── CORS Misconfiguration ───
export const corsMisconfigRule: Rule = {
  id: 'cors-misconfig',
  name: 'CORS Misconfiguration',
  description: 'Overly permissive CORS settings allowing cross-origin access from any origin',
  severity: 'medium',
  confidence: 'high',
  cwe: 'CWE-942',
  owasp: 'A05:2021-Security Misconfiguration',
  references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs', '.conf', '.cfg', '.nginx', '.htaccess'],
  patterns: [
    { regex: /Access-Control-Allow-Origin\s*:\s*\*/gi, message: 'CORS allows any origin — credentials cannot be sent securely', recommendation: 'Restrict to specific origins. Never use * with Access-Control-Allow-Credentials: true.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /origin\s*:\s*['"]\*['"]/gi, message: 'CORS origin set to wildcard — any domain can access', recommendation: 'Use an explicit list of allowed origins. Avoid reflecting the Origin header without validation.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /credentials\s*:\s*true.*origin\s*:\s*['"]\*['"]|origin\s*:\s*['"]\*['"].*credentials\s*:\s*true/gi, message: 'CORS with both wildcard origin and credentials — browsers will reject this', recommendation: 'Specify explicit origin when using credentials. This combination is invalid per spec.', confidence: 'medium', falsePositiveRisk: 'low' },
    { regex: /Access-Control-Allow-Origin\s*:\s*\$|Origin\s*:\s*.*\$|origin\s*:\s*.*req\./gi, message: 'CORS origin reflected from request — accepts any origin de facto', recommendation: 'Validate the Origin header against an allowlist. Do not blindly reflect it.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

// ─── Clickjacking ───
export const clickjackingRule: Rule = {
  id: 'clickjacking',
  name: 'Missing Clickjacking Protection',
  description: 'No X-Frame-Options or CSP frame-ancestors header — UI redress attack risk',
  severity: 'low',
  confidence: 'medium',
  cwe: 'CWE-1021',
  owasp: 'A05:2021-Security Misconfiguration',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs', '.conf', '.nginx'],
  patterns: [],

  /**
   * Reports the *absence* of frame protection, which is what the rule name
   * claims and what is actually a risk.
   *
   * It previously did the opposite: one pattern matched `X-Frame-Options: ...`
   * and another matched `frame-ancestors 'none'`, emitting them as findings with
   * messages like "good practice". A correctly hardened nginx config produced a
   * security finding for being hardened — inflating counts, tripping CI gates,
   * and training people to ignore the report. Both patterns also carried
   * `confidence: 'info'`, which is not a valid confidence value and made them
   * vanish under any `--confidence` threshold.
   */
  scan(filePath: string, content: string, lines: string[]): Finding[] {
    // Only meaningful where response headers are actually configured.
    const setsSecurityHeaders =
      /(?:add_header|setHeader|set_header|Header\s+set|helmet\(|response\.headers|res\.set)\s*\(?\s*['"]?(?:Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|Referrer-Policy|X-Frame-Options)/i;
    if (!setsSecurityHeaders.test(content)) return [];

    const hasXFrameOptions = /X-Frame-Options/i.test(content);
    const hasFrameAncestors = /frame-ancestors/i.test(content);
    if (hasXFrameOptions || hasFrameAncestors) return [];

    // Point at the first security header so the finding lands somewhere useful.
    const anchor = lines.findIndex(l => setsSecurityHeaders.test(l));
    const line = anchor >= 0 ? anchor + 1 : 1;

    return [{
      ruleId: this.id,
      title: this.name,
      severity: this.severity,
      confidence: 'medium',
      message: 'Security headers are configured here, but neither X-Frame-Options nor CSP frame-ancestors is set — the page can be framed for UI redress attacks',
      file: filePath,
      line,
      column: 1,
      snippet: (lines[line - 1] || '').trim().slice(0, 150),
      recommendation: "Add `frame-ancestors 'none'` to the Content-Security-Policy (or X-Frame-Options: DENY) unless the page is meant to be embedded.",
      cwe: this.cwe,
      owasp: this.owasp,
      references: [...this.references],
      falsePositiveRisk: 'medium',
    }];
  }
};

// ─── Cache Poisoning ───
export const cachePoisoningRule: Rule = {
  id: 'cache-poisoning',
  name: 'Web Cache Poisoning',
  description: 'Unkeyed headers or parameters that could allow cache poisoning attacks',
  severity: 'medium',
  confidence: 'low',
  cwe: 'CWE-444',
  owasp: 'A04:2021-Insecure Design',
  references: ['https://portswigger.net/research/practical-web-cache-poisoning'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /X-Forwarded-Host|X-Forwarded-Scheme|X-Original-URL|X-Rewrite-URL|X-HTTP-Method-Override/gi, message: 'Unkeyed header processed — potential cache poisoning vector', recommendation: 'Disable processing of unkeyed headers in caching layer. Use Vary header appropriately.', confidence: 'low', falsePositiveRisk: 'high' },
    { regex: /req\.(?:headers|get)\(?['"](?:x-[\w-]+|forwarded|via)/gi, message: 'Request header processing — review for cache poisoning if reflected in response', recommendation: 'Avoid reflecting unvalidated request headers in cached responses.', confidence: 'low', falsePositiveRisk: 'high' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

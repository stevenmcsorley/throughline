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

// ─── Server-Side Template Injection ───
export const sstiRule: Rule = {
  id: 'ssti',
  name: 'Server-Side Template Injection (SSTI)',
  description: 'User input rendered in server-side templates without sanitization — can lead to RCE',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-94',
  owasp: 'A03:2021-Injection',
  mitreAttack: { tactic: 'TA0002', technique: 'T1059' },
  references: ['https://portswigger.net/web-security/server-side-template-injection'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /res\.render\s*\([^)]*\b(?:req\.(?:query|params|body)|request\.(?:query|params|body))/gi, message: 'Express template render with user input — SSTI risk', recommendation: 'Never pass raw user input as template data without sanitization. Use strict context escaping.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /render_template_string?\s*\([^)]*\b(?:request\.(?:args|form|values|data))/gi, message: 'Flask render_template_string with user input — SSTI leading to RCE', recommendation: 'Use render_template() with static template files. Never render user input as template code.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:Jinja2|jinja2)\.(?:Template|Environment)\.(?:from_string|compile)\s*\(/gi, message: 'Jinja2 template compiled from string — potential SSTI', recommendation: 'Only compile templates from trusted sources. Never include user input in template source.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /(?:twig|smarty|blade)\s*->\s*(?:render|display|fetch)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)/gi, message: 'PHP template rendered with user input — SSTI risk', recommendation: 'Sanitize all template variables. Do not allow users to control template paths or inline template code.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /new\s+(?:PebbleEngine|VelocityEngine|MustacheFactory|Handlebars|Thymeleaf)[^(]*\.(?:compile|render|process)\s*\(/gi, message: 'Java template engine processing user input — verify template source', recommendation: 'Ensure template sources are loaded from trusted classpath resources, not user input.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /text\/template.*Parse\s*\([^)]*\b(?:r\.|req\.|c\.)/gi, message: 'Go template parsed with user input — potential SSTI', recommendation: 'Only parse templates from embedded filesystems or trusted sources. Never from user input.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /ejs\.render\s*\([^)]*\b(?:req\.|request\.)/gi, message: 'EJS template rendered with user input — SSTI risk', recommendation: 'Use ejs.renderFile() with static template files. Avoid ejs.render() with user-controlled strings.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

// ─── LDAP Injection ───
export const ldapInjectionRule: Rule = {
  id: 'ldap-injection',
  name: 'LDAP Injection',
  description: 'User input used in LDAP queries without proper escaping',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-90',
  owasp: 'A03:2021-Injection',
  mitreAttack: { tactic: 'TA0006', technique: 'T1552' },
  references: ['https://owasp.org/www-community/attacks/LDAP_Injection'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /(?:ldap|LDAP|Ldap)(?:Client|Connection)?[^(]*\.(?:search|bind|authenticate|compare|modify)\s*\([^)]*\b(?:req\.|request\.|params|query|getParameter)/gi, message: 'LDAP operation with user-controlled filter — injection risk', recommendation: 'Escape LDAP filter special characters: * ( ) \\ NUL. Use parameterized LDAP queries or a safe LDAP library.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /ldap\.(?:search|search_s|search_ext|search_ext_s)\s*\([^)]*\brequest\./gi, message: 'Python LDAP search with request data — injection risk', recommendation: 'Use ldap.filter.escape_filter_chars() on all user input before LDAP operations.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /ldap_search\s*\([^)]*\$_(?:GET|POST|REQUEST)/gi, message: 'PHP LDAP search with user input — injection risk', recommendation: 'Use ldap_escape() with LDAP_ESCAPE_FILTER on all user input.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

// ─── GraphQL Injection ───
export const graphqlInjectionRule: Rule = {
  id: 'graphql-injection',
  name: 'GraphQL Injection & Abuse',
  description: 'GraphQL queries constructed with user input, missing depth limits, or introspection enabled',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-89',
  owasp: 'A03:2021-Injection',
  references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
  extensions: ['.js', '.ts', '.py', '.java', '.go', '.cs'],
  patterns: [
    { regex: /graphql\s*\(\s*(?:req\.body|req\.query|request\.body).*query/gi, message: 'GraphQL query from raw user input — potential injection or abuse', recommendation: 'Validate queries against an allowlist. Use persisted queries. Set query depth and complexity limits.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /introspection\s*:\s*true/i, message: 'GraphQL introspection enabled in production — information disclosure', recommendation: 'Disable introspection in production environments.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /graphql-upload|graphqlUploadExpress|graphqlUploadKoa/gi, message: 'GraphQL file upload — verify file size limits and type validation', recommendation: 'Set strict file size limits. Validate file types server-side. Scan uploads for malware.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /maxDepth\s*:\s*\d{2,}/g, requiresFileContext: /\bgraphql|apollo|typeDefs|buildSchema|makeExecutableSchema\b/i, message: 'GraphQL query depth limit — verify it is sufficiently low (recommended: 5-7)', recommendation: 'Set query depth limit to 5-7. Also set query complexity/cost limits to prevent DoS.', confidence: 'low', falsePositiveRisk: 'high' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

// ─── HTTP Parameter Pollution ───
export const httpParamPollutionRule: Rule = {
  id: 'http-parameter-pollution',
  name: 'HTTP Parameter Pollution (HPP)',
  description: 'Multiple parameters with the same name — can bypass security controls',
  severity: 'medium',
  confidence: 'medium',
  cwe: 'CWE-235',
  owasp: 'A03:2021-Injection',
  references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /req\.query\s*\[\s*['"]\w+['"]\s*\]/g, message: 'Single query parameter access — HPP: duplicate params ignored', recommendation: 'Use req.query.paramName with array awareness, or validate parameter count. Express: use qs library with arrayLimit.', confidence: 'low', falsePositiveRisk: 'high' },
    { regex: /req\.(?:query|params|body)(?!\.\w+\b)/g, message: 'Accessing entire query/params/body object — review for HPP handling', recommendation: 'Access specific validated fields. Consider using schema validation libraries (joi, zod, yup).', confidence: 'low', falsePositiveRisk: 'high' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

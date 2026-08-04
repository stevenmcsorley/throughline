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

export const commandInjectionRule: Rule = {
  id: 'command-injection',
  name: 'Command Injection',
  description: 'Shell command construction with unsanitized user input',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-78',
  owasp: 'A03:2021-Injection',
  mitreAttack: { tactic: 'TA0002', technique: 'T1059' },
  references: [
    'https://owasp.org/www-community/attacks/Command_Injection',
    'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
  ],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs', '.swift', '.kt', '.pl'],
  patterns: [
    {
      regex: /(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:`[^`]*\$\{|\w+\s*\+[^)]*req\.|request\.)/gi,
      message: 'Child process spawned with user-controlled input — command injection',
      recommendation: 'Use spawn with argument arrays (never shell:true). Sanitize with allowlists.',
      fixExample: "// Instead of: exec(`ping ${host}`)\n// Use: spawn('ping', [host]) — still validate host against allowlist",
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /os\.(?:system|popen|exec|popen2|popen3|popen4)\s*\(\s*(?!["'][^"']*["']\s*$)/g,
      message: 'Python os.system/popen with dynamic input — command injection risk',
      recommendation: 'Use subprocess.run() with argument list and shell=False. Validate all inputs.',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /subprocess\.\w+\s*\([^)]*shell\s*=\s*True/gi,
      message: 'Python subprocess with shell=True — command injection risk',
      recommendation: 'Set shell=False and pass arguments as a list instead of a string.',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      // `(?<![.\w$])` keeps method calls out: `regex.exec(line)` and
      // `child.exec` are not shell invocations. Without it, every RegExp.exec
      // in a codebase reports as command injection.
      regex: /(?<![.\w$])(?:system|exec|passthru|shell_exec|popen|proc_open|expect_popen)\s*\(\s*(?!["'][^"']*["']\s*[),;])/gi,
      // escapeshellarg/escapeshellcmd are the documented PHP mitigations; a call
      // that uses them is the fixed form, not the vulnerable one.
      neutralizedBy: /\bescapeshellarg\s*\(|\bescapeshellcmd\s*\(/i,
      message: 'PHP command execution function with dynamic input',
      recommendation: 'Use escapeshellarg() and escapeshellcmd(). Prefer PHP APIs over shell commands.',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /(?:system|exec|spawn|%x)\s*\(?\s*[`"]#\{/g,
      message: 'Ruby command execution with string interpolation',
      recommendation: 'Use system(command, *args) with separate arguments. Avoid interpolation in shell commands.',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    // ── Ruby ──
    // The existing Ruby pattern required `#{` immediately after the quote, so
    // `system("ping -c 1 #{host}")` — interpolation after literal text, i.e. the
    // normal shape — was missed.
    {
      regex: /(?:\bsystem|\bexec|\bspawn|`|%x[({[])\s*\(?\s*["'`][^"'`]*#\{/g,
      message: 'Ruby shell command built with string interpolation',
      recommendation: 'Pass arguments as an array so no shell is involved: system("ping", "-c", "1", host)',
      fixExample: '# Instead of: system("ping -c 1 #{host}")\n# Use: system("ping", "-c", "1", host)',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    // ── Go ──
    // The existing Go pattern required a request accessor inline in the call.
    // When the tainted value was assigned to a variable first — the common case —
    // nothing matched.
    {
      regex: /\bexec\.Command(?:Context)?\s*\([^)]*"[^"]*"\s*\+/g,
      message: 'Go command built with string concatenation',
      recommendation: 'Pass arguments separately: exec.Command("ping", "-c", "1", host). Avoid sh -c.',
      fixExample: '// Instead of: exec.Command("sh", "-c", "ping "+host)\n// Use: exec.Command("ping", "-c", "1", host)',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /\bexec\.Command(?:Context)?\s*\(\s*"(?:sh|bash|cmd|powershell)"\s*,\s*"(?:-c|\/c|-Command)"/g,
      message: 'Go command invoked through a shell — arguments are re-parsed by the shell',
      recommendation: 'Invoke the binary directly with separate arguments instead of routing through sh -c.',
      confidence: 'medium',
      falsePositiveRisk: 'medium',
    },
    {
      regex: /Runtime\.getRuntime\(\)\s*\.\s*exec\s*\([^)]*\b(?:request\.|req\.|getParameter)/g,
      message: 'Java Runtime.exec() with user-controlled input',
      recommendation: 'Use ProcessBuilder with argument list. Validate inputs with strict allowlists.',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /exec\.Command\s*\([^)]*\b(?:r\.URL|r\.Query|r\.Param|c\.Query|c\.Param|request\.)/g,
      message: 'Go exec.Command with user-controlled input',
      recommendation: 'Validate command arguments against allowlists. Never pass raw user input to shell commands.',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
  ],
  scan(filePath: string, content: string, lines: string[]) {
    return scanPatterns(this, filePath, content, lines);
  }
};

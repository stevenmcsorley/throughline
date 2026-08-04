import { Rule } from '../../types';

export const sqlInjectionRule: Rule = {
  id: 'sql-injection',
  name: 'SQL Injection',
  description: 'User input concatenated or interpolated into SQL queries without parameterization',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-89',
  owasp: 'A03:2021-Injection',
  mitreAttack: { tactic: 'TA0001', technique: 'T1190' },
  references: [
    'https://owasp.org/www-community/attacks/SQL_Injection',
    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
  ],
  extensions: ['.js', '.ts', '.py', '.java', '.php', '.rb', '.go', '.cs', '.swift', '.kt', '.scala', '.pl', '.lua'],
  patterns: [
    {
      regex: /(?:execute|query|exec|run)\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*`/gi,
      message: 'SQL query built with template literal interpolation of untrusted data',
      recommendation: 'Use parameterized queries with placeholders (? or $1) instead of string interpolation',
      fixExample: "// Instead of: db.query(`SELECT * FROM users WHERE id = ${userId}`)\n// Use: db.query('SELECT * FROM users WHERE id = ?', [userId])",
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /(?:execute|query|exec|run)\s*\(\s*(?:"[^"]*"\s*\+\s*\w+\s*\+|[^)]*\b\w+\s*\+\s*\s*["'])/gi,
      message: 'SQL query built with string concatenation',
      recommendation: 'Use parameterized queries. Never concatenate strings into SQL.',
      fixExample: "// Instead of: db.query('SELECT * FROM users WHERE id = ' + userId)\n// Use: db.query('SELECT * FROM users WHERE id = ?', [userId])",
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    // ── Ruby ──
    // `db.execute("SELECT ... #{id}")`. The generic concatenation pattern above
    // only understands `+`, so Ruby interpolation went entirely undetected.
    {
      regex: /\.\s*(?:execute|exec_query|query|select_all|find_by_sql|where)\s*\(?\s*["'][^"']*#\{/g,
      message: 'Ruby SQL query built with string interpolation',
      recommendation: 'Use bound parameters: db.execute("SELECT * FROM users WHERE id = ?", [id])',
      fixExample: '# Instead of: db.execute("SELECT * FROM users WHERE id = #{id}")\n# Use: db.execute("SELECT * FROM users WHERE id = ?", [id])',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    // ── Go ──
    // `db.Query("SELECT ... " + id)`. Capitalised method names, and the query
    // string is concatenated on one side only, so neither generic shape matched.
    {
      regex: /\.\s*(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare)\s*\(\s*(?:[\w.]+\s*,\s*)?"[^"]*"\s*\+/g,
      message: 'Go SQL query built with string concatenation',
      recommendation: 'Use placeholders: db.Query("SELECT * FROM users WHERE id = $1", id)',
      fixExample: '// Instead of: db.Query("SELECT * FROM users WHERE id = " + id)\n// Use: db.Query("SELECT * FROM users WHERE id = $1", id)',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /\bfmt\.Sprintf\s*\(\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*%[svdq]/gi,
      message: 'Go SQL query assembled with fmt.Sprintf — not parameterized',
      recommendation: 'Sprintf does not escape SQL. Use placeholders and pass values as query arguments.',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    // ── PHP ──
    // `mysqli_query($conn, "SELECT ... " . $id)` — the connection handle comes
    // first and PHP concatenates with `.`, so the existing PHP pattern (which
    // expected `$var` directly inside the first-argument string) never fired.
    {
      regex: /(?:mysqli_query|mysql_query|pg_query|pg_send_query|->\s*query|->\s*exec|->\s*prepare)\s*\(\s*(?:\$\w+\s*,\s*)?["'][^"']*["']\s*\.\s*\$/g,
      message: 'PHP SQL query built with string concatenation',
      recommendation: 'Use prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
      fixExample: '// Instead of: mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id)\n// Use: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /(?:execute|cursor\.execute|executemany)\s*\(\s*f["']/gi,
      message: 'Python SQL query built with f-string interpolation',
      recommendation: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      fixExample: '# Instead of: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n# Use: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /(?:mysqli_query|mysql_query|pg_query|->query|->exec|PDO::query|sqlite_query)\s*\(\s*"[^"]*\$\w+/gi,
      message: 'PHP SQL query with variable interpolation in string',
      recommendation: 'Use PDO prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*"[^"]*"\s*\+/gi,
      message: 'Java SQL query built with string concatenation',
      recommendation: 'Use PreparedStatement: PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); stmt.setInt(1, userId);',
      confidence: 'high',
      falsePositiveRisk: 'low',
    },
    {
      regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.+\+.*(?:req\.|request\.|params\.|getParameter|query\[|cookie\[)/gi,
      message: 'User-controlled input concatenated directly into SQL statement',
      recommendation: 'Use parameterized queries / prepared statements. Never concatenate user input into SQL.',
      confidence: 'high',
      falsePositiveRisk: 'medium',
    },
  ],
  scan(filePath: string, content: string, lines: string[]) {
    const { applyPatternRule, buildVariableMap } = require('../../engine/pattern-engine');
    const varMap = buildVariableMap(lines);
    const findings = [];
    for (const p of this.patterns || []) {
      findings.push(...applyPatternRule(this, filePath, lines, p, varMap));
    }
    return findings;
  }
};

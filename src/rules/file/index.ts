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

export const pathTraversalRule: Rule = {
  id: 'path-traversal',
  name: 'Path Traversal',
  description: 'File operations using unsanitized user input — directory traversal to access arbitrary files',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-22',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0005', technique: 'T1083' },
  references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /(?:fs\.(?:readFile|writeFile|createReadStream|createWriteStream|unlink|open|readdir|stat|access|exists|rm|rmSync|readFileSync|writeFileSync))\s*\([^)]*\b(?:req\.|request\.|params|query|body)\b/gi, message: 'File system operation with user-controlled path — path traversal risk', recommendation: 'Resolve canonical path and verify it stays within allowed directory. Reject paths with "../"', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /path\.(?:join|resolve)\s*\([^)]*\b(?:req\.|request\.|params|query|body)\b/gi, message: 'path.join/resolve with user input — traversal may bypass join safety', recommendation: 'Use path.resolve() then verify the result starts with the expected base directory.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:fopen|file_get_contents|file_put_contents|include|require|include_once|require_once|readfile|unlink|file_exists|is_file|is_dir)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE|FILES)/gi, message: 'PHP file operation with user input — path traversal or LFI', recommendation: 'Use basename() to strip paths. Validate against an allowlist of permitted files. Use open_basedir.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /open\s*\([^)]*\b(?:request\.(?:args|form|get|data|json)|request\.)/gi, message: 'Python file open with user-controlled path', recommendation: 'Validate the resolved path stays within the intended directory. Use pathlib.Path.resolve().', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /new\s+(?:File|FileInputStream|FileReader|FileOutputStream|FileWriter|RandomAccessFile|FileChannel)\s*\([^)]*\b(?:request\.|req\.|getParameter)/g, message: 'Java file operation with user-controlled parameter', recommendation: 'Canonicalize the path and verify it starts with the expected parent directory.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:tarfile|zipfile)\.(?:extract|extractall)\s*\(/gi, message: 'Archive extraction — potential Zip Slip vulnerability', recommendation: 'Validate each entry path before extraction. Reject entries with ".." or absolute paths.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /express\.static\s*\([^)]*\)/gi, message: 'Express static file serving — verify it does not serve sensitive directories', recommendation: 'Serve static files from a dedicated directory. Never serve the application root.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const arbitraryFileWriteRule: Rule = {
  id: 'arbitrary-file-write',
  name: 'Arbitrary File Write',
  description: 'File upload or write operations with user-controlled paths/content — can lead to RCE',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-434',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0002', technique: 'T1505' },
  references: ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /(?:fs\.writeFile|fs\.writeFileSync|fs\.createWriteStream)\s*\([^)]*\b(?:req\.(?:body|query|params)\.\w+|req\.file)/gi, message: 'File write with user-controlled filename or content', recommendation: 'Generate server-side filenames (UUID). Validate content types. Never use user-supplied filenames.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:move_uploaded_file|fwrite|file_put_contents)\s*\([^)]*\$(?:_FILES|_GET|_POST)/gi, message: 'PHP file write with user-controlled path — arbitrary file upload/write', recommendation: 'Use move_uploaded_file() with a generated filename. Validate MIME types server-side.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\.upload\s*\(|\bupload\s*\(|multer\s*\(/gi, message: 'File upload handler — verify file type, size, and storage path restrictions', recommendation: 'Set max file size. Validate MIME types. Scan for malware. Generate unique filenames on server.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const raceConditionRule: Rule = {
  id: 'race-condition',
  name: 'Race Condition (TOCTOU)',
  description: 'Time-of-check to time-of-use patterns — filesystem or shared state race conditions',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-367',
  owasp: 'A01:2021-Broken Access Control',
  mitreAttack: { tactic: 'TA0004', technique: 'T1068' },
  references: ['https://owasp.org/www-community/attacks/Time_of_check_time_of_use'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /fs\.existsSync?\s*\([^)]*\).*\n.*fs\.(?:readFile|writeFile|unlink|rename)/g, message: 'File existence check followed by file operation — TOCTOU race condition', recommendation: 'Perform the operation directly and handle errors. Use atomic file operations (rename, link).', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /if\s*\(\s*(?:file_exists|is_file|is_dir|is_writable|is_readable)\s*\([^)]*\)[\s\S]{0,100}(?:fopen|file_get_contents|unlink|rename)(?!\s*\()/g, message: 'PHP: file check before operation — potential TOCTOU', recommendation: 'Use atomic operations. Open file handles directly and use flock() for synchronization.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /\.select\s*\([^)]*\)[\s\S]{0,200}\.update\s*\(/g, message: 'Database select-then-update without transaction or lock — race condition', recommendation: 'Use SELECT ... FOR UPDATE within a transaction. Or use atomic update operations with conditions.', confidence: 'low', falsePositiveRisk: 'high' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const redosRule: Rule = {
  id: 'dos-redos',
  name: 'ReDoS (Regular Expression Denial of Service)',
  description: 'Regex patterns vulnerable to catastrophic backtracking on crafted input',
  severity: 'medium',
  confidence: 'medium',
  cwe: 'CWE-1333',
  owasp: 'A03:2021-Injection',
  references: ['https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.go', '.cs'],
  patterns: [
    { regex: /\/\([^)]*\+(?:\.\*|\.\+|\w\+)[^)]*\)\+\//g, message: 'Nested quantifier in regex — potential catastrophic backtracking (ReDoS)', recommendation: 'Rewrite regex to avoid nested quantifiers ((a+)+). Use possessive quantifiers (a++) or atomic groups.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /\/\([^)]*\([^)]*\|[^)]*\)\*[^)]*\)\/|\/[^/]*\([^)]*\|[^)]*\)\+[^/]*\//g, message: 'Alternation with repetition in regex — ReDoS risk on crafted input', recommendation: 'Use atomic groups (?>...) or possessive quantifiers to prevent backtracking.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

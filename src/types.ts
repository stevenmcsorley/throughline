// ─── Severity ───
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ─── Confidence ───
export type Confidence = 'certain' | 'high' | 'medium' | 'low';

// ─── CVSS 3.1 ───
export interface CvssScores {
  baseScore: number;
  impactSubscore: number;
  exploitabilitySubscore: number;
  vectorString: string;
  rating: 'none' | 'low' | 'medium' | 'high' | 'critical';
}

// ─── MITRE ATT&CK ───
export type AttackTactic =
  | 'TA0001'  // Initial Access
  | 'TA0002'  // Execution
  | 'TA0003'  // Persistence
  | 'TA0004'  // Privilege Escalation
  | 'TA0005'  // Defense Evasion
  | 'TA0006'  // Credential Access
  | 'TA0007'  // Discovery
  | 'TA0008'  // Lateral Movement
  | 'TA0009'  // Collection
  | 'TA0010'  // Exfiltration
  | 'TA0011'  // Command and Control
  | 'TA0040'  // Impact
  | 'TA0043'; // Reconnaissance

export type AttackTechnique = string; // e.g. 'T1190', 'T1059', 'T1505'

// ─── OWASP ───
export type OwaspCategory =
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable Components'
  | 'A07:2021-Auth Failures'
  | 'A08:2021-Software & Data Integrity'
  | 'A09:2021-Logging & Monitoring'
  | 'A10:2021-SSRF';

// ─── CWE ───
export type CweId = `CWE-${number}`;

// ─── Data Flow ───
export interface TaintSource {
  name: string;
  category: 'user-input' | 'environment' | 'database' | 'network' | 'file' | 'crypto';
  pattern: string;
  description: string;
}

export interface TaintSink {
  name: string;
  category: 'sql' | 'command' | 'code-exec' | 'file-op' | 'network-req' | 'html-render' | 'redirect' | 'crypto' | 'deserialize' | 'auth' | 'template';
  pattern: string;
  description: string;
}

export interface TaintFlow {
  source: string;
  sinks: string[];
  variableChain: string[];
  sanitizers: string[];
  confidence: Confidence;
}

// ─── Finding ───
export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  message: string;
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  snippet: string;
  recommendation: string;
  fixExample?: string;

  // Standards mappings
  cwe: CweId;
  owasp: OwaspCategory;
  cvss?: CvssScores;
  mitreAttack?: { tactic: AttackTactic; technique: AttackTechnique };

  // Data flow (when available)
  taintFlow?: TaintFlow;

  // Metadata
  references: string[];
  falsePositiveRisk: 'low' | 'medium' | 'high'; // how likely this is a false positive
}

// ─── Rule ───
export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  cwe: CweId;
  owasp: OwaspCategory;
  mitreAttack?: { tactic: AttackTactic; technique: AttackTechnique };
  references: string[];
  extensions: string[];

  // For AST analysis
  astSources?: TaintSource[];
  astSinks?: TaintSink[];

  // For pattern analysis
  patterns?: PatternRule[];

  // Scan function
  scan(filePath: string, content: string, lines: string[], ast?: any): Finding[];
}

export interface PatternRule {
  regex: RegExp;
  message: string;
  recommendation: string;
  fixExample?: string;
  confidence: Confidence;
  falsePositiveRisk: 'low' | 'medium' | 'high';
  requiresTaintSource?: boolean;
  /**
   * Match inside string literals, regex literals and comments too.
   * Required by secret detection, where the secret *is* the string content.
   * Off by default: a vulnerability pattern found in data rather than code is
   * almost always documentation, a test string, or a scanner rule matching
   * its own pattern text.
   */
  matchInStrings?: boolean;
  /**
   * Match *only* inside comments — the inverse of the default.
   *
   * Used to detect security controls that were commented out rather than
   * removed. A commented-out CSRF or helmet registration is a protection the
   * application no longer has, and it is invisible to every other rule
   * precisely because comments are masked.
   */
  onlyInComments?: boolean;
  /**
   * Only apply this pattern when the file as a whole matches. Lets a narrow
   * pattern stay narrow: `maxDepth: 15` is only a GraphQL depth-limit finding
   * in a file that actually uses GraphQL, and is otherwise ordinary config.
   */
  requiresFileContext?: RegExp;
  /**
   * Suppress a match when its own line also matches this — the sanitizer
   * escape hatch. `shell_exec("ping " . escapeshellarg($host))` is the
   * documented safe form in PHP, and reporting it teaches people to ignore
   * the scanner.
   */
  neutralizedBy?: RegExp;
  contextLines?: number; // check nearby lines for context
}

// ─── Scan ───
export interface ScanOptions {
  paths: string[];
  extensions?: string[];
  exclude?: string[];
  rules?: string[];
  severity?: Severity;
  confidence?: Confidence;
  maxFileSize?: number;
  parallel?: boolean;
  /** Scan for high-entropy secrets (API keys, tokens) */
  entropy?: boolean;
  /** Scan dependencies for known CVEs */
  deps?: boolean;
  /** Only scan files changed since last scan */
  incremental?: boolean;
  /** Clear incremental cache before scanning */
  clearCache?: boolean;
  /** Use git diff to select files (--git-aware) */
  gitAware?: boolean;
  /** Git base ref for diff comparison */
  gitBaseRef?: string;
  /** Apply stored triage verdicts, hiding reviewed false positives (default true) */
  applyTriage?: boolean;
}

export interface ScanResult {
  filesScanned: number;
  findings: Finding[];
  durationMs: number;
  summary: ScanSummary;
  /** Present when triage verdicts were applied — see engine/triage */
  triage?: {
    suppressed: number;
    severityAdjusted: number;
    stale: number;
  };
  /** Present on incremental runs: how much was re-analysed vs served from cache */
  incremental?: {
    /** Files actually re-analysed this run */
    analysed: number;
    /** Unchanged files whose findings came from the cache */
    fromCache: number;
    /** Unchanged files re-analysed because the cache could not serve them */
    cacheMisses: number;
    deleted: number;
  };
}

export interface ScanSummary {
  bySeverity: Record<Severity, number>;
  byConfidence: Record<Confidence, number>;
  byOwasp: Partial<Record<OwaspCategory, number>>;
  byCwe: Record<string, number>;
  totalFindings: number;
  falsePositiveEstimate: { low: number; medium: number; high: number };
}

// ─── AST types (from babel) ───
export interface AstContext {
  imports: Map<string, string>;       // localName → modulePath
  variableTypes: Map<string, string>; // variableName → type annotation
  functionCalls: Map<string, string[]>; // functionName → argument names
  taintedVariables: Set<string>;       // variables sourced from user input
  sanitizerCalls: Set<string>;         // known sanitizer functions called
  scopeChain: Map<string, Set<string>>; // scope → variables
}

// ─── Dependency ───
export interface DependencyVuln {
  package: string;
  version: string;
  cve: string;
  severity: Severity;
  description: string;
  fixedIn?: string;
}

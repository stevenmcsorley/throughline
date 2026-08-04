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

export const nosqlInjectionRule: Rule = {
  id: 'nosql-injection',
  name: 'NoSQL Injection',
  description: 'User input used unsanitized in NoSQL queries — can bypass filters or extract data',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-943',
  owasp: 'A03:2021-Injection',
  mitreAttack: { tactic: 'TA0001', technique: 'T1190' },
  references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'],
  extensions: ['.js', '.ts', '.py', '.php', '.java', '.go'],
  patterns: [
    { regex: /\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateMany|updateOne|deleteMany|deleteOne|countDocuments|aggregate|distinct)\s*\(\s*(?:req\.body|req\.query|req\.params|request\.body)/gi, message: 'MongoDB query with raw request input — NoSQL injection risk', recommendation: 'Cast inputs to expected types. Strip $where, $regex, $ne, $gt operators from user-supplied objects. Use mongo-sanitize.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\$where\s*:/g, message: 'MongoDB $where operator — allows arbitrary JavaScript execution in query', recommendation: 'Never use $where with user input. It evaluates JavaScript and can lead to code execution.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\$regex\s*:(?:[^}]*\b(?:req\.|request\.|params|query)\b)/gi, message: 'MongoDB $regex with user input — ReDoS or injection risk', recommendation: 'Sanitize regex input. Use simple text search or full-text indexes where possible. Escape special regex chars.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /\$ne\s*:+|\$gt\s*:+|\$lt\s*:+/g, message: 'MongoDB operators — review if user can inject these (e.g., via JSON body)', recommendation: 'Validate that user-supplied objects do not contain $-prefixed keys. Use schema validation.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /\w+\.(?:find|findOne|findById|where)\s*\(\s*(?:req\.body|req\.query|req\.params)\b/gi, message: 'Mongoose query with raw request data', recommendation: 'Use Mongoose schema validation. Whitelist queryable fields. Cast types (e.g., mongoose.Types.ObjectId).', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const insecureDeserialRule: Rule = {
  id: 'insecure-deserialization',
  name: 'Insecure Deserialization',
  description: 'Deserializing untrusted data — can lead to RCE, DoS, or privilege escalation',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-502',
  owasp: 'A08:2021-Software & Data Integrity',
  mitreAttack: { tactic: 'TA0002', technique: 'T1059' },
  references: ['https://owasp.org/www-community/attacks/Deserialization_of_untrusted_data'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.cs'],
  patterns: [
    { regex: /eval\s*\(\s*(?:JSON\.parse|req\.(?:body|query|params)|request\.(?:body|query|params))/gi, message: 'eval with user input — arbitrary code execution', recommendation: 'Never use eval() on user input. Use JSON.parse() with schema validation for data parsing.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /new\s+Function\s*\([^)]*\b(?:req\.|request\.|params|query|body)\b/gi, message: 'new Function with user input — arbitrary code execution', recommendation: 'Function constructor with user input is equivalent to eval(). Use safe alternatives.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /pickle\.(?:loads?|load)\s*\([^)]*\b(?:request\.|request\.data|request\.body|file\.)/gi, message: 'pickle deserialization — arbitrary code execution on untrusted data', recommendation: 'Never unpickle untrusted data. Use JSON or protobuf for serialization. If pickle is unavoidable, use HMAC signatures.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /yaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.(?:Safe|CSafe))/gi, message: 'yaml.load() without SafeLoader — arbitrary code execution via YAML', recommendation: 'Always use yaml.safe_load() for untrusted data, or yaml.load(data, Loader=yaml.SafeLoader).', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /marshal\.(?:loads?|load)\s*\(/gi, message: 'marshal deserialization — can execute arbitrary code (unsafe format)', recommendation: 'Replace marshal with JSON or protobuf. marshal is not secure against malicious data.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, message: 'PHP unserialize with user input — object injection leading to RCE', recommendation: 'Never unserialize() user input. Use JSON. If required, use allowed_classes parameter to restrict deserialization.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /ObjectInputStream\s*\([^)]*\b(?:request\.|req\.|getInputStream|getParameter)/gi, message: 'Java ObjectInputStream with untrusted data — deserialization RCE', recommendation: 'Use a safe deserialization library (e.g., Jackson with DefaultTyping disabled). Implement a class allowlist.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter|JavaScriptSerializer)\b/gi, message: '.NET unsafe deserialization formatter — known RCE gadgets', recommendation: 'Use System.Text.Json or DataContractSerializer with known types. Never deserialize untrusted data with BinaryFormatter.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:node-serialize|serialize-javascript|node-serializer)[^(]*\s*\(/gi, message: 'Node.js deserialization library — verify safety', recommendation: 'Use v8.deserialize() for trusted data. For untrusted data, use JSON.parse() with schema validation.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /require\s*\(\s*(?:req\.|request\.|params|query|body)/gi, message: 'Dynamic require() with user input — arbitrary module loading', recommendation: 'Never use require() with user-controlled paths. Use static imports or a whitelist of allowed modules.', confidence: 'high', falsePositiveRisk: 'low' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const xxeRule: Rule = {
  id: 'xxe',
  name: 'XML External Entity (XXE) Injection',
  description: 'XML parsers processing external entities — can read local files, perform SSRF, or cause DoS',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-611',
  owasp: 'A05:2021-Security Misconfiguration',
  mitreAttack: { tactic: 'TA0006', technique: 'T1083' },
  references: ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'],
  extensions: ['.js', '.ts', '.py', '.php', '.rb', '.java', '.cs'],
  patterns: [
    { regex: /(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax|xml\.parsers\.expat|lxml\.etree)\b.*\bparse\s*\(/gi, message: 'XML parser used — ensure external entities are disabled', recommendation: 'Python: use defusedxml (defusedxml.ElementTree.parse, defusedxml.minidom.parse).', confidence: 'high', falsePositiveRisk: 'medium' },
    { regex: /DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance/gi, message: 'Java XML parser factory — must explicitly disable XXE', recommendation: 'Set factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) and factory.setFeature("http://xml.org/sax/features/external-general-entities", false).', confidence: 'high', falsePositiveRisk: 'medium' },
    { regex: /(?:simplexml_load_string|simplexml_load_file|DOMDocument::loadXML|DOMDocument::load|SimpleXMLElement)\s*\(/gi, message: 'PHP XML parsing — ensure libxml_disable_entity_loader(true)', recommendation: 'Call libxml_disable_entity_loader(true) before parsing XML. PHP 8.0+ this is default but verify.', confidence: 'high', falsePositiveRisk: 'medium' },
    { regex: /(?:xml2js\.parseString|libxmljs\.parseXml|fast-xml-parser\.parse)\s*\(/gi, message: 'Node.js XML parser — ensure entity expansion is disabled', recommendation: 'Configure parser options to disable entity expansion and DTD processing.', confidence: 'high', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

export const prototypePollutionRule: Rule = {
  id: 'prototype-pollution',
  name: 'Prototype Pollution',
  description: 'JavaScript patterns vulnerable to prototype pollution — can lead to RCE or property injection',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-1321',
  owasp: 'A03:2021-Injection',
  mitreAttack: { tactic: 'TA0002', technique: 'T1059' },
  references: ['https://owasp.org/www-community/attacks/Prototype_Pollution'],
  extensions: ['.js', '.ts'],
  patterns: [
    { regex: /Object\.assign\s*\(\s*(?:\{\}|{)\s*,\s*(?:req\.body|req\.query|req\.params|request\.body)\b/gi, message: 'Object.assign with raw request body — prototype pollution via __proto__ key', recommendation: 'Filter out __proto__, constructor, and prototype keys before merging. Or use Object.create(null) for user objects.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /(?:_\.merge|_\.defaultsDeep|_\.extend|merge|defaultsDeep|deepExtend|deepmerge|deep-merge)\s*\([^)]*\b(?:req\.body|req\.query|req\.params|request\.body)/gi, message: 'Deep merge with user input — prototype pollution risk', recommendation: 'Use safe merge that ignores __proto__/constructor/prototype. Consider lodash.merge with a customizer that rejects these keys.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /obj\[key\]\s*=\s*(?!.*hasOwnProperty|.*Object\.prototype\.hasOwnProperty)/g, message: 'Dynamic key property assignment without __proto__ guard', recommendation: 'Add guard: if (key === "__proto__" || key === "constructor" || key === "prototype") return;', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /for\s*\(\s*(?:var|let|const)?\s*(\w+)\s+in\s+(\w+)\)\s*\{/g, message: 'for...in loop — ensure hasOwnProperty check is used', recommendation: 'Use for...of with Object.keys() or add: if (!obj.hasOwnProperty(key)) continue;', confidence: 'low', falsePositiveRisk: 'high' },
    { regex: /JSON\.parse\s*\(\s*JSON\.stringify\s*\([^)]*\)\s*\)/g, message: 'JSON round-trip clone — loses prototype pollution protections from original object', recommendation: 'This clone approach drops __proto__ setter behavior, but is not a fix. Validate user objects explicitly.', confidence: 'low', falsePositiveRisk: 'high' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

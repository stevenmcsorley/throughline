import { Rule } from '../types';

// Injection
import { sqlInjectionRule } from './injection/sql-injection';
import { commandInjectionRule } from './injection/command-injection';
import { sstiRule, ldapInjectionRule, graphqlInjectionRule, httpParamPollutionRule } from './injection/other-injections';

// Crypto
import { insecureCryptoRule, hardcodedSecretsRule } from './crypto/index';

// Auth
import { insecureJwtRule, csrfRule, idorRule, massAssignmentRule, missingAuthRule } from './auth/index';

// Web
import { xssRule, ssrfRule, openRedirectRule, corsMisconfigRule, clickjackingRule, cachePoisoningRule } from './web/index';

// File
import { pathTraversalRule, arbitraryFileWriteRule, raceConditionRule, redosRule } from './file/index';

// Infra
import { dockerSecurityRule, k8sSecurityRule, terraformSecurityRule } from './infra/index';

// Deps
import { dependencyScanRule } from './deps/index';

// Code Quality
import { nosqlInjectionRule, insecureDeserialRule, xxeRule, prototypePollutionRule } from './code-quality/index';

export const allRules: Rule[] = [
  // ─── Critical ───
  sqlInjectionRule,
  commandInjectionRule,
  hardcodedSecretsRule,
  insecureDeserialRule,
  sstiRule,
  arbitraryFileWriteRule,

  // ─── High ───
  xssRule,
  pathTraversalRule,
  insecureCryptoRule,
  ssrfRule,
  nosqlInjectionRule,
  xxeRule,
  insecureJwtRule,
  prototypePollutionRule,
  idorRule,
  massAssignmentRule,
  ldapInjectionRule,
  graphqlInjectionRule,
  dockerSecurityRule,
  k8sSecurityRule,
  terraformSecurityRule,
  dependencyScanRule,
  raceConditionRule,

  // ─── Medium ───
  openRedirectRule,
  corsMisconfigRule,
  csrfRule,
  missingAuthRule,
  cachePoisoningRule,
  redosRule,

  // ─── Low/Info ───
  clickjackingRule,
  httpParamPollutionRule,
];

export function getRulesByIds(ids: string[]): Rule[] {
  if (!ids || ids.length === 0) return allRules;
  const idSet = new Set(ids.map(id => id.toLowerCase()));
  return allRules.filter(r => idSet.has(r.id.toLowerCase()));
}

// Note: there are deliberately no getRulesBySeverity/getRulesByConfidence
// helpers. A rule's declared severity is the *typical* severity of what it
// finds, not a bound on it — a "high" rule can emit a critical finding. The
// --severity/--confidence thresholds therefore filter findings, in
// applyFindingFilters() in scanner.ts.

export function getRuleSummary() {
  const bySeverity: Record<string, string[]> = {};
  for (const rule of allRules) {
    if (!bySeverity[rule.severity]) bySeverity[rule.severity] = [];
    bySeverity[rule.severity].push(rule.id);
  }
  return {
    totalRules: allRules.length,
    bySeverity,
    cwes: [...new Set(allRules.map(r => r.cwe))].sort(),
    languages: [...new Set(allRules.flatMap(r => r.extensions))].sort(),
  };
}

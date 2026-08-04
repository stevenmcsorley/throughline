import { CvssScores, Severity } from './types';

// CVSS 3.1 scoring as per FIRST specification
// https://www.first.org/cvss/v3.1/specification-document

type AttackVector = 'N' | 'A' | 'L' | 'P';
type AttackComplexity = 'L' | 'H';
type PrivilegesRequired = 'N' | 'L' | 'H';
type UserInteraction = 'N' | 'R';
type Scope = 'U' | 'C';
type CiaImpact = 'N' | 'L' | 'H';

interface CvssVector {
  AV: AttackVector;
  AC: AttackComplexity;
  PR: PrivilegesRequired;
  UI: UserInteraction;
  S: Scope;
  C: CiaImpact;
  I: CiaImpact;
  A: CiaImpact;
}

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.5 },
  },
  UI: { N: 0.85, R: 0.62 },
  CIA: { N: 0, L: 0.22, H: 0.56 },
};

function roundUp1(value: number): number {
  const intPart = Math.floor(value);
  const frac = value - intPart;
  if (frac > 0) {
    return value < 0.1 ? Math.ceil(value * 10) / 10 : Math.ceil(value * 10) / 10;
  }
  return value;
}

export function calculateCvss(vector: CvssVector): CvssScores {
  const { AV, AC, PR, UI, S, C, I, A } = vector;

  // Exploitability subscore
  const ess = 8.22 * WEIGHTS.AV[AV] * WEIGHTS.AC[AC] * WEIGHTS.PR[S][PR] * WEIGHTS.UI[UI];

  // Impact subscore
  const iscBase = 1 - ((1 - WEIGHTS.CIA[C]) * (1 - WEIGHTS.CIA[I]) * (1 - WEIGHTS.CIA[A]));

  let impact: number;
  if (S === 'U') {
    impact = 6.42 * iscBase;
  } else {
    impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }

  let baseScore: number;
  if (impact <= 0) {
    baseScore = 0;
  } else if (S === 'U') {
    baseScore = roundUp1(Math.min(impact + ess, 10));
  } else {
    baseScore = roundUp1(Math.min(1.08 * (impact + ess), 10));
  }

  const rating: CvssScores['rating'] =
    baseScore >= 9.0 ? 'critical' :
    baseScore >= 7.0 ? 'high' :
    baseScore >= 4.0 ? 'medium' :
    baseScore >= 0.1 ? 'low' : 'none';

  const vectorString = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;

  return {
    baseScore: Math.round(baseScore * 10) / 10,
    impactSubscore: Math.round(impact * 10) / 10,
    exploitabilitySubscore: Math.round(ess * 10) / 10,
    vectorString,
    rating,
  };
}

// Default CVSS vectors for common vulnerability classes
export const DEFAULT_CVSS: Record<string, CvssVector> = {
  'sql-injection':            { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'command-injection':        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'hardcoded-secrets':        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'xss':                      { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
  'path-traversal':           { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  'insecure-crypto':          { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  'ssrf':                     { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  'nosql-injection':          { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'open-redirect':            { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
  'prototype-pollution':      { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'insecure-deserialization': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'xxe':                      { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  'insecure-jwt':             { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  'missing-authz':            { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'ssti':                     { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'ldap-injection':           { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  'mass-assignment':          { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'idor':                     { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  'graphql-injection':        { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
  'cors-misconfig':           { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'H', I: 'H', A: 'N' },
  'race-condition':           { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'arbitrary-file-write':     { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'dependency-vuln':          { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'docker-root':              { AV: 'L', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' },
  'docker-secret':            { AV: 'L', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' },
  'k8s-privileged':           { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' },
  'terraform-misconfig':      { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
  'csrf':                     { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
  'http-parameter-pollution': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },
  'cache-poisoning':          { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' },
  'clickjacking':             { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
  'dos-redos':                { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'H' },
  'insecure-cors':            { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'H', I: 'H', A: 'N' },
};

export function severityFromCvss(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

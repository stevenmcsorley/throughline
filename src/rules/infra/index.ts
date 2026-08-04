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

// ─── Docker Security ───
export const dockerSecurityRule: Rule = {
  id: 'docker-security',
  name: 'Docker Security Misconfiguration',
  description: 'Dockerfile patterns that weaken container security',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-250',
  owasp: 'A05:2021-Security Misconfiguration',
  mitreAttack: { tactic: 'TA0004', technique: 'T1611' },
  references: ['https://owasp.org/www-project-docker-top-10/', 'https://docs.docker.com/develop/security-best-practices/'],
  extensions: ['.dockerfile', 'Dockerfile', '.dockerignore'],
  patterns: [
    { regex: /^FROM\s+(?!.*:.*alpine|.*:.*slim|.*:.*distroless|.*scratch)(?:[^:\s]+|(?!.*slim))$/gim, message: 'Base image may not be minimal — increases attack surface', recommendation: 'Use alpine, slim, or distroless base images to minimize attack surface.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /^USER\s+root\s*$|^#.*root/gim, message: 'Container running as root — privilege escalation risk', recommendation: 'Create a non-root user: RUN adduser -D appuser && USER appuser', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /^ENV\s+(?:AWS_|SECRET|PASSWORD|PASSWD|TOKEN|KEY)\s*=/gim, message: 'Sensitive value in ENV instruction — visible in docker inspect and image history', recommendation: 'Use Docker secrets, build-time args with --build-arg (still visible in history), or runtime secret mounts.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /^ADD\s+(?:https?|ftp):\/\//gim, message: 'ADD with remote URL — unpredictable and unpinned dependency', recommendation: 'Use RUN curl/wget with pinned version and hash verification. Prefer COPY for local files.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /^RUN\s+curl\s+.*\|\s*(?:bash|sh|python|perl)/gim, message: 'curl-pipe-shell pattern — arbitrary code execution from remote source', recommendation: 'Download, verify checksum, and then execute. Use pinned versions.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /^VOLUME\s+\[/gim, message: 'VOLUME declaration — be aware volumes persist and may leak data', recommendation: 'Use explicit volume mounts at runtime. Avoid anonymous volumes that accumulate secrets.', confidence: 'low', falsePositiveRisk: 'medium' },
    { regex: /^EXPOSE\s+(?:0\.0\.0\.0|::\/0)/gim, message: 'Port exposed on all interfaces explicitly', recommendation: 'Bind to 127.0.0.1 when the service only needs local access.', confidence: 'low', falsePositiveRisk: 'medium' },
    { regex: /^HEALTHCHECK\s+NONE\b/gim, message: 'Healthcheck disabled — container may run in broken state undetected', recommendation: 'Add HEALTHCHECK instruction to detect runtime failures.', confidence: 'low', falsePositiveRisk: 'medium' },
    { regex: /^FROM\s+[^:]*$/gim, message: 'Base image without tag — defaults to :latest which is non-deterministic', recommendation: 'Pin to a specific digest or version tag: FROM node:20-alpine@sha256:...', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) { return scanPatterns(this, filePath, content, lines); }
};

// ─── Kubernetes Security ───
export const k8sSecurityRule: Rule = {
  id: 'k8s-security',
  name: 'Kubernetes Security Misconfiguration',
  description: 'Kubernetes manifests with insecure pod security settings',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-250',
  owasp: 'A05:2021-Security Misconfiguration',
  mitreAttack: { tactic: 'TA0004', technique: 'T1611' },
  references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/'],
  extensions: ['.yml', '.yaml'],
  patterns: [
    { regex: /privileged\s*:\s*true/i, message: 'Container running in privileged mode — full host access', recommendation: 'Never run containers privileged. Use specific capabilities with securityContext.capabilities.add instead.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /allowPrivilegeEscalation\s*:\s*true/i, message: 'Privilege escalation allowed — container can gain more privileges', recommendation: 'Set allowPrivilegeEscalation: false on all containers.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /hostNetwork\s*:\s*true/i, message: 'Host network access enabled — container shares host network namespace', recommendation: 'Avoid hostNetwork unless absolutely necessary. It bypasses network policies.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /hostPID\s*:\s*true|hostIPC\s*:\s*true/i, message: 'Container sharing host PID or IPC namespace — container escape risk', recommendation: 'Never use hostPID or hostIPC. These allow container processes to see/interact with host processes.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /runAsUser\s*:\s*0|runAsGroup\s*:\s*0|runAsNonRoot\s*:\s*false/i, message: 'Container running as root user', recommendation: 'Set runAsNonRoot: true and specify a non-zero runAsUser (e.g., 1000).', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /readOnlyRootFilesystem\s*:\s*false/i, message: 'Writable root filesystem — allows attacker to write tools/backdoors', recommendation: 'Set readOnlyRootFilesystem: true. Mount only necessary directories as volumes.', confidence: 'medium', falsePositiveRisk: 'medium' },
    { regex: /capabilities\s*:\s*\n\s*add\s*:\s*\n\s*-\s*(?:ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE)/gi, message: 'Dangerous Linux capability granted to container', recommendation: 'Drop ALL capabilities and only add minimum required ones. Avoid SYS_ADMIN and NET_ADMIN.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /automountServiceAccountToken\s*:\s*true|automountServiceAccountToken\s*:\s*[^f][^a][^l][^s][^e]/gi, message: 'Service account token auto-mounted — potential credential leak', recommendation: 'Set automountServiceAccountToken: false if the pod does not need to access the API server.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) {
    // Only scan files that look like K8s manifests
    if (content.includes('kind:') && (content.includes('Pod') || content.includes('Deployment') ||
        content.includes('StatefulSet') || content.includes('DaemonSet') || content.includes('Job') ||
        content.includes('CronJob') || content.includes('ReplicaSet'))) {
      return scanPatterns(this, filePath, content, lines);
    }
    return [];
  }
};

// ─── Terraform Security ───
export const terraformSecurityRule: Rule = {
  id: 'terraform-misconfig',
  name: 'Terraform IaC Misconfiguration',
  description: 'Infrastructure as Code patterns that create insecure cloud resources',
  severity: 'high',
  confidence: 'high',
  cwe: 'CWE-668',
  owasp: 'A05:2021-Security Misconfiguration',
  references: ['https://owasp.org/www-project-top-10-infrastructure-as-code-risks/'],
  extensions: ['.tf', '.tfvars', '.hcl'],
  patterns: [
    { regex: /aws_s3_bucket[^(]*\{[^}]*acl\s*=\s*"(?:public-read|public-read-write|authenticated-read)"/gi, message: 'S3 bucket with public ACL — data exposure risk', recommendation: 'Use "private" ACL. Enable block public access settings. Use bucket policies for granular access.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /aws_security_group_rule[^(]*\{[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/gi, message: 'Security group open to 0.0.0.0/0 — unrestricted access', recommendation: 'Restrict CIDR to known IP ranges. Never use 0.0.0.0/0 for SSH (22), RDP (3389), or DB ports.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /aws_db_instance[^(]*\{[^}]*publicly_accessible\s*=\s*true/gi, message: 'Database instance publicly accessible', recommendation: 'Set publicly_accessible = false. Use VPC and connect via bastion or VPN.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /aws_iam_role_policy[^(]*\{[^}]*"\*"\s*:\s*\[?\s*"\*"\s*\]?/gi, message: 'IAM policy with wildcard actions and resources — excessive permissions', recommendation: 'Follow least privilege principle. Specify exact actions and resources. Avoid "*" for both.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /storage_bucket_acl\s*=\s*"(?:public-read|public-read-write)"/gi, message: 'GCS bucket with public ACL', recommendation: 'Use uniform bucket-level access. Avoid legacy ACLs. Grant access via IAM.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /aws_ecs_task_definition[^(]*\{[^}]*"environment"\s*=\s*\[\s*\{[^}]*name\s*=\s*"([^"]*(?:SECRET|PASSWORD|TOKEN|KEY)[^"]*)"/gi, message: 'Sensitive value in ECS environment variable — visible in AWS console', recommendation: 'Use AWS Secrets Manager or SSM Parameter Store for secrets. Reference via secrets block in task definition.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /aws_lambda_function[^(]*\{[^}]*"environment"\s*=\s*\{[^}]*variables\s*=\s*\{[^}]*"(?:SECRET|PASSWORD|TOKEN|KEY)/gi, message: 'Secrets in Lambda environment variables', recommendation: 'Use AWS Secrets Manager or encrypted environment variables with KMS.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /aws_rds_cluster[^(]*\{[^}]*storage_encrypted\s*=\s*false/gi, message: 'RDS cluster storage encryption disabled', recommendation: 'Set storage_encrypted = true. Use KMS customer-managed key for compliance.', confidence: 'high', falsePositiveRisk: 'low' },
    { regex: /aws_eks_cluster[^(]*\{[^}]*endpoint_public_access\s*=\s*true/gi, message: 'EKS cluster with public endpoint — attack surface for API server', recommendation: 'Disable public endpoint access if internal-only. Use private endpoint or restrict with source CIDRs.', confidence: 'medium', falsePositiveRisk: 'medium' },
  ],
  scan(filePath: string, content: string, lines: string[]) {
    // Only scan if it looks like Terraform
    if (content.includes('resource "') || content.includes('provider "') || content.includes('terraform {')) {
      return scanPatterns(this, filePath, content, lines);
    }
    return [];
  }
};

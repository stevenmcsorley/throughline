import { ScanResult } from '../types';

export function htmlFormat(result: ScanResult): string {
  const { filesScanned, findings, durationMs, summary } = result;

  const sevColors: Record<string, string> = {
    critical: '#dc2626', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6', info: '#6b7280',
  };

  const findingsHtml = findings.map((f, i) => {
    const cvssHtml = f.cvss
      ? `<span class="cvss" style="background:${cvssColor(f.cvss.baseScore)}">CVSS ${f.cvss.baseScore}</span>`
      : '';
    return `
    <tr class="finding" data-severity="${f.severity}">
      <td style="color:${sevColors[f.severity]};font-weight:bold;text-align:center">${i + 1}</td>
      <td><span class="severity-badge" style="background:${sevColors[f.severity]}">${f.severity.toUpperCase()}</span></td>
      <td><strong>${esc(f.title)}</strong><br><span class="dim">${esc(f.ruleId)}</span></td>
      <td>${esc(f.file.split('/').pop() || f.file.split('\\').pop() || f.file)}<br><span class="dim">line ${f.line}${cvssHtml}</span></td>
      <td>
        <div>${esc(f.message)}</div>
        ${f.recommendation ? `<div class="rec">→ ${esc(f.recommendation)}</div>` : ''}
        ${f.fixExample ? `<pre class="fix">${esc(f.fixExample)}</pre>` : ''}
        <div class="meta">${f.cwe} | ${f.owasp} | Confidence: ${f.confidence}</div>
      </td>
    </tr>`;
  }).join('\n');

  const summaryBars = ['critical', 'high', 'medium', 'low', 'info']
    .filter(s => (summary.bySeverity as any)[s] > 0)
    .map(s => {
      const count = (summary.bySeverity as any)[s];
      const pct = ((count / findings.length) * 100).toFixed(0);
      return `<div class="summary-bar">
        <span class="label" style="color:${sevColors[s]}">${s.toUpperCase()}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${sevColors[s]}"></div></div>
        <span>${count} (${pct}%)</span>
      </div>`;
    }).join('\n');

  const owaspBreakdown = Object.entries(summary.byOwasp)
    .sort((a, b) => b[1] - a[1])
    .map(([owasp, count]) => `<tr><td>${esc(owasp)}</td><td>${count}</td></tr>`)
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Throughline — Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .header { text-align: center; padding: 3rem 0 2rem; border-bottom: 2px solid #334155; margin-bottom: 2rem; }
  .header h1 { font-size: 2.5rem; color: #38bdf8; margin-bottom: 0.5rem; }
  .header .subtitle { color: #94a3b8; font-size: 1.1rem; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; text-align: center; }
  .stat .value { font-size: 2rem; font-weight: 700; color: #38bdf8; }
  .stat .label { color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .summary-bars { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }
  .summary-bars h2 { margin-bottom: 1rem; font-size: 1.2rem; }
  .summary-bar { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
  .summary-bar .label { font-weight: 600; min-width: 80px; }
  .bar-track { flex: 1; background: #334155; border-radius: 4px; height: 8px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
  .section { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }
  .section h2 { margin-bottom: 1rem; font-size: 1.2rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.75rem; background: #0f172a; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }
  td { padding: 0.75rem; border-top: 1px solid #334155; vertical-align: top; font-size: 0.9rem; }
  tr:hover { background: #1a2744; }
  .severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; color: white; margin-right: 0.5rem; }
  .cvss { padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: 600; color: white; margin-left: 0.5rem; }
  .dim { color: #64748b; font-size: 0.85rem; }
  .rec { color: #4ade80; margin-top: 0.25rem; font-size: 0.85rem; }
  .fix { background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 0.75rem; margin-top: 0.5rem; font-size: 0.8rem; color: #e2e8f0; overflow-x: auto; }
  .meta { color: #64748b; font-size: 0.75rem; margin-top: 0.5rem; }
  .owasp-table td { font-size: 0.85rem; }
  .footer { text-align: center; color: #64748b; font-size: 0.8rem; padding: 2rem 0; }
  @media (max-width: 768px) { .stats { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Throughline</h1>
    <p class="subtitle">Advanced Security Vulnerability Analysis Report</p>
    <p class="dim" style="margin-top:0.5rem">Generated ${new Date().toISOString().split('T')[0]}</p>
  </div>

  <div class="stats">
    <div class="stat"><div class="value">${filesScanned}</div><div class="label">Files Scanned</div></div>
    <div class="stat"><div class="value">${findings.length}</div><div class="label">Findings</div></div>
    <div class="stat"><div class="value">${(durationMs / 1000).toFixed(1)}s</div><div class="label">Duration</div></div>
  </div>

  ${findings.length > 0 ? `
  <div class="summary-bars">
    <h2>Finding Distribution</h2>
    ${summaryBars}
  </div>
  ` : `
  <div class="section" style="text-align:center;padding:3rem">
    <p style="font-size:1.2rem;color:#4ade80">✓ No vulnerabilities detected</p>
  </div>
  `}

  ${findings.length > 0 ? `
  <div class="section">
    <h2>Findings (${findings.length})</h2>
    <table>
      <thead><tr><th style="width:30px">#</th><th>Severity</th><th>Issue</th><th>Location</th><th>Details</th></tr></thead>
      <tbody>${findingsHtml}</tbody>
    </table>
  </div>
  ` : ''}

  ${Object.keys(summary.byOwasp).length > 0 ? `
  <div class="section">
    <h2>OWASP Top 10 Coverage</h2>
    <table class="owasp-table">
      <thead><tr><th>Category</th><th>Findings</th></tr></thead>
      <tbody>${owaspBreakdown}</tbody>
    </table>
  </div>
  ` : ''}

  <div class="footer">
    <p>Throughline v2.0.0 — Static Application Security Testing</p>
    <p>This report contains security findings that should be reviewed by qualified security personnel.</p>
  </div>
</div>
</body>
</html>`;
}

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function cvssColor(score: number): string {
  if (score >= 9.0) return '#7f1d1d';
  if (score >= 7.0) return '#991b1b';
  if (score >= 4.0) return '#92400e';
  if (score >= 0.1) return '#1e40af';
  return '#374151';
}

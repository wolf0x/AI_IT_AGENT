use async_trait::async_trait;
use serde_json::{json, Value};
use std::fs;
use chrono::Utc;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrReportTool;

#[async_trait]
impl Tool for IrReportTool {
    fn name(&self) -> &str { "ir_report" }
    fn description(&self) -> &str {
        "Generate a self-contained HTML incident response report from analyzer findings. Accepts findings JSON (from ir_analyzer) and optional raw scan data, produces a styled HTML file with summary cards, findings table, and timeline."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "findings": {
                    "type": "object",
                    "description": "Findings JSON from ir_analyzer (with 'findings' array and 'summary')"
                },
                "output_path": {
                    "type": "string",
                    "description": "File path to save the HTML report (default: workspace/output/ir_report_TIMESTAMP.html)"
                },
                "title": {
                    "type": "string",
                    "description": "Report title (default: 'Windows Incident Response Report')"
                }
            },
            "required": ["findings"]
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let findings_data = &args["findings"];
        let title = args["title"].as_str().unwrap_or("Windows Incident Response Report");

        let findings_arr = findings_data["findings"].as_array()
            .ok_or("Missing 'findings' array in findings data")?;
        let summary = &findings_data["summary"];

        let critical = summary["critical"].as_u64().unwrap_or(0);
        let high = summary["high"].as_u64().unwrap_or(0);
        let medium = summary["medium"].as_u64().unwrap_or(0);
        let low = summary["low"].as_u64().unwrap_or(0);
        let total = findings_arr.len();

        let now = Utc::now();
        let timestamp = now.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let file_ts = now.format("%Y%m%d_%H%M%S").to_string();

        let output_path = args["output_path"].as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}/output/ir_report_{}.html", ctx.working_dir, file_ts));

        // Build findings rows
        let mut findings_rows = String::new();
        for f in findings_arr {
            let severity = f["severity"].as_str().unwrap_or("low");
            let badge_class = match severity {
                "critical" => "sev-critical",
                "high" => "sev-high",
                "medium" => "sev-medium",
                "low" => "sev-low",
                _ => "sev-pass",
            };
            let rule_id = f["rule_id"].as_str().unwrap_or("-");
            let category = f["category"].as_str().unwrap_or("-");
            let title_text = f["title"].as_str().unwrap_or("-");
            let evidence = f["evidence"].as_str().unwrap_or("-");
            let recommendation = f["recommendation"].as_str().unwrap_or("-");

            findings_rows.push_str(&format!(r#"<tr class="finding-row" data-severity="{}">
<td><span class="badge {}">{}</span></td>
<td class="rule-id">{}</td>
<td>{}</td>
<td class="finding-title">{}</td>
<td class="evidence"><pre>{}</pre></td>
<td>{}</td>
</tr>"#,
                severity, badge_class, severity,
                html_escape(rule_id),
                html_escape(category),
                html_escape(title_text),
                html_escape(evidence),
                html_escape(recommendation),
            ));
        }

        // Build priority advice
        let mut advice = Vec::new();
        if critical > 0 {
            advice.push("CRITICAL: Immediately preserve all logs and evidence. Begin forensic imaging if possible.");
        }
        if high > 0 {
            advice.push("HIGH: Export and review all high-severity findings. Check for lateral movement indicators.");
        }
        if medium > 0 {
            advice.push("MEDIUM: Schedule investigation of medium-severity items within 24 hours.");
        }
        advice.push("Generate a timeline of all events and correlate across categories.");
        advice.push("Compare findings against known-good baseline for this environment.");

        let advice_html: String = advice.iter().enumerate()
            .map(|(i, a)| format!("<li>{}: {}</li>", i + 1, html_escape(a)))
            .collect();

        let html = format!(r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
:root {{
  --bg: #f0f2f5; --card: #fff; --text: #1a1a2e; --text2: #555;
  --critical: #991b1b; --high: #dc2626; --medium: #d97706; --low: #0284c7; --pass: #059669;
  --border: #e5e7eb; --shadow: 0 1px 3px rgba(0,0,0,0.1);
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: 'Segoe UI', 'Microsoft YaHei', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: #fff; padding: 30px 40px; border-radius: 12px; margin-bottom: 24px; }}
header h1 {{ font-size: 1.8em; margin-bottom: 8px; }}
header .meta {{ opacity: 0.8; font-size: 0.9em; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.summary-card {{ background: var(--card); border-radius: 10px; padding: 20px; box-shadow: var(--shadow); text-align: center; }}
.summary-card .number {{ font-size: 2.2em; font-weight: 700; }}
.summary-card .label {{ font-size: 0.85em; color: var(--text2); margin-top: 4px; }}
.summary-card.critical .number {{ color: var(--critical); }}
.summary-card.high .number {{ color: var(--high); }}
.summary-card.medium .number {{ color: var(--medium); }}
.summary-card.total .number {{ color: var(--text); }}
.section {{ background: var(--card); border-radius: 10px; padding: 24px; box-shadow: var(--shadow); margin-bottom: 24px; }}
.section h2 {{ font-size: 1.3em; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid var(--border); }}
.two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
@media(max-width:860px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
.filter-bar {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
.filter-bar select, .filter-bar input {{ padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 0.9em; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
th {{ background: #f8f9fa; padding: 10px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid var(--border); }}
td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
tr:hover {{ background: #f8f9fa; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; color: #fff; font-size: 0.8em; font-weight: 600; }}
.sev-critical {{ background: var(--critical); }}
.sev-high {{ background: var(--high); }}
.sev-medium {{ background: var(--medium); }}
.sev-low {{ background: var(--low); }}
.sev-pass {{ background: var(--pass); }}
.evidence pre {{ white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow-y: auto; font-size: 0.85em; background: #f8f9fa; padding: 8px; border-radius: 4px; margin: 0; }}
.finding-title {{ max-width: 200px; }}
.rule-id {{ font-family: monospace; font-size: 0.85em; color: var(--text2); }}
.advice-list {{ padding-left: 20px; }}
.advice-list li {{ margin-bottom: 8px; }}
footer {{ text-align: center; padding: 20px; color: var(--text2); font-size: 0.85em; }}
@media print {{ body {{ background: #fff; }} .section {{ box-shadow: none; border: 1px solid #ddd; }} }}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>{title_escaped}</h1>
  <div class="meta">Generated: {timestamp} | Total Findings: {total}</div>
</header>

<div class="summary-grid">
  <div class="summary-card critical"><div class="number">{critical}</div><div class="label">Critical</div></div>
  <div class="summary-card high"><div class="number">{high}</div><div class="label">High</div></div>
  <div class="summary-card medium"><div class="number">{medium}</div><div class="label">Medium</div></div>
  <div class="summary-card total"><div class="number">{total}</div><div class="label">Total Findings</div></div>
</div>

<div class="two-col">
  <div class="section">
    <h2>Analysis Summary</h2>
    <p>This report contains <strong>{total}</strong> findings from automated incident response analysis.
    Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}.</p>
    <p style="margin-top:12px">Findings are generated by a rule-based engine that examines process listings, network connections, persistence mechanisms, event logs, account configurations, driver signatures, and lateral movement indicators.</p>
  </div>
  <div class="section">
    <h2>Priority Actions</h2>
    <ol class="advice-list">{advice_html}</ol>
  </div>
</div>

<div class="section" id="findings">
  <h2>All Findings</h2>
  <div class="filter-bar">
    <label>Severity: <select id="sevFilter" onchange="filterFindings()">
      <option value="all">All</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="pass">Pass</option>
    </select></label>
    <label>Search: <input type="text" id="searchFilter" placeholder="Search findings..." oninput="filterFindings()"></label>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Title</th><th>Evidence</th><th>Recommendation</th></tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>
</div>

<footer>
  Windows Incident Response Report — Generated by RustAgent IR Tools
</footer>
</div>

<script>
function filterFindings() {{
  const sev = document.getElementById('sevFilter').value;
  const search = document.getElementById('searchFilter').value.toLowerCase();
  document.querySelectorAll('.finding-row').forEach(row => {{
    const matchSev = sev === 'all' || row.dataset.severity === sev;
    const matchSearch = !search || row.textContent.toLowerCase().includes(search);
    row.style.display = matchSev && matchSearch ? '' : 'none';
  }});
}}
</script>
</body>
</html>"#,
            title = html_escape(title),
            title_escaped = html_escape(title),
            timestamp = timestamp,
            total = total,
            critical = critical,
            high = high,
            medium = medium,
            findings_rows = findings_rows,
            advice_html = advice_html,
        );

        // Write to file
        fs::write(&output_path, &html)
            .map_err(|e| format!("Failed to write report: {}", e))?;

        Ok(json!({
            "status": "ok",
            "output_path": output_path,
            "total_findings": total,
            "summary": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            }
        }))
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#39;")
}

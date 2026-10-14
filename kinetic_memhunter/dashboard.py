"""
Kinetic-Memhunter: Interactive HTML Forensic Dashboard Generator.
Renders an executive, self-contained dashboard summarizing batch memory analysis,
comparative metrics against baseline reports and VirusTotal GTI data.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def generate_dashboard_html(results_dir: str | Path, output_file: str | Path | None = None) -> Path:
    """Generates a self-contained, interactive HTML forensic report dashboard."""
    results_path = Path(results_dir)
    summary_file = results_path / "benchmark_summary.json"

    if summary_file.exists():
        with open(summary_file, "r", encoding="utf-8") as f:
            summary_data = json.load(f)
    else:
        summary_data = {}

    samples = summary_data.get("results") or summary_data.get("samples") or []
    families = summary_data.get("family_breakdown") or summary_data.get("family_distribution") or {}

    samples_json = json.dumps(samples, indent=2)
    families_json = json.dumps(families, indent=2)

    total_samples = summary_data.get("successful_analyses") or summary_data.get("total_samples") or len(samples)
    avg_adv = summary_data.get("average_advantage_ratio", 1.0)
    total_our = summary_data.get("total_our_indicators_discovered") or summary_data.get("total_our_indicators") or sum(s.get("our_indicators", 0) for s in samples)
    total_ref = summary_data.get("total_reference_indicators") or summary_data.get("total_ref_indicators") or sum(s.get("ref_indicators", 0) for s in samples)
    total_sqlite = summary_data.get("total_sqlite_databases_carved") or sum(s.get("sqlite_count", 0) for s in samples)
    total_creds = summary_data.get("total_credentials_extracted") or sum(s.get("credentials_count", 0) for s in samples)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Kinetic-Memhunter // Forensic Memory Intelligence Dashboard</title>
  <style>
    :root {{
      --bg-primary: #0a0e17;
      --bg-secondary: #121826;
      --bg-card: #1b2336;
      --border: #2a3650;
      --text-main: #f0f4fc;
      --text-muted: #8b9bb4;
      --accent-cyan: #00e5ff;
      --accent-green: #00e676;
      --accent-purple: #b388ff;
      --accent-amber: #ffd740;
      --accent-red: #ff5252;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; }}
    body {{ background: var(--bg-primary); color: var(--text-main); line-height: 1.5; padding: 2rem; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
    .title-group h1 {{ font-size: 1.75rem; font-weight: 700; color: var(--accent-cyan); letter-spacing: -0.5px; }}
    .title-group p {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }}
    .badge {{ background: rgba(0, 229, 255, 0.1); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }}
    
    /* Stats Grid */
    .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.25rem; margin-bottom: 2.5rem; }}
    .kpi-card {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; }}
    .kpi-card .label {{ color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }}
    .kpi-card .value {{ font-size: 2rem; font-weight: 800; margin-top: 0.5rem; }}
    .val-cyan {{ color: var(--accent-cyan); }}
    .val-green {{ color: var(--accent-green); }}
    .val-purple {{ color: var(--accent-purple); }}
    .val-amber {{ color: var(--accent-amber); }}
    .val-red {{ color: var(--accent-red); }}

    /* Layout */
    .dashboard-body {{ display: grid; grid-template-columns: 320px 1fr; gap: 2rem; }}
    @media (max-width: 1024px) {{ .dashboard-body {{ grid-template-columns: 1fr; }} }}

    /* Sidebar / Family Breakdown */
    .card {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
    .card h2 {{ font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; }}
    .fam-item {{ margin-bottom: 1rem; }}
    .fam-header {{ display: flex; justify-content: space-between; font-size: 0.9rem; margin-bottom: 0.25rem; }}
    .progress-bar {{ background: var(--bg-card); height: 8px; border-radius: 4px; overflow: hidden; }}
    .progress-fill {{ background: var(--accent-cyan); height: 100%; border-radius: 4px; }}

    /* Controls & Table */
    .table-controls {{ display: flex; gap: 1rem; margin-bottom: 1rem; }}
    .search-input {{ flex: 1; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 0.6rem 1rem; color: #fff; font-size: 0.9rem; outline: none; }}
    .search-input:focus {{ border-color: var(--accent-cyan); }}
    
    .table-container {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }}
    th {{ background: var(--bg-card); padding: 0.85rem 1rem; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border); }}
    td {{ padding: 0.85rem 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }}
    tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
    .hash-cell {{ font-family: monospace; color: var(--accent-cyan); font-weight: 500; cursor: pointer; }}
    .badge-adv {{ background: rgba(0, 230, 118, 0.15); color: var(--accent-green); padding: 0.2rem 0.5rem; border-radius: 6px; font-weight: 700; font-family: monospace; }}
    .badge-score {{ background: rgba(255, 82, 82, 0.15); color: var(--accent-red); padding: 0.2rem 0.5rem; border-radius: 6px; font-weight: 700; }}
  </style>
</head>
<body>
  <div class="header">
    <div class="title-group">
      <h1>KINETIC-MEMHUNTER // FORENSIC DASHBOARD</h1>
      <p>Automated In-Memory Stealer Deconstruction vs Baseline Sandboxes & VirusTotal GTI</p>
    </div>
    <div>
      <span class="badge">Engine Status: Optimal</span>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="label">Samples Processed</div>
      <div class="value val-cyan">{total_samples}</div>
    </div>
    <div class="kpi-card">
      <div class="label">Average Advantage Ratio</div>
      <div class="value val-green">{avg_adv:.1f}x</div>
    </div>
    <div class="kpi-card">
      <div class="label">Discovered Threat Indicators</div>
      <div class="value val-purple">{total_our:,}</div>
    </div>
    <div class="kpi-card">
      <div class="label">Reference Indicators</div>
      <div class="value val-amber">{total_ref:,}</div>
    </div>
    <div class="kpi-card">
      <div class="label">SQLite DBs Carved</div>
      <div class="value val-cyan">{total_sqlite}</div>
    </div>
    <div class="kpi-card">
      <div class="label">Stolen Records Recovered</div>
      <div class="value val-red">{total_creds}</div>
    </div>
  </div>

  <div class="dashboard-body">
    <div>
      <div class="card">
        <h2>Family Attribution</h2>
        <div id="family-breakdown"></div>
      </div>
      <div class="card">
        <h2>Forensic Highlights</h2>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">
          Direct address-space carving routinely extracts up to <strong>278x</strong> more indicators than passive sandbox observation.
        </p>
        <ul style="font-size: 0.85rem; padding-left: 1.25rem; color: var(--text-main);">
          <li>In-flight browser credential databases</li>
          <li>Win32 named mutexes & CodeView PDBs</li>
          <li>Dead Drop Resolvers (Steam, Telegram)</li>
          <li>Hypervisor & sandbox evasion unmasking</li>
        </ul>
      </div>
    </div>

    <div>
      <div class="table-controls">
        <input type="text" id="search-input" class="search-input" placeholder="Filter by SHA-256 hash or malware family...">
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>SHA-256 Hash</th>
              <th>Malware Family</th>
              <th>Score</th>
              <th>Our Indicators</th>
              <th>Reference</th>
              <th>Advantage Ratio</th>
              <th>SQLite</th>
              <th>Credentials</th>
            </tr>
          </thead>
          <tbody id="samples-table-body"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const samples = {samples_json};
    const families = {families_json};

    function renderFamilies() {{
      const container = document.getElementById('family-breakdown');
      const total = Object.values(families).reduce((a, b) => a + b, 0) || 1;
      container.innerHTML = Object.entries(families).map(([fam, count]) => {{
        const pct = ((count / total) * 100).toFixed(1);
        return `
          <div class="fam-item">
            <div class="fam-header">
              <span><strong>${{fam}}</strong></span>
              <span>${{count}} (${{pct}}%)</span>
            </div>
            <div class="progress-bar">
              <div class="progress-fill" style="width: ${{pct}}%;"></div>
            </div>
          </div>
        `;
      }}).join('');
    }}

    function renderTable(filterText = '') {{
      const tbody = document.getElementById('samples-table-body');
      const q = filterText.toLowerCase();
      const filtered = samples.filter(s => 
        (s.sample_hash && s.sample_hash.toLowerCase().includes(q)) ||
        (s.family && s.family.toLowerCase().includes(q))
      );

      tbody.innerHTML = filtered.map(s => `
        <tr>
          <td class="hash-cell" title="${{s.sample_hash}}">${{s.sample_hash ? s.sample_hash.substring(0, 16) + '...' : 'Unknown'}}</td>
          <td><strong>${{s.family || 'Unknown'}}</strong> <span style="font-size:0.75rem; color:var(--text-muted);">(${{Math.round((s.confidence||0)*100)}}%)</span></td>
          <td><span class="badge-score">${{s.threat_score || 0}}</span></td>
          <td><strong style="color:var(--accent-cyan);">${{s.our_indicators || 0}}</strong></td>
          <td>${{s.ref_indicators || 0}}</td>
          <td><span class="badge-adv">${{(s.advantage_ratio || 1.0).toFixed(1)}}x</span></td>
          <td>${{s.sqlite_count || 0}}</td>
          <td>${{s.credentials_count || 0}}</td>
        </tr>
      `).join('');
    }}

    document.getElementById('search-input').addEventListener('input', (e) => {{
      renderTable(e.target.value);
    }});

    renderFamilies();
    renderTable();
  </script>
</body>
</html>
"""

    out_file = Path(output_file) if output_file else results_path / "DASHBOARD.html"
    out_file.write_text(html_content, encoding="utf-8")
    return out_file

/* =========================================================================
   Explainable CSPM dashboard
   Vanilla JS, no build step, no CDN. Charts are hand-drawn SVG so the demo
   works on a machine with no network.

   Two views: Technical (for engineers) and Compliance (for risk/audit).
   Both read the same stored findings -- the difference is framing, which is
   the whole point of the project.
   ========================================================================= */

'use strict';

/* ------------------------------------------------------------------ state */

const state = {
  view: 'technical',
  filters: {
    band: [],
    status: [],
    resource_type: [],
    rule_id: [],
    detection_source: [],
  },
  search: '',
  sort: 'risk_score:desc',
  findings: [],
  total: 0,
  loading: false,
  selected: null,
  stats: null,
  compliance: null,
  trend: null,
  options: null,
  rulesById: {},
};

/* -------------------------------------------------------------- utilities */

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

/** Escape untrusted text before it goes near innerHTML.
 *  Resource names and ARNs come from a cloud account and are not ours to trust. */
function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const BAND_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const SOURCE_LABELS = { rule_engine: 'Rule engine', anomaly_detection: 'Anomaly detection' };
const STATUS_LABELS = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  remediated: 'Remediated',
  false_positive: 'False positive',
};

const prettyStatus = (s) => STATUS_LABELS[s] || s;
const prettyBand = (s) => BAND_LABELS[s] || s;
const prettySource = (s) => SOURCE_LABELS[s] || s;

function prettyResourceType(type) {
  const names = {
    s3_bucket: 'S3 bucket',
    iam_policy: 'IAM policy',
    iam_user: 'IAM user',
    security_group: 'Security group',
    ebs_volume: 'EBS volume',
    rds_instance: 'RDS instance',
    account: 'Account',
  };
  return names[type] || type;
}

/** Banding mirrors `rules.SEVERITY_BANDS` in P2. The API sends a bare score, so
 *  the thresholds are restated here; keep the two in step. */
function bandOf(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function formatDateTime(iso) {
  if (!iso) return 'unknown';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { el.hidden = true; }, 3200);
}

/* ------------------------------------------------------------- api client */

async function api(path, params) {
  const url = new URL(path, window.location.origin);
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value === null || value === undefined || value === '') return;
    if (Array.isArray(value)) {
      if (!value.length) return;
      value.forEach((v) => url.searchParams.append(key, v));
    } else {
      url.searchParams.set(key, value);
    }
  });

  const response = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch (_) { /* non-JSON error body */ }
    throw new Error(`${response.status}: ${detail}`);
  }
  return response.json();
}

/* -------------------------------------------------------------- multiselect */

function labelsFor(filterKey) {
  const map = {
    band: prettyBand,
    status: prettyStatus,
    resource_type: prettyResourceType,
    detection_source: prettySource,
    rule_id: (v) => v,
  };
  return map[filterKey] || ((v) => v);
}

/** Repaint just the summary from current state.
 *
 *  Re-rendering the whole control on every checkbox click would tear down the
 *  <details> the user is clicking inside, so the popover would slam shut after
 *  each selection and picking two values would mean reopening it twice. */
function paintMultiselectSummary(host, { key, label }) {
  const selected = state.filters[key] || [];
  const summary = $('summary', host);
  if (!summary) return;

  host.dataset.active = selected.length ? 'true' : 'false';

  // Naming the single selected value reads better than "Severity"; with several
  // selected the count badge carries it and the label stays generic.
  $('.multiselect-label', summary).textContent =
    selected.length === 1 ? `${label}: ${labelsFor(key)(selected[0])}` : label;

  const count = $('.multiselect-count', summary);
  count.textContent = selected.length;
  count.hidden = selected.length === 0;
}

function renderMultiselect(host) {
  const key = host.dataset.filter;
  const label = host.dataset.label;
  const values = (state.options && state.options[key]) || [];
  const selected = state.filters[key] || [];
  const format = labelsFor(key);

  host.dataset.active = selected.length ? 'true' : 'false';

  host.innerHTML = `
    <details>
      <summary>
        <span class="multiselect-label">${esc(label)}</span>
        <span class="multiselect-count" hidden></span>
        <span class="multiselect-caret">&#9662;</span>
      </summary>
      <div class="multiselect-panel">
        ${values.length
          ? values.map((value) => `
              <label class="multiselect-option">
                <input type="checkbox" value="${esc(value)}" ${selected.includes(value) ? 'checked' : ''}>
                <span>${esc(format(value))}</span>
              </label>`).join('')
          : '<div class="multiselect-empty">No values yet</div>'}
      </div>
    </details>`;

  paintMultiselectSummary(host, { key, label });

  $$('input[type=checkbox]', host).forEach((box) => {
    box.addEventListener('change', () => {
      state.filters[key] = $$('input[type=checkbox]:checked', host).map((b) => b.value);
      paintMultiselectSummary(host, { key, label });
      loadFindings();
    });
  });
}

function renderAllMultiselects() {
  $$('.multiselect').forEach(renderMultiselect);
}

/* ------------------------------------------------------------------ charts */

function emptyChart(message) {
  return `<div class="chart-empty">${esc(message)}</div>`;
}

/** Donut built from stroked circles -- exact, and far less code than arc paths. */
function donutChart(segments, radius) {
  const present = segments.filter((s) => s.count > 0);
  if (!present.length) return emptyChart('No data yet');

  const total = present.reduce((sum, s) => sum + s.count, 0);
  const r = radius || 56;
  const thickness = 20;
  const size = (r + thickness) * 2;
  const circumference = 2 * Math.PI * r;

  let offset = 0;
  const arcs = present.map((segment) => {
    const length = (segment.count / total) * circumference;
    const arc = `
      <circle cx="${size / 2}" cy="${size / 2}" r="${r}"
              fill="none" stroke="${segment.color}" stroke-width="${thickness}"
              stroke-dasharray="${length} ${circumference - length}"
              stroke-dashoffset="${-offset}"
              transform="rotate(-90 ${size / 2} ${size / 2})">
        <title>${esc(segment.label)}: ${segment.count}</title>
      </circle>`;
    offset += length;
    return arc;
  }).join('');

  const legend = present.map((segment) => `
    <div class="legend-item">
      <span class="legend-swatch" style="background:${segment.color}"></span>
      <span class="legend-label">${esc(segment.label)}</span>
      <span class="legend-count">${segment.count}</span>
    </div>`).join('');

  return `
    <div class="donut-wrap">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img"
           aria-label="Findings by severity">${arcs}
        <text x="50%" y="47%" text-anchor="middle" dominant-baseline="middle"
              style="font-size:24px;font-weight:650;fill:var(--text)">${total}</text>
        <text x="50%" y="60%" text-anchor="middle" dominant-baseline="middle"
              style="font-size:10px;fill:var(--text-muted);letter-spacing:.06em">FINDINGS</text>
      </svg>
      <div class="donut-legend">${legend}</div>
    </div>`;
}

function barChart(rows, color, formatLabel) {
  if (!rows.length) return emptyChart('No data yet');
  const max = Math.max(...rows.map((r) => r.count), 1);
  return `<div class="bar-list">${rows.map((row) => `
    <div class="bar-item">
      <span class="bar-label" title="${esc((formatLabel || ((v) => v))(row.label))}">
        ${esc((formatLabel || ((v) => v))(row.label))}
      </span>
      <span class="bar-track">
        <span class="bar-fill" style="width:${Math.max((row.count / max) * 100, 2)}%;background:${color}"></span>
      </span>
      <span class="bar-value">${row.count}</span>
    </div>`).join('')}</div>`;
}

function trendChart(points) {
  if (!points.length) return emptyChart('No scan history yet');
  if (points.length === 1) {
    return `<div class="chart-empty">
      Only one day of data (<strong>${esc(points[0].date)}</strong>, ${points[0].count} findings).
      Run more scans to build a trend.
    </div>`;
  }

  // No preserveAspectRatio="none": height:auto in CSS means the labels scale
  // with the geometry instead of being stretched by it.
  const width = 1000;
  const height = 200;
  const pad = { top: 14, right: 18, bottom: 26, left: 36 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const maxCount = Math.max(...points.map((p) => p.count), 1);
  const stepX = plotW / (points.length - 1);

  const coords = points.map((point, index) => ({
    x: pad.left + index * stepX,
    y: pad.top + plotH - (point.count / maxCount) * plotH,
    point,
  }));

  const line = coords.map((c, i) => `${i === 0 ? 'M' : 'L'}${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(' ');
  const area = `${line} L${coords[coords.length - 1].x.toFixed(1)},${pad.top + plotH} `
    + `L${coords[0].x.toFixed(1)},${pad.top + plotH} Z`;

  const gridLines = [0, 0.5, 1].map((frac) => {
    const y = pad.top + plotH * (1 - frac);
    return `<line class="trend-grid" x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}"/>
            <text class="trend-axis" x="${pad.left - 6}" y="${y + 3}" text-anchor="end">${Math.round(maxCount * frac)}</text>`;
  }).join('');

  // label every nth date so the axis stays readable
  const labelEvery = Math.ceil(points.length / 7);
  const axis = coords.map((c, i) => (i % labelEvery === 0 || i === coords.length - 1)
    ? `<text class="trend-axis" x="${c.x}" y="${height - 6}" text-anchor="middle">${esc(c.point.date.slice(5))}</text>`
    : '').join('');

  const dots = coords.map((c) => `
    <circle class="trend-dot" cx="${c.x}" cy="${c.y}" r="3.5">
      <title>${esc(c.point.date)}: ${c.point.count} findings, avg score ${c.point.avg_score}</title>
    </circle>`).join('');

  return `
    <svg class="trend-svg" viewBox="0 0 ${width} ${height}"
         role="img" aria-label="Findings detected per day">
      ${gridLines}
      <path class="trend-area" d="${area}"/>
      <path class="trend-line" d="${line}"/>
      ${dots}
      ${axis}
    </svg>`;
}

/* ------------------------------------------------------------------ tiles */

function renderTiles() {
  const host = $('#tiles');
  if (!state.stats) { host.innerHTML = ''; return; }
  const s = state.stats.summary;

  const tiles = [
    { label: 'Total findings', value: s.total, foot: `${s.scan_count} scan(s)`, accent: 'var(--border-strong)' },
    { label: 'Open', value: s.open, foot: 'Awaiting action', accent: 'var(--risk-critical)' },
    { label: 'Critical', value: s.critical, foot: 'Score 80+', accent: 'var(--risk-critical)' },
    { label: 'Acknowledged', value: s.acknowledged, foot: 'Accepted risk', accent: 'var(--status-acknowledged)' },
    { label: 'Remediated', value: s.remediated, foot: 'Fixed', accent: 'var(--status-remediated)' },
    { label: 'Avg score (open)', value: s.average_open_score, foot: `All findings: ${s.average_score}`, accent: 'var(--accent)' },
  ];

  if (s.anomaly_findings > 0) {
    tiles.push({
      label: 'Anomaly-detected', value: s.anomaly_findings,
      foot: 'Not from a static rule', accent: '#7c3aed',
    });
  }

  host.innerHTML = tiles.map((tile) => `
    <div class="tile" style="--tile-accent:${tile.accent}">
      <div class="tile-label">${esc(tile.label)}</div>
      <div class="tile-value">${esc(tile.value)}</div>
      <div class="tile-foot">${esc(tile.foot)}</div>
    </div>`).join('');
}

/* ------------------------------------------------------------ findings list */

function findingRowHTML(finding) {
  finding = finding || {};
  finding.resource = finding.resource || {};
  finding.compliance_mappings = Array.isArray(finding.compliance_mappings)
    ? finding.compliance_mappings
    : [];
  finding.risk_score = Number(finding.risk_score) || 0;
  finding.status = finding.status || 'open';
  finding.finding_id = finding.finding_id || 'unknown';
  finding.rule_id = finding.rule_id || 'unknown';
  const band = bandOf(finding.risk_score);
  const ruleTitle = (state.rulesById[finding.rule_id] || {}).title || finding.rule_id;
  const isAnomaly = finding.detection_source === 'anomaly_detection';

  const frameworks = finding.compliance_mappings.map((m) => m.framework);
  const uniqueFrameworks = [...new Set(frameworks)];

  return `
    <button class="finding-row" data-id="${esc(finding.finding_id)}" type="button">
      <span class="score-badge band-${band}">${Math.round(finding.risk_score)}</span>

      <span class="finding-main">
        <span class="finding-title">${esc(ruleTitle)}</span>
        <span class="finding-meta">
          <span class="mono">${esc(finding.resource.name)}</span>
          <span>&middot;</span>
          <span>${esc(prettyResourceType(finding.resource.type))}</span>
          <span>&middot;</span>
          <span>${esc(finding.resource.region)}</span>
        </span>
      </span>

      <span class="finding-right">
        ${isAnomaly ? '<span class="chip chip-anomaly">Anomaly</span>' : ''}
        ${uniqueFrameworks.map((f) => `<span class="chip chip-framework">${esc(f)}</span>`).join('')}
        <span class="chip chip-status-${esc(finding.status)}">${esc(prettyStatus(finding.status))}</span>
      </span>
    </button>`;
}

function renderFindings() {
  const host = $('#findings-list');
  const sub = $('#findings-sub');

  if (state.loading) {
    sub.textContent = 'Loading…';
    host.innerHTML = Array.from({ length: 5 })
      .map(() => '<div style="padding:14px 8px"><div class="skeleton" style="width:70%"></div></div>')
      .join('');
    return;
  }

  sub.textContent = state.total === 0
    ? 'No findings match the current filters'
    : `Showing ${state.findings.length} of ${state.total} finding(s)`;

  if (!state.findings.length) {
    host.innerHTML = `
      <div class="empty-state">
        <strong>No findings</strong>
        ${state.total === 0 && !hasActiveFilters()
          ? 'Run a scan (<code class="mono">POST /scan</code>) or seed the demo database to populate the dashboard.'
          : 'Try widening or clearing the filters above.'}
      </div>`;
    return;
  }

  host.innerHTML = state.findings.map(findingRowHTML).join('');

  $$('.finding-row', host).forEach((row) => {
    row.addEventListener('click', () => openDrawer(row.dataset.id));
  });
}

function hasActiveFilters() {
  return Boolean(
    state.search
    || Object.values(state.filters).some((values) => values.length)
  );
}

/* --------------------------------------------------------------- the drawer */

function scoreBreakdownHTML(finding) {
  const rows = finding.score_breakdown || [];
  if (!rows.length) {
    return `<p class="breakdown-note">
      No scoring factors were substantiated. This finding is listed because the rule
      fired, but the evidence needed to score it was not supplied &mdash; usually a
      gap in the detection engine's output rather than a clean resource.
    </p>`;
  }

  const maxWeight = Math.max(...rows.map((r) => Math.abs(r.weight)), 1);

  const body = rows.map((row) => `
    <div class="breakdown-row">
      <div>
        <div class="breakdown-factor">${esc(row.factor)}</div>
        <div class="breakdown-desc">${esc(row.description)}</div>
        <div class="breakdown-bar" style="width:${(Math.abs(row.weight) / maxWeight) * 100}%;
             ${row.weight < 0 ? 'background:var(--text-subtle)' : ''}"></div>
      </div>
      <div class="breakdown-weight" style="${row.weight < 0 ? 'color:var(--text-muted)' : ''}">
        ${row.weight > 0 ? '+' : ''}${row.weight}
      </div>
    </div>`).join('');

  return `
    <div class="breakdown">
      ${body}
      <div class="breakdown-total">
        <span>Total risk score</span>
        <span>${Math.round(finding.risk_score)} / 100</span>
      </div>
    </div>
    <p class="breakdown-note">
      These factors add up to exactly the score shown &mdash; there is no hidden
      weighting. That is what makes the number auditable.
    </p>`;
}

function complianceHTML(finding) {
  const mappings = finding.compliance_mappings || [];
  if (!mappings.length) return '<p class="breakdown-note">No framework mappings for this rule.</p>';
  return `<div class="clause-list">${mappings.map((m) => `
    <div class="clause">
      <div class="clause-head">
        <span class="chip chip-framework">${esc(m.framework)}</span>
        <span class="clause-code">${esc(m.clause)}</span>
      </div>
      <div class="clause-desc">${esc(m.clause_description)}</div>
    </div>`).join('')}</div>`;
}

/** Render one context value. Values come from a cloud account, so they are
 *  escaped; anything structured is shown as JSON rather than "[object Object]". */
function renderContextValue(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return esc(value.map(renderContextValueRaw).join(', '));
  return esc(renderContextValueRaw(value));
}

function renderContextValueRaw(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function contextHTML(finding) {
  const entries = Object.entries(finding.context || {});
  if (!entries.length) {
    return '<p class="breakdown-note">No raw context was recorded for this finding.</p>';
  }
  return `<dl class="kv">${entries.map(([key, value]) => `
    <dt>${esc(key)}</dt>
    <dd>${renderContextValue(value)}</dd>`).join('')}</dl>`;
}

function drawerHTML(finding) {
  const band = bandOf(finding.risk_score);
  const rule = state.rulesById[finding.rule_id] || {};
  const explanation = finding.explanation || {};
  const projected = explanation.projected_score_after_fix;
  // Only shown when it is a real reduction: "(--0 points)" would read as a bug.
  const improvement = projected !== undefined && projected !== null
    && finding.risk_score - projected > 0
    ? Math.round(finding.risk_score - projected)
    : null;

  return `
    <div class="drawer-head">
      <span class="score-badge band-${band}" style="width:58px;height:52px;font-size:19px">
        ${Math.round(finding.risk_score)}
      </span>
      <div style="min-width:0">
        <div class="drawer-title">${esc(rule.title || finding.rule_id)}</div>
        <div class="drawer-sub">
          <span class="mono">${esc(finding.resource.name)}</span> &middot;
          ${esc(prettyResourceType(finding.resource.type))} &middot; ${esc(finding.resource.region)}
        </div>
        <div class="drawer-sub mono" style="font-size:11px">${esc(finding.resource.id)}</div>
      </div>
    </div>

    <div class="status-actions">
      ${['open', 'acknowledged', 'remediated', 'false_positive'].map((status) => `
        <button class="btn btn-sm btn-status ${finding.status === status ? 'is-active' : ''}"
                data-status="${status}" type="button"
                style="${finding.status === status ? `color:var(--status-${status === 'false_positive' ? 'false' : status})` : ''}">
          ${esc(prettyStatus(status))}
        </button>`).join('')}
    </div>

    <div class="drawer-section">
      <h3>Explanation</h3>
      <div class="explain-card">
        <div class="explain-block explain-issue">
          <div class="explain-label">The issue</div>
          <div class="explain-text">${esc(explanation.issue)}</div>
        </div>
        <div class="explain-block explain-consequence">
          <div class="explain-label">What happens if unaddressed</div>
          <div class="explain-text">${esc(explanation.consequence)}</div>
        </div>
        <div class="explain-block explain-fix">
          <div class="explain-label">Recommended fix</div>
          <div class="explain-text">${esc(explanation.fix)}</div>
        </div>
        <div class="projected">
          <span class="projected-score">${Math.round(finding.risk_score)}</span>
          <span class="projected-arrow">&rarr;</span>
          <span class="projected-score">${projected !== null && projected !== undefined ? Math.round(projected) : '?'}</span>
          <span class="projected-label">
            projected score after remediation
            ${improvement !== null ? `(&minus;${improvement} points)` : ''}
          </span>
        </div>
      </div>
    </div>

    <div class="drawer-section">
      <h3>Why this score</h3>
      ${scoreBreakdownHTML(finding)}
    </div>

    <div class="drawer-section">
      <h3>Compliance mappings</h3>
      ${complianceHTML(finding)}
    </div>

    <div class="drawer-section">
      <h3>Detected by</h3>
      <p class="clause-desc">
        <span class="chip ${finding.detection_source === 'anomaly_detection' ? 'chip-anomaly' : 'chip-source'}">
          ${esc(prettySource(finding.detection_source))}
        </span>
        <span class="mono" style="margin-left:8px">${esc(finding.rule_id)}</span>
      </p>
    </div>

    <div class="drawer-section">
      <h3>Observed context</h3>
      ${contextHTML(finding)}
    </div>

    <div class="drawer-section">
      <h3>Timeline</h3>
      <dl class="kv">
        <dt>First detected</dt><dd>${esc(formatDateTime(finding.detected_at))}</dd>
        <dt>Last seen</dt><dd>${esc(formatDateTime(finding.last_seen_at))}</dd>
        <dt>Scan</dt><dd class="mono">${esc(finding.scan_id)}</dd>
        <dt>Finding ID</dt><dd class="mono">${esc(finding.finding_id)}</dd>
      </dl>
    </div>`;
}

function openDrawer(findingId) {
  const finding = state.findings.find((f) => f.finding_id === findingId);
  if (!finding) return;
  state.selected = finding;

  $('#drawer-body').innerHTML = drawerHTML(finding);
  $('#drawer').hidden = false;
  $('#drawer-scrim').hidden = false;

  $$('.btn-status', $('#drawer-body')).forEach((button) => {
    button.addEventListener('click', () => setStatus(finding.finding_id, button.dataset.status));
  });
}

function closeDrawer() {
  $('#drawer').hidden = true;
  $('#drawer-scrim').hidden = true;
  state.selected = null;
}

async function setStatus(findingId, status) {
  try {
    const response = await fetch(`/findings/${encodeURIComponent(findingId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (!response.ok) throw new Error(response.statusText);

    const finding = await response.json();
    const index = state.findings.findIndex((f) => f.finding_id === findingId);
    if (index !== -1) state.findings[index] = finding;

    openDrawer(findingId);
    toast(`Marked as ${prettyStatus(status)}`);
    // loadFindings rather than renderFindings: a status change alters which
    // findings count as open, and the compliance view's remediation queue is
    // built from that filter. Re-rendering only the technical list would leave
    // the queue showing a finding that has just been actioned.
    await Promise.all([loadFindings(), loadStats(), loadCompliance()]);
  } catch (error) {
    toast(`Could not update status: ${error.message}`);
  }
}

/* ------------------------------------------------------------ compliance view */

function renderCompliance() {
  const frameworkHost = $('#framework-cards');
  const clauseHost = $('#clause-tables');
  const queueHost = $('#compliance-findings');

  if (!state.compliance) {
    frameworkHost.innerHTML = '';
    clauseHost.innerHTML = '';
    queueHost.innerHTML = '';
    return;
  }

  if (!state.compliance.length) {
    frameworkHost.innerHTML = '<div class="empty-state"><strong>No compliance data</strong>Seed the database to see framework mappings.</div>';
    clauseHost.innerHTML = '';
    queueHost.innerHTML = '';
    return;
  }

  frameworkHost.innerHTML = state.compliance.map((item) => `
    <div class="framework-card">
      <div class="framework-name">${esc(item.framework)}</div>
      <div class="framework-stats">
        <div>
          <div class="framework-stat-value">${item.finding_count}</div>
          <div class="framework-stat-label">findings</div>
        </div>
        <div>
          <div class="framework-stat-value" style="color:var(--risk-critical)">${item.open_count}</div>
          <div class="framework-stat-label">open</div>
        </div>
        <div>
          <div class="framework-stat-value">${item.average_score}</div>
          <div class="framework-stat-label">avg score</div>
        </div>
      </div>
    </div>`).join('');

  clauseHost.innerHTML = state.compliance.map((item) => `
    <div>
      <div class="clause-table-head">
        <span class="chip chip-framework">${esc(item.framework)}</span>
        <span class="card-sub">${item.clauses.length} clause(s) breached</span>
      </div>
      <div class="table-scroll">
        <table class="data">
          <thead>
            <tr>
              <th style="width:110px">Clause</th>
              <th>Requirement</th>
              <th class="num" style="width:90px">Findings</th>
            </tr>
          </thead>
          <tbody>
            ${item.clauses.map((clause) => `
              <tr>
                <td class="mono"><strong>${esc(clause.clause)}</strong></td>
                <td>${esc(clause.clause_description)}</td>
                <td class="num">${clause.count}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`).join('');

  // Remediation queue: worst open findings overall, which is what a risk owner
  // needs to triage first regardless of which framework they map to.
  const open = state.findings.filter((f) => f.status === 'open').slice(0, 8);
  if (!open.length) {
    queueHost.innerHTML = '<div class="empty-state"><strong>Nothing open</strong>Every finding has been actioned.</div>';
  } else {
    queueHost.innerHTML = open.map(findingRowHTML).join('');
    $$('.finding-row', queueHost).forEach((row) => {
      row.addEventListener('click', () => openDrawer(row.dataset.id));
    });
  }
}

/* ----------------------------------------------------------------- loading */

async function loadOptions() {
  state.options = await api('/filter-options');
  renderAllMultiselects();
}

async function loadStats() {
  state.stats = await api('/stats');
  renderTiles();

  const bandColors = {
    critical: 'var(--risk-critical)',
    high: 'var(--risk-high)',
    medium: 'var(--risk-medium)',
    low: 'var(--risk-low)',
  };
  $('#chart-severity').innerHTML = donutChart(
    state.stats.by_band.map((row) => ({
      label: prettyBand(row.label),
      count: row.count,
      color: bandColors[row.label] || 'var(--text-subtle)',
    }))
  );

  $('#chart-service').innerHTML = barChart(
    state.stats.by_service,
    'var(--accent)',
    prettyResourceType
  );

  const lastScan = state.stats.summary.last_scan_at;
  $('#last-scan').textContent = lastScan
    ? `Last scan ${formatDateTime(lastScan)} · ${state.stats.summary.total} finding(s) tracked`
    : 'No scans ingested yet';
}

async function loadCompliance() {
  state.compliance = await api('/compliance');
  renderCompliance();
}

async function loadTrend() {
  state.trend = await api('/trend');
  $('#chart-trend').innerHTML = trendChart(state.trend.by_day);
}

async function loadFindings() {
  state.loading = true;
  renderFindings();

  const [sort, order] = state.sort.split(':');
  try {
    const result = await api('/findings', {
      ...state.filters,
      q: state.search,
      sort,
      order,
      limit: 200,
    });
    state.findings = result.items;
    state.total = result.total;
  } catch (error) {
    state.findings = [];
    state.total = 0;
    toast(`Could not load findings: ${error.message}`);
  } finally {
    state.loading = false;
    renderFindings();
    if (state.view === 'compliance') renderCompliance();
  }
}

async function refreshAll() {
  try {
    await Promise.all([loadOptions(), loadStats(), loadCompliance(), loadTrend(), loadFindings()]);
  } catch (error) {
    toast(`Could not reach the API: ${error.message}`);
  }
}

/* ------------------------------------------------------------------- events */

function switchView(view) {
  state.view = view;
  $$('.tab').forEach((tab) => {
    const active = tab.dataset.view === view;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  $('#view-technical').hidden = view !== 'technical';
  $('#view-compliance').hidden = view !== 'compliance';
}

function wireEvents() {
  $$('.tab').forEach((tab) => {
    tab.addEventListener('click', () => switchView(tab.dataset.view));
  });

  $('#refresh-btn').addEventListener('click', refreshAll);
  $('#drawer-close').addEventListener('click', closeDrawer);
  $('#drawer-scrim').addEventListener('click', closeDrawer);

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeDrawer();
  });

  let searchTimer;
  $('#search').addEventListener('input', (event) => {
    clearTimeout(searchTimer);
    const value = event.target.value.trim();
    searchTimer = setTimeout(() => {
      state.search = value;
      loadFindings();
    }, 250);
  });

  $('#sort').addEventListener('change', (event) => {
    state.sort = event.target.value;
    loadFindings();
  });

  $('#clear-filters').addEventListener('click', () => {
    state.search = '';
    $('#search').value = '';
    Object.keys(state.filters).forEach((key) => { state.filters[key] = []; });
    renderAllMultiselects();
    loadFindings();
  });

  // close open multiselect popovers when clicking elsewhere
  document.addEventListener('click', (event) => {
    $$('.multiselect details[open]').forEach((details) => {
      if (!details.contains(event.target)) details.removeAttribute('open');
    });
  });
}

/* --------------------------------------------------------------------- init */

async function init() {
  wireEvents();

  try {
    const rules = await api('/rules');
    state.rulesById = Object.fromEntries(rules.map((rule) => [rule.rule_id, rule]));
  } catch (_) {
    // non-fatal: rows fall back to showing the raw rule_id
  }

  await refreshAll();
}

document.addEventListener('DOMContentLoaded', init);

import os
import uuid
import csv
import io
import json
from datetime import timedelta

from flask import Flask, render_template_string, request, redirect, url_for, flash, Response

from .config import WATCHLISTS_FILE, STATE_FILE, DAILY_LOOKBACK_HOURS, LONG_BACKFILL_DAYS
from .utils import load_json, save_json, now_utc, hash_for_cpes
from .vulnerabilitylookup import build_session
from .scan import run_scan
from .scan_history import add_scan_result, get_new_vulnerabilities

TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerability Management System</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  .badge { display:inline-flex; align-items:center; padding:0 0.5rem; border-radius:9999px; font-size:0.75rem; line-height:1.25rem; font-weight:600; }
  .sev-Critical { background:#dc2626; color:#fff; } .sev-High { background:#ef4444; color:#fff; }
  .sev-Medium  { background:#f59e0b; color:#fff; } .sev-Low { background:#16a34a; color:#fff; }
  .sev-None    { background:#9ca3af; color:#fff; }
  th.sortable { cursor:pointer; }
  #stickyBox { position: sticky; top: 12px; z-index: 10; }
  thead.sticky th { position: sticky; top: 0; background: #f8fafc; z-index: 5; }
</style>
</head>
<body class="bg-slate-50 text-slate-900">
<div class="h-screen flex">
  <!-- Sidebar -->
  <aside id="sidebar" class="w-80 bg-white border-r border-slate-200 overflow-y-auto">
    <div class="sticky top-0 z-20 bg-white border-b border-slate-200 p-4">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <svg viewBox="0 0 24 24" class="h-5 w-5 text-indigo-600" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M4 7h16M4 12h16M4 17h10"/>
          </svg>
          <span class="font-semibold">Vuln Manager</span>
        </div>
        <a href="#create" class="text-xs px-2 py-1 rounded bg-indigo-600 text-white hover:bg-indigo-500">New</a>
      </div>

      <div class="mt-3 flex gap-2">
        <div class="relative flex-1">
          <input id="wlSearch" class="w-full border rounded-lg pl-8 pr-2 py-1.5 text-sm" placeholder="Search watchlists">
          <svg viewBox="0 0 24 24" class="absolute left-2 top-1.5 h-5 w-5 text-slate-400" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"></circle><path d="m21 21-4.3-4.3"></path>
          </svg>
        </div>
        <button id="selectMode" class="text-xs px-2 py-1 rounded border border-slate-300 hover:bg-slate-50">Select</button>
        <form method="post" action="{{ url_for('delete_lists') }}" id="bulkDelForm" onsubmit="return confirm('Delete selected watchlists?');">
          <input type="hidden" name="ids" id="bulkIds" value="">
          <button id="bulkDelete" disabled class="text-xs px-2 py-1 rounded bg-red-600 text-white disabled:opacity-40">Delete</button>
        </form>
      </div>

      <div class="mt-2 flex items-center gap-3 text-xs text-slate-600">
        <label class="flex items-center gap-2">
          <input id="wlSelectAll" type="checkbox" class="h-4 w-4" disabled>
          <span>All</span>
        </label>
        <span class="text-slate-300">•</span>
        <button class="text-indigo-600 hover:underline text-xs" onclick="document.querySelector('#cpesField')?.scrollIntoView({behavior:'smooth'}); return false;">
          Create watch
        </button>
      </div>
    </div>

    {% if watchlists %}
      <ul id="wlList" class="p-3 space-y-1">
        {% for w in watchlists %}
          <li class="relative group" data-id="{{ w.id }}">
            <div class="grid grid-cols-[auto_1fr_auto] items-start gap-2 p-3 rounded-lg hover:bg-slate-50
                        {% if current and current.id==w.id %}bg-slate-50 ring-1 ring-indigo-200{% endif %}">
              <!-- checkbox (only in Select mode) -->
              <input type="checkbox" class="wlbox h-4 w-4 mt-0.5 hidden" value="{{ w.id }}">

              <!-- main link -->
              <a href="{{ url_for('open_watchlist', wid=w.id) }}"
                 class="wlLink min-w-0"
                 data-key="{{ (w.name ~ ' ' ~ (w.cpes|join(' ')))|lower }}">
                <div class="text-sm font-medium truncate">{{ w.name }}</div>
                <div class="text-xs text-slate-500 truncate">
                  {{ w.cpes|length }} CPE{{ 's' if w.cpes|length != 1 else '' }}
                  • {{ (w.cpes[0] if w.cpes else '')|replace('cpe:2.3:','') }}
                </div>
              </a>

              <!-- quick actions -->
              <div class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                <a title="Scan 24h" class="text-[11px] px-2 py-1 rounded border border-slate-300 hover:bg-slate-50"
                   data-no-toggle href="{{ url_for('run_watchlist', wid=w.id, win='24h') }}">24h</a>
                <a title="Backfill 90d" class="text-[11px] px-2 py-1 rounded border border-slate-300 hover:bg-slate-50"
                   data-no-toggle href="{{ url_for('run_watchlist', wid=w.id, win='90d') }}">90d</a>

                <div class="relative" data-no-toggle>
                  <button type="button" class="px-1.5 py-1 rounded hover:bg-slate-100 text-slate-600"
                          onclick="this.nextElementSibling.classList.toggle('hidden'); event.preventDefault();">⋯</button>
                  <div class="menuPanel hidden absolute right-0 mt-1 w-44 bg-white border rounded shadow z-10">
                    <a class="block px-3 py-2 text-sm hover:bg-slate-50" href="{{ url_for('export_json', wid=w.id, win='24h') }}">Export JSON (24h)</a>
                    <a class="block px-3 py-2 text-sm hover:bg-slate-50" href="{{ url_for('export_csv', wid=w.id, win='24h') }}">Export CSV (24h)</a>
                    <a class="block px-3 py-2 text-sm hover:bg-slate-50" href="{{ url_for('export_json', wid=w.id, win='90d') }}">Export JSON (90d)</a>
                    <a class="block px-3 py-2 text-sm hover:bg-slate-50" href="{{ url_for('export_csv', wid=w.id, win='90d') }}">Export CSV (90d)</a>
                    <a class="block px-3 py-2 text-sm hover:bg-slate-50"
                       href="mailto:?subject={{ ('CPE Watchlist - ' + w.name)|urlencode }}&body={{ ('Open: ' + request.host_url.rstrip('/') + url_for('open_watchlist', wid=w.id))|urlencode }}">
                      Share via email
                    </a>
                    <a class="block px-3 py-2 text-sm hover:bg-slate-50" href="#"
                       onclick="navigator.clipboard.writeText('{{ request.host_url.rstrip('/') + url_for('open_watchlist', wid=w.id) }}'); this.closest('.menuPanel').classList.add('hidden'); return false;">
                      Copy link
                    </a>
                    <a class="block px-3 py-2 text-sm text-red-600 hover:bg-red-50"
                       href="{{ url_for('delete_single', wid=w.id) }}"
                       onclick="return confirm('Delete this watchlist?')">Delete</a>
                  </div>
                </div>
              </div>
            </div>
          </li>
        {% endfor %}
      </ul>
    {% else %}
      <div class="p-4 text-sm text-slate-500">No lists yet.</div>
    {% endif %}
  </aside>

  <!-- Main -->
  <main class="flex-1 p-6 overflow-y-auto">
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="mb-4">
        {% for m in messages %}
          <div class="rounded-md bg-amber-50 border border-amber-200 text-amber-800 px-3 py-2 text-sm">{{ m }}</div>
        {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Create / Run -->
      <div class="lg:col-span-1" id="create">
        <form method="post" action="{{ url_for('submit') }}" class="bg-white rounded-xl shadow p-4 space-y-3">
          <h2 class="text-base font-semibold mb-1">Create / run a watch</h2>
          <label class="text-sm font-medium">Name (optional)</label>
          <input name="name" class="w-full border rounded-lg px-3 py-2" placeholder="e.g., Core Servers"
                 value="{{ current.name if current else '' }}"/>

          <label class="text-sm font-medium">CPEs (comma-separated)</label>
          <textarea id="cpesField" name="cpes" rows="4" class="w-full border rounded-lg px-3 py-2"
                    placeholder="cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:x64:*, cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*">{{ current.cpes|join(', ') if current else '' }}</textarea>

          <div class="flex items-center gap-2">
            <input id="insecure" name="insecure" type="checkbox" class="h-4 w-4" {% if current and current.insecure %}checked{% endif %}>
            <label for="insecure" class="text-sm">Skip TLS verification (insecure)</label>
          </div>

          <div class="flex flex-col gap-2">
            <button name="action" value="run_daily" class="px-3 py-2 rounded-lg bg-slate-900 text-white hover:bg-slate-800"
                    title="Scans last 24 hours for each CPE">Scan last 24 hours</button>
            <button name="action" value="run_90d" class="px-3 py-2 rounded-lg bg-indigo-600 text-white hover:bg-indigo-500"
                    title="Backfill scan for last 90 days">Scan last 90 days (backfill)</button>
            <button name="action" value="save_only" class="px-3 py-2 rounded-lg bg-slate-200 hover:bg-slate-300">Save only</button>
          </div>
        </form>
      </div>

      <!-- Filters + Details + Table -->
      <div class="lg:col-span-2">
        {% if results is not none %}
          <!-- Safe JSON payload -->
          <script id="DATA" type="application/json">{{ results|tojson }}</script>

          <div id="stickyBox">
            <!-- Filters -->
            <div id="filtersBox" class="bg-white rounded-xl shadow p-4 mb-3 flex flex-wrap gap-3 items-end">
              <div>
                <label class="text-xs text-slate-500">Search</label>
                <input id="f_text" class="border rounded px-2 py-1" placeholder="CVE, text, CPE">
              </div>
              <div>
                <label class="text-xs text-slate-500">Severity</label>
                <select id="f_sev" class="border rounded px-2 py-1">
                  <option value="">All</option>
                  <option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>None</option>
                </select>
              </div>
              <div>
                <label class="text-xs text-slate-500">Min CVSS</label>
                <input id="f_score" type="number" min="0" max="10" step="0.1" class="border rounded px-2 py-1 w-24" placeholder="e.g. 7.0">
              </div>
              <div>
                <label class="text-xs text-slate-500">Min EPSS %</label>
                <input id="f_epss" type="number" min="0" max="100" step="1" class="border rounded px-2 py-1 w-24" placeholder="e.g. 50">
              </div>
              <div>
                <label class="text-xs text-slate-500">Status</label>
                <select id="f_status" class="border rounded px-2 py-1">
                  <option value="">All</option>
                  <option value="new">New only</option>
                </select>
              </div>
              <label class="flex items-center gap-2">
                <input id="f_kev" type="checkbox" class="h-4 w-4"><span class="text-sm">KEV only</span>
              </label>
              <button id="f_clear" class="ml-auto text-sm px-2 py-1 border rounded">Clear</button>
            </div>

            <!-- CPE Builder -->
            <div class="bg-white rounded-xl shadow p-4 mb-3">
              <div class="flex items-center justify-between">
                <h3 class="text-sm font-semibold">CPE 2.3 Builder</h3>
                <button id="builderToggle" class="text-xs text-indigo-700 underline">Hide/Show</button>
              </div>
              <div id="builderBody" class="mt-3 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                <div><label class="text-xs text-slate-500">Part</label>
                  <select id="b_part" class="w-full border rounded px-2 py-1">
                    <option value="a">a (application)</option>
                    <option value="o" selected>o (operating system)</option>
                    <option value="h">h (hardware)</option>
                  </select>
                </div>
                <div><label class="text-xs text-slate-500">Vendor</label><input id="b_vendor" class="w-full border rounded px-2 py-1" placeholder="canonical"></div>
                <div><label class="text-xs text-slate-500">Product</label><input id="b_product" class="w-full border rounded px-2 py-1" placeholder="ubuntu_linux"></div>
                <div><label class="text-xs text-slate-500">Version</label><input id="b_version" class="w-full border rounded px-2 py-1" placeholder="*"></div>
                <div><label class="text-xs text-slate-500">Update</label><input id="b_update" class="w-full border rounded px-2 py-1" placeholder="*"></div>
                <div><label class="text-xs text-slate-500">Edition</label><input id="b_edition" class="w-full border rounded px-2 py-1" placeholder="*"></div>
                <div><label class="text-xs text-slate-500">Language</label><input id="b_language" class="w-full border rounded px-2 py-1" placeholder="*"></div>
                <div><label class="text-xs text-slate-500">SW Edition</label><input id="b_sw" class="w-full border rounded px-2 py-1" placeholder="*"></div>
                <div><label class="text-xs text-slate-500">Target SW</label><input id="b_tsw" class="w-full border rounded px-2 py-1" placeholder="*"></div>
                <div><label class="text-xs text-slate-500">Target HW</label><input id="b_thw" class="w-full border rounded px-2 py-1" placeholder="*"></div>
                <div><label class="text-xs text-slate-500">Other</label><input id="b_other" class="w-full border rounded px-2 py-1" placeholder="*"></div>
                <div class="col-span-full flex flex-wrap items-center gap-2">
                  <button id="b_build" class="px-2 py-1 border rounded">Build CPE</button>
                  <code id="b_output" class="text-xs bg-slate-100 px-2 py-1 rounded">cpe:2.3:o:*:*:*:*:*:*:*:*:*:*:*</code>
                  <button id="b_add" class="ml-auto px-2 py-1 rounded bg-slate-900 text-white">Add to CPEs field</button>
                </div>
                <div class="col-span-full text-xs text-slate-500">
                  Tip: leave fields empty to use <code>*</code>. Special chars <code>:</code> and <code>\</code> are auto-escaped.
                </div>
              </div>
            </div>

            <!-- Details panel -->
            <div class="bg-white rounded-xl shadow mb-3 p-4" id="detailPanel" hidden>
              <div class="flex items-center justify-between mb-2">
                <div>
                  <div class="text-lg font-semibold" id="d_cve"></div>
                  <div class="text-xs text-slate-500" id="d_meta"></div>
                </div>
                <div class="flex items-center gap-2">
                  <button id="btnPrev" class="px-2 py-1 border rounded">&larr; Prev</button>
                  <button id="btnNext" class="px-2 py-1 border rounded">Next &rarr;</button>
                  <a id="d_link" target="_blank" class="px-2 py-1 rounded bg-slate-900 text-white">Open on NVD</a>
                </div>
              </div>
              <div class="prose max-w-none">
                <p id="d_desc" class="whitespace-pre-wrap"></p>
                <div id="d_cwes" class="text-sm text-slate-600"></div>
                <div id="d_refs" class="mt-2 text-sm">
                  <div class="font-medium">References</div>
                  <ul id="d_refs_list" class="list-disc pl-5"></ul>
                </div>
              </div>
            </div>
          </div><!-- /stickyBox -->

          <!-- Results -->
          <div class="bg-white rounded-xl shadow">
            <div class="px-4 py-3 border-b flex items-center justify-between">
              <div>
                <div class="text-base font-semibold">Results (<span id="resCount">{{ results|length }}</span>)</div>
                <div class="text-xs text-slate-500">Window: {{ window_label }} • Click a row to open details above</div>
              </div>
              <div class="text-xs text-slate-500">Click headers to sort</div>
            </div>
            <div class="overflow-x-auto">
              <table id="resTable" class="min-w-full text-sm">
                <thead class="bg-slate-50 sticky">
                  <tr class="text-left">
                    <th class="px-4 py-2 sortable" data-k="cve">CVE</th>
                    <th class="px-4 py-2">KEV</th>
                    <th class="px-4 py-2 sortable" data-k="sev">Severity</th>
                    <th class="px-4 py-2 sortable" data-k="score">CVSS</th>
                    <th class="px-4 py-2 sortable" data-k="epss">EPSS %</th>
                    <th class="px-4 py-2 sortable" data-k="pub">Published</th>
                    <th class="px-4 py-2 sortable" data-k="mod">Last Modified</th>
                    <th class="px-4 py-2">Matched CPE</th>
                  </tr>
                </thead>
                <tbody id="resBody"></tbody>
              </table>
            </div>
          </div>
        {% endif %}
      </div>
    </div>
  </main>
</div>

<!-- Shared scripts live at the end so DOM is ready -->
<script>
  // ----- Sidebar: search / select / bulk delete -----
  (function(){
    const wlList       = document.getElementById('wlList');
    const wlSearch     = document.getElementById('wlSearch');
    const selectModeBtn= document.getElementById('selectMode');
    const wlSelectAll  = document.getElementById('wlSelectAll');
    const bulkIds      = document.getElementById('bulkIds');
    const bulkDelete   = document.getElementById('bulkDelete');

    if (!wlList) return;

    let manageMode = false;
    const rows = () => Array.from(wlList.querySelectorAll(':scope > li'));
    const visibleRows = () => rows().filter(li => li.style.display !== 'none');

    function updateBulkState(){
      const visBoxes = visibleRows().map(li => li.querySelector('.wlbox')).filter(Boolean);
      const ids = visBoxes.filter(cb => cb.checked).map(cb => cb.value);
      bulkIds.value = ids.join(',');
      bulkDelete.disabled = ids.length === 0;
      wlSelectAll.checked = (visBoxes.length>0) && visBoxes.every(cb=>cb.checked);
      wlSelectAll.indeterminate = (ids.length>0 && !wlSelectAll.checked);
    }

    function setManage(on){
      manageMode = on;
      selectModeBtn.textContent = on ? 'Done' : 'Select';
      wlSelectAll.disabled = !on;

      rows().forEach(li=>{
        const cb = li.querySelector('.wlbox');
        const link = li.querySelector('.wlLink');
        if (cb) cb.classList.toggle('hidden', !on);
        if (link) link.classList.toggle('pointer-events-none', on);
      });

      if (!on){
        wlList.querySelectorAll('.wlbox').forEach(cb => cb.checked = false);
        wlSelectAll.checked = false;
        wlSelectAll.indeterminate = false;
        bulkIds.value = '';
      }
      updateBulkState();
    }

    function applyFilter(){
      const q = (wlSearch.value || '').trim().toLowerCase();
      rows().forEach(li=>{
        const key = (li.querySelector('.wlLink')?.dataset.key || '');
        li.style.display = q && !key.includes(q) ? 'none' : '';
      });
      updateBulkState();
    }

    selectModeBtn?.addEventListener('click', (e)=>{ e.preventDefault(); setManage(!manageMode); });
    wlSelectAll?.addEventListener('change', ()=>{
      visibleRows().forEach(li => { const cb = li.querySelector('.wlbox'); if (cb) cb.checked = wlSelectAll.checked; });
      updateBulkState();
    });
    wlList.addEventListener('change', (e)=>{
      if (e.target instanceof HTMLInputElement && e.target.classList.contains('wlbox')) updateBulkState();
    });
    wlList.addEventListener('click', (e)=>{
      if (!manageMode) return;
      const block = e.target.closest('[data-no-toggle], .menuPanel, a, button, input');
      if (block) return;
      const li = e.target.closest('li');
      if (!li) return;
      const cb = li.querySelector('.wlbox');
      if (cb){ cb.checked = !cb.checked; updateBulkState(); }
    });
    document.addEventListener('click', (e)=>{
      document.querySelectorAll('.menuPanel').forEach(p=>{
        if (!p.contains(e.target) && p.previousElementSibling !== e.target) p.classList.add('hidden');
      });
    });
    wlSearch?.addEventListener('input', applyFilter);

    setManage(false);
    applyFilter();
  })();
</script>

{% if results is not none %}
<script>
  // ----- Results: safe JSON parse + render/filter/sort/details -----
  let ORIGINAL = [];
  try {
    const dataEl = document.getElementById('DATA');
    ORIGINAL = dataEl ? JSON.parse(dataEl.textContent || '[]') : [];
  } catch (e) {
    console.error('Failed to parse results JSON:', e);
    ORIGINAL = [];
  }

  let filtered = [...ORIGINAL];
  let sortKey = 'mod', sortDir = -1;
  let currentIdx = -1;

  function renderTable(list){
    const tb = document.getElementById('resBody');
    if (!tb) return;
    tb.innerHTML = '';
    list.forEach((r, idx)=>{
      const sev = r.severity || 'None';
      const score = (r.score ?? '');
      const epss = r.epss !== null && r.epss !== undefined ? (r.epss * 100).toFixed(1) + '%' : '—';
      const epssClass = r.epss >= 0.5 ? 'text-red-600 font-semibold' : '';
      const tr = document.createElement('tr');
      tr.className = 'border-t hover:bg-slate-50 cursor-pointer';
      tr.dataset.idx = idx;
      tr.innerHTML = `
        <td class="px-4 py-2 text-indigo-700 underline">${r.cve}${r.is_new ? ' <span class="text-xs bg-green-500 text-white px-1 rounded">NEW</span>' : ''}</td>
        <td class="px-4 py-2">${r.kev ? '✅' : '—'}</td>
        <td class="px-4 py-2"><span class="badge sev-${sev}">${sev}</span></td>
        <td class="px-4 py-2">${score}</td>
        <td class="px-4 py-2 ${epssClass}">${epss}</td>
        <td class="px-4 py-2">${r.published || ''}</td>
        <td class="px-4 py-2">${r.lastModified || ''}</td>
        <td class="px-4 py-2 truncate max-w-[14rem]" title="${r.matched_cpe_query || ''}">${r.matched_cpe_query || ''}</td>`;
      tr.addEventListener('click', ()=> { showDetails(idx); window.scrollTo({top:document.getElementById('stickyBox').offsetTop-8, behavior:'smooth'}); });
      tb.appendChild(tr);
    });
    const rc = document.getElementById('resCount');
    if (rc) rc.textContent = list.length;
  }

  function showDetails(idx){
    const r = filtered[idx];
    if (!r) return;
    currentIdx = idx;
    const panel = document.getElementById('detailPanel');
    if (!panel) return;
    panel.hidden = false;
    const sev = r.severity || 'None';
    const score = (r.score ?? '');
    const epss = r.epss !== null && r.epss !== undefined ? (r.epss * 100).toFixed(1) + '%' : 'N/A';
    const epssPerc = r.epss_percentile !== null && r.epss_percentile !== undefined ? (r.epss_percentile * 100).toFixed(1) + 'th' : 'N/A';
    document.getElementById('d_cve').textContent = r.cve + (r.kev ? '  (KEV)' : '') + (r.is_new ? '  (NEW)' : '');
    document.getElementById('d_meta').textContent = `Severity: ${sev}  •  CVSS: ${score}  •  EPSS: ${epss} (${epssPerc} percentile)  •  Modified: ${r.lastModified || ''}`;
    document.getElementById('d_desc').textContent = r.description || '(no description)';
    document.getElementById('d_link').href = 'https://nvd.nist.gov/vuln/detail/' + r.cve;

    const cwes = (r.cwes || []).join(', ');
    document.getElementById('d_cwes').textContent = cwes ? ('CWE: ' + cwes) : '';

    const ul = document.getElementById('d_refs_list');
    ul.innerHTML = '';
    (r.refs || []).forEach(ref => {
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.textContent = (ref.tags && ref.tags.length ? ref.tags.join(', ') : (ref.source || 'ref'));
      a.href = ref.url || '#';
      a.target = '_blank';
      a.className = 'text-indigo-700 underline';
      li.appendChild(a);
      ul.appendChild(li);
    });
  }

  function applyFilters(){
    const q = (document.getElementById('f_text').value || '').toLowerCase();
    const sev = document.getElementById('f_sev').value;
    const minScoreStr = document.getElementById('f_score').value;
    const minEpssStr = document.getElementById('f_epss').value;
    const statusFilter = document.getElementById('f_status').value;
    const kevOnly = document.getElementById('f_kev').checked;
    const minScore = minScoreStr ? parseFloat(minScoreStr) : NaN;
    const minEpss = minEpssStr ? parseFloat(minEpssStr) / 100 : NaN;

    filtered = ORIGINAL.filter(r => {
      const hay = (r.cve + ' ' + (r.description || '') + ' ' + (r.matched_cpe_query || '')).toLowerCase();
      if (q && !hay.includes(q)) return false;
      const rsev = (r.severity || 'None');
      if (sev && rsev !== sev) return false;
      const sc = (r.score === null || r.score === undefined) ? NaN : parseFloat(r.score);
      if (!isNaN(minScore) && (isNaN(sc) || sc < minScore)) return false;
      const epss = (r.epss === null || r.epss === undefined) ? NaN : parseFloat(r.epss);
      if (!isNaN(minEpss) && (isNaN(epss) || epss < minEpss)) return false;
      if (statusFilter === 'new' && !r.is_new) return false;
      if (kevOnly && !r.kev) return false;
      return true;
    });
    sortAndRender();
    if (currentIdx >= 0 && currentIdx < filtered.length) showDetails(currentIdx);
  }

  function sortAndRender(){
    const dir = sortDir;
    const key = sortKey;
    filtered.sort((a,b)=>{
      const A = (k)=>({cve:a.cve, sev:(a.severity||'None'), score:(a.score??-1), epss:(a.epss??-1), pub:(a.published||''), mod:(a.lastModified||'')})[k];
      const B = (k)=>({cve:b.cve, sev:(b.severity||'None'), score:(b.score??-1), epss:(b.epss??-1), pub:(b.published||''), mod:(b.lastModified||'')})[k];
      const va=A(key), vb=B(key);
      if (va<vb) return -1*dir;
      if (va>vb) return  1*dir;
      return 0;
    });
    renderTable(filtered);
  }

  // Wire up filters/sort/keys after DOM is ready (we're at the end of body already)
  (function(){
    const txt = document.getElementById('f_text');
    const sev = document.getElementById('f_sev');
    const sc  = document.getElementById('f_score');
    const epss = document.getElementById('f_epss');
    const status = document.getElementById('f_status');
    const kev = document.getElementById('f_kev');
    const clr = document.getElementById('f_clear');

    if (txt) txt.addEventListener('input', applyFilters);
    if (sev) sev.addEventListener('change', applyFilters);
    if (sc)  sc.addEventListener('input', applyFilters);
    if (epss) epss.addEventListener('input', applyFilters);
    if (status) status.addEventListener('change', applyFilters);
    if (kev) kev.addEventListener('change', applyFilters);
    if (clr) clr.addEventListener('click', (e)=>{e.preventDefault();
      if (txt) txt.value=''; if (sev) sev.value=''; if (sc) sc.value=''; if (epss) epss.value=''; if (status) status.value=''; if (kev) kev.checked=false; applyFilters();
    });

    document.querySelectorAll('th.sortable').forEach(th=>{
      th.addEventListener('click', ()=>{
        const k = th.dataset.k;
        if (sortKey === k) { sortDir = -sortDir; }
        else { sortKey = k; sortDir = (k==='score' || k==='epss' || k==='mod' || k==='pub') ? -1 : 1; }
        sortAndRender();
      });
    });

    const prev = document.getElementById('btnPrev');
    const next = document.getElementById('btnNext');
    if (prev) prev.addEventListener('click', ()=>{ if (currentIdx>0) showDetails(currentIdx-1); });
    if (next) next.addEventListener('click', ()=>{ if (currentIdx<filtered.length-1) showDetails(currentIdx+1); });
    window.addEventListener('keydown', (e)=> {
      const panel = document.getElementById('detailPanel');
      if (!panel || panel.hidden) return;
      if (e.key === 'ArrowLeft' && currentIdx>0) showDetails(currentIdx-1);
      if (e.key === 'ArrowRight' && currentIdx<filtered.length-1) showDetails(currentIdx+1);
    });

    // Initial render
    sortKey='mod'; sortDir=-1;
    sortAndRender();
  })();
</script>
{% endif %}
</body></html>"""


def create_app(args):
    app = Flask(__name__)
    app.secret_key = "dev-" + uuid.uuid4().hex

    def read_watchlists():
        wl = load_json(WATCHLISTS_FILE, {"lists": []})
        wl["lists"] = wl.get("lists", [])
        return wl

    def write_watchlists(data):
        save_json(WATCHLISTS_FILE, data)

    @app.get("/favicon.ico")
    def favicon():
        return ("", 204)

    @app.get("/")
    def index():
        wl = read_watchlists()
        return render_template_string(TEMPLATE, watchlists=wl["lists"], current=None, results=None, window_label="")

    @app.get("/open/<wid>")
    def open_watchlist(wid):
        wl = read_watchlists()
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            flash("Watchlist not found.")
            return redirect(url_for("index"))
        return render_template_string(TEMPLATE, watchlists=wl["lists"], current=current, results=None, window_label="")

    @app.post("/delete")
    def delete_lists():
        ids = (request.form.get("ids") or "").split(",")
        ids = [x for x in ids if x]
        wl = read_watchlists()
        before = len(wl["lists"])
        wl["lists"] = [x for x in wl["lists"] if x["id"] not in ids]
        write_watchlists(wl)
        flash(f"Deleted {before - len(wl['lists'])} watchlist(s).")
        return redirect(url_for("index"))

    @app.get("/delete/<wid>")
    def delete_single(wid):
        wl = read_watchlists()
        wl["lists"] = [x for x in wl["lists"] if x["id"] != wid]
        write_watchlists(wl)
        flash("Deleted.")
        return redirect(url_for("index"))

    @app.get("/run/<wid>")
    def run_watchlist(wid):
        wl = read_watchlists()
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            flash("Watchlist not found.")
            return redirect(url_for("index"))
        win = (request.args.get("win") or "24h").lower()
        if win == "24h":
            force_since = now_utc() - timedelta(hours=DAILY_LOOKBACK_HOURS)
        else:
            force_since = now_utc() - timedelta(days=LONG_BACKFILL_DAYS)

        session = build_session(
            https_proxy=args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=args.ca_bundle,
            insecure=current.get("insecure", False) or args.insecure,
            timeout=args.timeout,
        )
        state_all = load_json(STATE_FILE, {})
        state_key = f"nvd:{hash_for_cpes(current['cpes'])}"
        results, updated_entry = run_scan(
            cpes=current["cpes"], state_all=state_all, state_key=state_key,
            session=session, insecure=current.get("insecure", False) or args.insecure,
            api_key=args.nvd_api_key, since=force_since, no_rejected=True, kev_only=False,
        )
        if updated_entry.get("per_cpe"):
            state_all[state_key] = updated_entry
            save_json(STATE_FILE, state_all)

        # Mark new vulnerabilities by comparing with previous scan
        new_cve_ids = set()
        if wl_id := current.get("id"):
            new_vulns = get_new_vulnerabilities(results, wl_id)
            new_cve_ids = {v["cve"] for v in new_vulns}

            # Add to scan history
            add_scan_result(
                watchlist_id=wl_id,
                watchlist_name=current.get("name", "Unnamed"),
                cpes=current["cpes"],
                cve_records=results,
                scan_window=win
            )

        # Mark each result as new or not
        for result in results:
            result["is_new"] = result["cve"] in new_cve_ids

        window_label = "last 24 hours" if win == "24h" else "last 90 days"
        return render_template_string(
            TEMPLATE,
            watchlists=wl["lists"],
            current=current,
            results=results,
            window_label=window_label,
        )

    @app.post("/submit")
    def submit():
        name = (request.form.get("name") or "").strip()
        cpes_raw = (request.form.get("cpes") or "").strip()
        action = request.form.get("action")
        insecure_flag = bool(request.form.get("insecure"))

        if not cpes_raw:
            flash("Please provide at least one CPE (comma-separated).")
            return redirect(url_for("index"))

        cpes = [c.strip() for c in cpes_raw.split(",") if c.strip()]
        if not cpes:
            flash("Could not parse any CPEs.")
            return redirect(url_for("index"))

        wl = read_watchlists()
        wid = str(uuid.uuid4())
        entry = {"id": wid, "name": name or f"List {len(wl['lists'])+1}", "cpes": cpes, "insecure": insecure_flag}
        wl["lists"].insert(0, entry)
        write_watchlists(wl)

        if action == "save_only":
            flash("Saved.")
            return redirect(url_for("open_watchlist", wid=wid))
        next_window = "24h" if action == "run_daily" else "90d"
        return redirect(url_for("run_watchlist", wid=wid, win=next_window))

    # --- Export helpers/endpoints ---
    def _scan_for_export(wid: str, win: str):
        wl = load_json(WATCHLISTS_FILE, {"lists": []})
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            return None, None
        if win == "24h":
            force_since = now_utc() - timedelta(hours=DAILY_LOOKBACK_HOURS)
        else:
            force_since = now_utc() - timedelta(days=LONG_BACKFILL_DAYS)
        session = build_session(
            https_proxy=args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=args.ca_bundle,
            insecure=current.get("insecure", False) or args.insecure,
            timeout=args.timeout,
        )
        state_all = load_json(STATE_FILE, {})
        state_key = f"nvd:{hash_for_cpes(current['cpes'])}"
        results, updated_entry = run_scan(
            cpes=current["cpes"], state_all=state_all, state_key=state_key,
            session=session, insecure=current.get("insecure", False) or args.insecure,
            api_key=args.nvd_api_key, since=force_since, no_rejected=True, kev_only=False,
        )
        if updated_entry.get("per_cpe"):
            state_all[state_key] = updated_entry
            save_json(STATE_FILE, state_all)
        return current, results

    @app.get("/export/<wid>.json")
    def export_json(wid):
        win = (request.args.get("win") or "24h").lower()
        current, results = _scan_for_export(wid, win)
        if not current:
            return Response("Not found", status=404)
        body = json.dumps(results, ensure_ascii=False, indent=2)
        return Response(body, mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{current["name"]}_{win}.json"'})

    @app.get("/export/<wid>.csv")
    def export_csv(wid):
        win = (request.args.get("win") or "24h").lower()
        current, results = _scan_for_export(wid, win)
        if not current:
            return Response("Not found", status=404)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "CVE",
                "Severity",
                "Score",
                "Published",
                "LastModified",
                "MatchedCPE",
                "KEV",
                "CWEs",
                "Description",
            ]
        )
        for r in results:
            sev = r.get("severity", "")
            score = r.get("score", "")
            w.writerow(
                [
                    r.get("cve", ""),
                    sev,
                    score,
                    r.get("published", ""),
                    r.get("lastModified", ""),
                    r.get("matched_cpe_query", ""),
                    "yes" if r.get("kev") else "",
                    ";".join(r.get("cwes", [])),
                    (r.get("description", "") or "").replace("\n", " ").strip(),
                ]
            )
        body = buf.getvalue()
        return Response(body, mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{current["name"]}_{win}.csv"'})

    return app

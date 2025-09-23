(function () {
  document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initResults();
    initCpeBuilder();
  });

  function initSidebar() {
    const wlList = document.getElementById('wlList');
    if (!wlList) {
      return;
    }
    const wlSearch = document.getElementById('wlSearch');
    const selectModeBtn = document.getElementById('selectMode');
    const wlSelectAll = document.getElementById('wlSelectAll');
    const bulkIds = document.getElementById('bulkIds');
    const bulkDelete = document.getElementById('bulkDelete');

    let manageMode = false;
    const rows = () => Array.from(wlList.querySelectorAll(':scope > li'));
    const visibleRows = () => rows().filter((li) => li.style.display !== 'none');

    function updateBulkState() {
      const visBoxes = visibleRows()
        .map((li) => li.querySelector('.wlbox'))
        .filter(Boolean);
      const ids = visBoxes.filter((cb) => cb.checked).map((cb) => cb.value);
      if (bulkIds) {
        bulkIds.value = ids.join(',');
      }
      if (bulkDelete) {
        bulkDelete.disabled = ids.length === 0;
      }
      if (wlSelectAll) {
        wlSelectAll.checked = visBoxes.length > 0 && visBoxes.every((cb) => cb.checked);
        wlSelectAll.indeterminate = ids.length > 0 && !wlSelectAll.checked;
      }
    }

    function setManage(on) {
      manageMode = on;
      if (selectModeBtn) {
        selectModeBtn.textContent = on ? 'Done' : 'Select';
      }
      if (wlSelectAll) {
        wlSelectAll.disabled = !on;
      }

      rows().forEach((li) => {
        const cb = li.querySelector('.wlbox');
        const link = li.querySelector('.wlLink');
        if (cb) {
          cb.classList.toggle('hidden', !on);
          if (!on) {
            cb.checked = false;
          }
        }
        if (link) {
          link.classList.toggle('pointer-events-none', on);
        }
      });

      if (wlSelectAll) {
        wlSelectAll.checked = false;
        wlSelectAll.indeterminate = false;
      }
      if (bulkIds) {
        bulkIds.value = '';
      }
      updateBulkState();
    }

    function applyFilter() {
      const q = (wlSearch?.value || '').trim().toLowerCase();
      rows().forEach((li) => {
        const key = li.querySelector('.wlLink')?.dataset.key || '';
        li.style.display = q && !key.includes(q) ? 'none' : '';
      });
      updateBulkState();
    }

    selectModeBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      setManage(!manageMode);
    });

    wlSelectAll?.addEventListener('change', () => {
      visibleRows().forEach((li) => {
        const cb = li.querySelector('.wlbox');
        if (cb) {
          cb.checked = wlSelectAll.checked;
        }
      });
      updateBulkState();
    });

    wlList.addEventListener('change', (e) => {
      if (e.target instanceof HTMLInputElement && e.target.classList.contains('wlbox')) {
        updateBulkState();
      }
    });

    wlList.addEventListener('click', (e) => {
      if (!(e.target instanceof Element)) {
        return;
      }
      const moreBtn = e.target.closest('.more-btn');
      if (moreBtn) {
        e.preventDefault();
        const panel = moreBtn.nextElementSibling;
        if (panel) {
          panel.classList.toggle('hidden');
        }
        return;
      }

      if (!manageMode) {
        return;
      }
      const block = e.target.closest('[data-no-toggle], .menuPanel, a, button, input');
      if (block) {
        return;
      }
      const li = e.target.closest('li');
      if (!li) {
        return;
      }
      const cb = li.querySelector('.wlbox');
      if (cb) {
        cb.checked = !cb.checked;
        updateBulkState();
      }
    });

    document.addEventListener('click', (e) => {
      if (!(e.target instanceof Element)) {
        return;
      }
      document.querySelectorAll('.menuPanel').forEach((panel) => {
        if (!panel.contains(e.target) && panel.previousElementSibling !== e.target) {
          panel.classList.add('hidden');
        }
      });
    });

    wlSearch?.addEventListener('input', applyFilter);

    setManage(false);
    applyFilter();
  }

  function initResults() {
    const dataEl = document.getElementById('DATA');
    if (!dataEl) {
      return;
    }

    let original = [];
    try {
      original = JSON.parse(dataEl.textContent || '[]');
    } catch (err) {
      console.error('Failed to parse results JSON', err);
      original = [];
    }

    if (!Array.isArray(original)) {
      original = [];
    }

    let filtered = [...original];
    let sortKey = 'mod';
    let sortDir = -1;
    let currentIdx = -1;

    const resBody = document.getElementById('resBody');
    const resCount = document.getElementById('resCount');
    const detailPanel = document.getElementById('detailPanel');

    function renderTable(list) {
      if (!resBody) {
        return;
      }
      resBody.innerHTML = '';
      list.forEach((r, idx) => {
        const sev = r.severity || 'None';
        const score = r.score ?? '';
        const tr = document.createElement('tr');
        tr.className = 'border-t hover:bg-slate-50 cursor-pointer';
        tr.dataset.idx = String(idx);
        tr.innerHTML = `
          <td class="px-4 py-2 text-indigo-700 underline">${r.cve}</td>
          <td class="px-4 py-2">${r.kev ? '✅' : '—'}</td>
          <td class="px-4 py-2"><span class="badge sev-${sev}">${sev}</span></td>
          <td class="px-4 py-2">${score}</td>
          <td class="px-4 py-2">${r.published || ''}</td>
          <td class="px-4 py-2">${r.lastModified || ''}</td>
          <td class="px-4 py-2 truncate max-w-[14rem]" title="${r.matched_cpe_query || ''}">${r.matched_cpe_query || ''}</td>`;
        tr.addEventListener('click', () => {
          showDetails(idx);
          const sticky = document.getElementById('stickyBox');
          if (sticky) {
            window.scrollTo({ top: sticky.offsetTop - 8, behavior: 'smooth' });
          }
        });
        resBody.appendChild(tr);
      });
      if (resCount) {
        resCount.textContent = String(list.length);
      }
    }

    function showDetails(idx) {
      const r = filtered[idx];
      if (!r || !detailPanel) {
        return;
      }
      currentIdx = idx;
      detailPanel.hidden = false;
      const sev = r.severity || 'None';
      const score = r.score ?? '';
      const desc = r.description || '(no description)';
      const cwes = Array.isArray(r.cwes) ? r.cwes.join(', ') : '';

      const cveEl = document.getElementById('d_cve');
      const metaEl = document.getElementById('d_meta');
      const descEl = document.getElementById('d_desc');
      const cwesEl = document.getElementById('d_cwes');
      const linkEl = document.getElementById('d_link');
      const refsList = document.getElementById('d_refs_list');

      if (cveEl) {
        cveEl.textContent = r.cve + (r.kev ? ' (KEV)' : '');
      }
      if (metaEl) {
        metaEl.textContent = `Severity: ${sev} • Score: ${score} • Modified: ${r.lastModified || ''}`;
      }
      if (descEl) {
        descEl.textContent = desc;
      }
      if (cwesEl) {
        cwesEl.textContent = cwes ? `CWE: ${cwes}` : '';
      }
      if (linkEl) {
        linkEl.href = 'https://nvd.nist.gov/vuln/detail/' + r.cve;
      }
      if (refsList) {
        refsList.innerHTML = '';
        (r.refs || []).forEach((ref) => {
          const li = document.createElement('li');
          const a = document.createElement('a');
          const label = ref.tags && ref.tags.length ? ref.tags.join(', ') : ref.source || 'ref';
          a.textContent = label;
          a.href = ref.url || '#';
          a.target = '_blank';
          a.className = 'text-indigo-700 underline';
          li.appendChild(a);
          refsList.appendChild(li);
        });
      }
    }

    function applyFilters() {
      const q = (document.getElementById('f_text')?.value || '').toLowerCase();
      const sev = document.getElementById('f_sev')?.value || '';
      const minScoreStr = document.getElementById('f_score')?.value || '';
      const kevOnly = document.getElementById('f_kev')?.checked || false;
      const minScore = minScoreStr ? parseFloat(minScoreStr) : NaN;

      filtered = original.filter((r) => {
        const hay = (r.cve + ' ' + (r.description || '') + ' ' + (r.matched_cpe_query || '')).toLowerCase();
        if (q && !hay.includes(q)) {
          return false;
        }
        const rsev = r.severity || 'None';
        if (sev && rsev !== sev) {
          return false;
        }
        const sc = r.score === null || r.score === undefined ? NaN : parseFloat(r.score);
        if (!Number.isNaN(minScore) && (Number.isNaN(sc) || sc < minScore)) {
          return false;
        }
        if (kevOnly && !r.kev) {
          return false;
        }
        return true;
      });
      sortAndRender();
      if (currentIdx >= 0 && currentIdx < filtered.length) {
        showDetails(currentIdx);
      }
    }

    function sortAndRender() {
      const key = sortKey;
      const dir = sortDir;
      const accessors = {
        cve: (item) => item.cve,
        sev: (item) => item.severity || 'None',
        score: (item) => (item.score === null || item.score === undefined ? -1 : parseFloat(item.score)),
        pub: (item) => item.published || '',
        mod: (item) => item.lastModified || '',
      };
      filtered.sort((a, b) => {
        const va = accessors[key](a);
        const vb = accessors[key](b);
        if (va < vb) {
          return -1 * dir;
        }
        if (va > vb) {
          return 1 * dir;
        }
        return 0;
      });
      renderTable(filtered);
    }

    const txt = document.getElementById('f_text');
    const sevSelect = document.getElementById('f_sev');
    const scoreInput = document.getElementById('f_score');
    const kevInput = document.getElementById('f_kev');
    const clearBtn = document.getElementById('f_clear');

    txt?.addEventListener('input', applyFilters);
    sevSelect?.addEventListener('change', applyFilters);
    scoreInput?.addEventListener('input', applyFilters);
    kevInput?.addEventListener('change', applyFilters);
    clearBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      if (txt) txt.value = '';
      if (sevSelect) sevSelect.value = '';
      if (scoreInput) scoreInput.value = '';
      if (kevInput) kevInput.checked = false;
      applyFilters();
    });

    document.querySelectorAll('th.sortable').forEach((th) => {
      th.addEventListener('click', () => {
        const k = th.dataset.k;
        if (!k) {
          return;
        }
        if (sortKey === k) {
          sortDir = -sortDir;
        } else {
          sortKey = k;
          sortDir = k === 'score' || k === 'mod' || k === 'pub' ? -1 : 1;
        }
        sortAndRender();
      });
    });

    document.getElementById('btnPrev')?.addEventListener('click', () => {
      if (currentIdx > 0) {
        showDetails(currentIdx - 1);
      }
    });
    document.getElementById('btnNext')?.addEventListener('click', () => {
      if (currentIdx < filtered.length - 1) {
        showDetails(currentIdx + 1);
      }
    });

    window.addEventListener('keydown', (e) => {
      if (!detailPanel || detailPanel.hidden) {
        return;
      }
      if (e.key === 'ArrowLeft' && currentIdx > 0) {
        showDetails(currentIdx - 1);
      }
      if (e.key === 'ArrowRight' && currentIdx < filtered.length - 1) {
        showDetails(currentIdx + 1);
      }
    });

    sortAndRender();
  }

  function initCpeBuilder() {
    const body = document.getElementById('builderBody');
    if (!body) {
      return;
    }
    const toggle = document.getElementById('builderToggle');
    const output = document.getElementById('b_output');
    const addBtn = document.getElementById('b_add');
    const buildBtn = document.getElementById('b_build');
    const cpesField = document.getElementById('cpesField');

    const fieldIds = [
      'b_part',
      'b_vendor',
      'b_product',
      'b_version',
      'b_update',
      'b_edition',
      'b_language',
      'b_sw',
      'b_tsw',
      'b_thw',
      'b_other',
    ];

    function escapeSegment(value) {
      if (!value) {
        return '*';
      }
      return value.replace(/\\/g, '\\\\').replace(/:/g, '\\:');
    }

    function buildCpe() {
      const values = fieldIds.map((id) => {
        const el = document.getElementById(id);
        if (!el) {
          return '*';
        }
        const raw = 'value' in el ? el.value : '';
        return escapeSegment(raw.trim());
      });
      const part = values.shift() || 'o';
      return `cpe:2.3:${part}:${values.join(':')}`;
    }

    function updateOutput() {
      if (output) {
        output.textContent = buildCpe();
      }
    }

    toggle?.addEventListener('click', (e) => {
      e.preventDefault();
      body.classList.toggle('hidden');
      if (toggle) {
        toggle.textContent = body.classList.contains('hidden') ? 'Show' : 'Hide';
      }
    });

    buildBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      updateOutput();
    });

    addBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      updateOutput();
      if (!output || !cpesField) {
        return;
      }
      const cpe = output.textContent.trim();
      if (!cpe) {
        return;
      }
      const current = cpesField.value.trim();
      cpesField.value = current ? `${current.replace(/\s*$/, '')}, ${cpe}` : cpe;
      cpesField.dispatchEvent(new Event('input', { bubbles: true }));
    });

    fieldIds.forEach((id) => {
      document.getElementById(id)?.addEventListener('input', () => {
        updateOutput();
      });
    });

    updateOutput();
  }
})();

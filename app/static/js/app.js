/**
 * CPExVTOPS - Vulnerability Management System
 * Frontend Application Logic
 */
(function () {
  document.addEventListener('DOMContentLoaded', () => {
    const bootstrap = parseBootstrap();
    const app = createApp(bootstrap);
    app.init();
  });

  function parseBootstrap() {
    try {
      const node = document.getElementById('BOOTSTRAP');
      return node ? JSON.parse(node.textContent || '{}') : {};
    } catch (err) {
      console.error('Failed to parse bootstrap payload', err);
      return {};
    }
  }

  function createApp(bootstrap) {
    const csrfToken = bootstrap.csrfToken || document.querySelector('meta[name="csrf-token"]')?.content || '';
    const collapsedKey = 'cpexvtops-collapsed-projects';
    const settingsKey = 'cpexvtops-settings';
    const mitigatedKey = 'cpexvtops-mitigated';

    // Load persisted state
    const collapsedInitial = new Set();
    try {
      const stored = window.localStorage.getItem(collapsedKey);
      if (stored) JSON.parse(stored).forEach((id) => collapsedInitial.add(id));
    } catch (err) {
      console.warn('Unable to read collapsed state', err);
    }

    // Load mitigated CVEs
    let mitigatedCves = new Set();
    try {
      const stored = window.localStorage.getItem(mitigatedKey);
      if (stored) JSON.parse(stored).forEach((id) => mitigatedCves.add(id));
    } catch (err) {
      console.warn('Unable to read mitigated state', err);
    }

    // Load settings
    let settings = {
      scanTimes: '07:30,12:30,16:00,19:30',
      cvssThreshold: 0,
      epssThreshold: 0,
      autoRefresh: false,
    };
    try {
      const stored = window.localStorage.getItem(settingsKey);
      if (stored) settings = { ...settings, ...JSON.parse(stored) };
    } catch (err) {
      console.warn('Unable to read settings', err);
    }

    const state = {
      projects: bootstrap.projects || [],
      lists: bootstrap.lists || [],
      currentWatchId: bootstrap.currentWatchId || null,
      originalResults: bootstrap.results || [],
      filteredResults: [],
      windowLabel: bootstrap.windowLabel || '',
      initialIssues: bootstrap.issues || [],
      filters: {
        cve: '',
        text: '',
        epss: '',
        score: '',
        kev: '',
        dateFilter: 'custom',
        showAll: false,
        showMitigated: false,
        showNew: true,
      },
      sortKey: 'pub',
      sortDir: -1,
      detailIndex: -1,
      manageMode: false,
      selectedIds: new Set(),
      collapsed: collapsedInitial,
      pendingRun: false,
      cpeList: [],
      scheduleIntervals: settings.scanTimes.split(',').filter(Boolean),
      scanPeriod: '7d',
      currentPage: 1,
      pageSize: 25,
    };

    // DOM references
    const dom = {
      alerts: document.getElementById('alerts'),
      projectsContainer: document.getElementById('projectsContainer'),
      searchInput: document.getElementById('wlSearch'),
      selectModeBtn: document.getElementById('selectMode'),
      selectAllBox: document.getElementById('wlSelectAll'),
      selectedCount: document.getElementById('selectedCount'),
      deleteSelectedBtn: document.getElementById('btnDeleteSelected'),
      newWatchBtn: document.getElementById('btnNewWatch'),
      newProjectBtn: document.getElementById('btnNewProject'),

      // CPE Builder
      builderToggle: document.getElementById('builderToggle'),
      builderBody: document.getElementById('builderBody'),
      builderOutput: document.getElementById('b_output'),
      builderSuggestions: document.getElementById('builderSuggestions'),
      cpeList: document.getElementById('cpeList'),
      manualCpeInput: document.getElementById('manualCpeInput'),
      btnAddManualCpe: document.getElementById('btnAddManualCpe'),
      btnAddCpe: document.getElementById('b_add'),

      // Schedule
      scheduleIntervals: document.getElementById('scheduleIntervals'),
      btnAddInterval: document.getElementById('btnAddInterval'),
      scanFromDate: document.getElementById('scanFromDate'),
      scanToDate: document.getElementById('scanToDate'),
      btnSaveAndScan: document.getElementById('btnSaveAndScan'),

      // Form
      form: document.getElementById('watchForm'),
      formId: document.getElementById('formWatchId'),
      formTitle: document.getElementById('formTitle'),
      formProjectLabel: document.getElementById('formProjectLabel'),
      formProject: document.getElementById('formProject'),
      formName: document.getElementById('formName'),
      formCpes: document.getElementById('formCpes'),
      formComments: document.getElementById('formComments'),
      optNoRejected: document.getElementById('optNoRejected'),
      optIsVulnerable: document.getElementById('optIsVulnerable'),
      optHasKev: document.getElementById('optHasKev'),
      optInsecure: document.getElementById('optInsecure'),
      optHttpProxy: document.getElementById('optHttpProxy'),
      optHttpsProxy: document.getElementById('optHttpsProxy'),
      optCaBundle: document.getElementById('optCaBundle'),
      optTimeout: document.getElementById('optTimeout'),
      formWarnings: document.getElementById('formWarnings'),
      btnSaveWatch: document.getElementById('btnSaveWatch'),
      btnDeleteWatch: document.getElementById('btnDeleteWatch'),

      // Filters
      filterCve: document.getElementById('f_cve'),
      filterText: document.getElementById('f_text'),
      filterEpss: document.getElementById('f_epss'),
      filterScore: document.getElementById('f_score'),
      filterKev: document.getElementById('f_kev'),
      btnFilter: document.getElementById('btnFilter'),
      filterClear: document.getElementById('f_clear'),
      filterAll: document.getElementById('f_all'),
      filterMitigated: document.getElementById('f_mitigated'),
      filterNew: document.getElementById('f_new'),

      // Results
      windowLabel: document.getElementById('windowLabel'),
      resCount: document.getElementById('resCount'),
      resBody: document.getElementById('resBody'),
      btnExportCsv: document.getElementById('btnExportCsv'),
      btnExportNdjson: document.getElementById('btnExportNdjson'),

      // Pagination
      btnPrevPage: document.getElementById('btnPrevPage'),
      btnNextPage: document.getElementById('btnNextPage'),
      pageInfo: document.getElementById('pageInfo'),

      // Detail panel
      detailPanel: document.getElementById('detailPanel'),
      detailCve: document.getElementById('d_cve'),
      detailMeta: document.getElementById('d_meta'),
      detailMatched: document.getElementById('d_matched'),
      detailDesc: document.getElementById('d_desc'),
      detailCwes: document.getElementById('d_cwes'),
      detailKev: document.getElementById('d_kev'),
      detailKevDetails: document.getElementById('d_kev_details'),
      detailRefs: document.getElementById('d_refs_list'),
      btnPrev: document.getElementById('btnPrev'),
      btnNext: document.getElementById('btnNext'),
      btnCopyJson: document.getElementById('btnCopyJson'),
      btnMarkMitigated: document.getElementById('btnMarkMitigated'),
      linkNvd: document.getElementById('d_link'),

      // Settings modal
      settingsModal: document.getElementById('settingsModal'),
      btnSettings: document.getElementById('btnSettings'),
      btnCloseSettings: document.getElementById('btnCloseSettings'),
      btnCancelSettings: document.getElementById('btnCancelSettings'),
      btnSaveSettings: document.getElementById('btnSaveSettings'),
      settingScanTimes: document.getElementById('settingScanTimes'),
      settingCvssThreshold: document.getElementById('settingCvssThreshold'),
      settingEpssThreshold: document.getElementById('settingEpssThreshold'),
      settingAutoRefresh: document.getElementById('settingAutoRefresh'),

      // Interval modal
      intervalModal: document.getElementById('intervalModal'),
      btnCloseInterval: document.getElementById('btnCloseInterval'),
      btnCancelInterval: document.getElementById('btnCancelInterval'),
      btnConfirmInterval: document.getElementById('btnConfirmInterval'),
      intervalTime: document.getElementById('intervalTime'),
    };

    const builderFields = [
      'b_part', 'b_vendor', 'b_product', 'b_version', 'b_update',
      'b_edition', 'b_language', 'b_sw', 'b_tsw', 'b_thw', 'b_other',
    ].map((id) => document.getElementById(id));

    // API functions
    const api = {
      async getWatchlists() {
        const data = await requestJson('/api/watchlists');
        state.projects = data.projects || [];
        state.lists = data.lists || [];
        renderSidebar();
        populateProjectSelect();
      },
      async createProject(name) {
        return requestJson('/api/projects', { method: 'POST', body: { name } });
      },
      async renameProject(id, name) {
        return requestJson(`/api/projects/${id}`, { method: 'PATCH', body: { name } });
      },
      async deleteProject(id) {
        return requestJson(`/api/projects/${id}`, { method: 'DELETE' });
      },
      async createWatchlist(payload) {
        return requestJson('/api/watchlists', { method: 'POST', body: payload });
      },
      async updateWatchlist(id, payload) {
        return requestJson(`/api/watchlists/${id}`, { method: 'PUT', body: payload });
      },
      async deleteWatchlist(id) {
        return requestJson(`/api/watchlists/${id}`, { method: 'DELETE' });
      },
      async runWatchlist(id, window) {
        return requestJson('/api/run', { method: 'POST', body: { watchlistId: id, window } });
      },
      async suggestCpe(params) {
        const qs = new URLSearchParams(params);
        return requestJson(`/api/cpe_suggest?${qs.toString()}`);
      },
    };

    async function requestJson(url, options = {}) {
      const opts = { method: 'GET', headers: { 'X-CSRF-Token': csrfToken } };
      if (options.method) opts.method = options.method;
      if (options.body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(options.body);
      }
      try {
        const res = await fetch(url, opts);
        const text = await res.text();
        let data = {};
        if (text) {
          try { data = JSON.parse(text); } catch (err) { data = {}; }
        }
        if (!res.ok) {
          const message = (data && (data.error || data.message)) || text || res.statusText || 'Request failed';
          const error = new Error(message);
          error.status = res.status;
          throw error;
        }
        return data;
      } catch (err) {
        showAlert(err.message || 'Request failed', 'error');
        throw err;
      }
    }

    // Utility functions
    function showAlert(message, level = 'info', timeout = 5000) {
      if (!dom.alerts) return;
      const box = document.createElement('div');
      box.className = `flash flash--${level}`;
      box.textContent = message;
      dom.alerts.appendChild(box);
      if (timeout) setTimeout(() => box.remove(), timeout);
    }

    function saveCollapsed() {
      try {
        window.localStorage.setItem(collapsedKey, JSON.stringify(Array.from(state.collapsed)));
      } catch (err) {
        console.warn('Unable to persist collapsed state', err);
      }
    }

    function saveMitigated() {
      try {
        window.localStorage.setItem(mitigatedKey, JSON.stringify(Array.from(mitigatedCves)));
      } catch (err) {
        console.warn('Unable to persist mitigated state', err);
      }
    }

    function saveSettings() {
      try {
        window.localStorage.setItem(settingsKey, JSON.stringify(settings));
      } catch (err) {
        console.warn('Unable to persist settings', err);
      }
    }

    function findWatchlist(id) {
      return state.lists.find((w) => w.id === id) || null;
    }

    function sortedListsFor(projectId) {
      return state.lists
        .filter((w) => w.projectId === projectId)
        .sort((a, b) => (a.order || 0) - (b.order || 0));
    }

    // Sidebar rendering with team cards
    function renderSidebar() {
      if (!dom.projectsContainer) return;
      dom.projectsContainer.innerHTML = '';

      state.projects.slice().sort((a, b) => (a.order || 0) - (b.order || 0)).forEach((project) => {
        const wrapper = document.createElement('section');
        wrapper.className = 'team-card' + (state.currentWatchId && findWatchlist(state.currentWatchId)?.projectId === project.id ? ' team-card--active' : '');
        wrapper.dataset.projectId = project.id;

        const header = document.createElement('div');
        header.className = 'team-card__header';

        // Checkbox for selection
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = `h-4 w-4 ${state.manageMode ? '' : 'hidden'}`;
        checkbox.checked = state.selectedIds.has(project.id);
        checkbox.addEventListener('change', () => {
          if (checkbox.checked) state.selectedIds.add(project.id);
          else state.selectedIds.delete(project.id);
          updateBulkState();
        });

        // Play button
        const playBtn = document.createElement('button');
        playBtn.className = 'team-card__action team-card__action--play';
        playBtn.innerHTML = '<svg viewBox="0 0 24 24" class="h-4 w-4" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>';
        playBtn.title = 'Run scan';
        playBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const lists = sortedListsFor(project.id);
          if (lists.length > 0) {
            selectWatchlist(lists[0].id, true, state.scanPeriod === 'custom' ? '24h' : state.scanPeriod);
          }
        });

        // Team name
        const nameEl = document.createElement('span');
        nameEl.className = 'font-semibold flex-1 truncate cursor-pointer';
        nameEl.textContent = project.name;
        nameEl.addEventListener('click', () => {
          if (state.collapsed.has(project.id)) {
            state.collapsed.delete(project.id);
          } else {
            state.collapsed.add(project.id);
          }
          saveCollapsed();
          renderSidebar();
        });

        // Edit button
        const editBtn = document.createElement('button');
        editBtn.className = 'team-card__action';
        editBtn.innerHTML = '<svg viewBox="0 0 24 24" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
        editBtn.title = 'Edit team';
        editBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const newName = prompt('Team name', project.name);
          if (newName && newName !== project.name) {
            api.renameProject(project.id, newName).then(() => api.getWatchlists());
          }
        });

        // Delete button
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'team-card__action team-card__action--delete';
        deleteBtn.innerHTML = '<svg viewBox="0 0 24 24" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
        deleteBtn.title = 'Delete team';
        deleteBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (confirm('Delete this team? Teams must be empty.')) {
            api.deleteProject(project.id).then(() => api.getWatchlists());
          }
        });

        header.appendChild(checkbox);
        header.appendChild(playBtn);
        header.appendChild(nameEl);
        header.appendChild(editBtn);
        header.appendChild(deleteBtn);
        wrapper.appendChild(header);

        // CPE list (collapsible)
        if (!state.collapsed.has(project.id)) {
          const lists = sortedListsFor(project.id);
          const cpeContainer = document.createElement('div');
          cpeContainer.className = 'mt-2 space-y-1';

          lists.forEach((watch) => {
            watch.cpes.forEach((cpe, idx) => {
              if (idx < 3) { // Show max 3 CPEs
                const cpeEl = document.createElement('div');
                cpeEl.className = 'cpe-item';
                cpeEl.innerHTML = `
                  <span class="cpe-item__name" title="${cpe}">${cpe.replace('cpe:2.3:', '')}</span>
                  <span class="cpe-item__status cpe-item__status--ok"></span>
                `;
                cpeEl.addEventListener('click', () => selectWatchlist(watch.id, false));
                cpeContainer.appendChild(cpeEl);
              }
            });
            if (watch.cpes.length > 3) {
              const moreEl = document.createElement('div');
              moreEl.className = 'text-xs text-slate-400 pl-2';
              moreEl.textContent = `+${watch.cpes.length - 3} more...`;
              cpeContainer.appendChild(moreEl);
            }
          });

          // Scheduled scans display
          if (state.scheduleIntervals.length > 0) {
            const schedDiv = document.createElement('div');
            schedDiv.className = 'scheduled-scans';
            schedDiv.innerHTML = '<div class="text-xs font-medium text-slate-500 mb-1">Scheduled:</div>';
            state.scheduleIntervals.slice(0, 4).forEach((time, idx) => {
              const scanEl = document.createElement('div');
              scanEl.className = 'scheduled-scan';
              scanEl.innerHTML = `
                <span>Scan ${idx + 1}</span>
                <span class="scheduled-scan__time">${time}</span>
              `;
              schedDiv.appendChild(scanEl);
            });
            cpeContainer.appendChild(schedDiv);
          }

          // Comments preview
          const watch = lists[0];
          if (watch?.comments) {
            const commentDiv = document.createElement('div');
            commentDiv.className = 'mt-2 p-2 bg-slate-50 rounded text-xs text-slate-600';
            commentDiv.textContent = watch.comments.substring(0, 100) + (watch.comments.length > 100 ? '...' : '');
            cpeContainer.appendChild(commentDiv);
          }

          wrapper.appendChild(cpeContainer);
        }

        dom.projectsContainer.appendChild(wrapper);
      });

      updateBulkState();
    }

    function populateProjectSelect() {
      if (!dom.formProject) return;
      dom.formProject.innerHTML = '';
      state.projects.slice().sort((a, b) => (a.order || 0) - (b.order || 0)).forEach((project) => {
        const option = document.createElement('option');
        option.value = project.id;
        option.textContent = project.name;
        dom.formProject.appendChild(option);
      });
    }

    function selectWatchlist(id, runImmediately = false, window = '24h') {
      state.currentWatchId = id;
      state.detailIndex = -1;
      state.selectedIds.clear();
      const watch = findWatchlist(id);
      if (!watch) {
        clearForm();
        renderSidebar();
        return;
      }
      fillForm(watch);
      renderSidebar();
      updateBulkState();
      if (runImmediately) runCurrent(window);
    }

    function clearForm() {
      if (dom.formId) dom.formId.value = '';
      if (dom.formTitle) dom.formTitle.textContent = 'Create team';
      if (dom.formProjectLabel) dom.formProjectLabel.textContent = '';
      if (dom.formName) dom.formName.value = '';
      if (dom.formCpes) dom.formCpes.value = '';
      if (dom.formComments) dom.formComments.value = '';
      if (dom.optNoRejected) dom.optNoRejected.checked = true;
      if (dom.optIsVulnerable) dom.optIsVulnerable.checked = false;
      if (dom.optHasKev) dom.optHasKev.checked = false;
      if (dom.optInsecure) dom.optInsecure.checked = false;
      if (dom.optHttpProxy) dom.optHttpProxy.value = '';
      if (dom.optHttpsProxy) dom.optHttpsProxy.value = '';
      if (dom.optCaBundle) dom.optCaBundle.value = '';
      if (dom.optTimeout) dom.optTimeout.value = '';
      if (dom.formWarnings) dom.formWarnings.textContent = '';
      state.cpeList = [];
      renderCpeList();
    }

    function fillForm(watch) {
      if (dom.formId) dom.formId.value = watch.id;
      if (dom.formTitle) dom.formTitle.textContent = 'Edit team';
      const project = state.projects.find((p) => p.id === watch.projectId);
      if (dom.formProjectLabel) dom.formProjectLabel.textContent = project ? project.name : '';
      if (dom.formProject) dom.formProject.value = watch.projectId;
      if (dom.formName) dom.formName.value = watch.name || '';
      if (dom.formCpes) dom.formCpes.value = watch.cpes.join(', ');
      if (dom.formComments) dom.formComments.value = watch.comments || '';
      const options = watch.options || {};
      if (dom.optNoRejected) dom.optNoRejected.checked = options.noRejected !== false;
      if (dom.optIsVulnerable) dom.optIsVulnerable.checked = Boolean(options.isVulnerable);
      if (dom.optHasKev) dom.optHasKev.checked = Boolean(options.hasKev);
      if (dom.optInsecure) dom.optInsecure.checked = Boolean(options.insecure);
      if (dom.optHttpProxy) dom.optHttpProxy.value = options.httpProxy || '';
      if (dom.optHttpsProxy) dom.optHttpsProxy.value = options.httpsProxy || '';
      if (dom.optCaBundle) dom.optCaBundle.value = options.caBundle || '';
      if (dom.optTimeout) dom.optTimeout.value = options.timeout || '';
      state.cpeList = [...watch.cpes];
      renderCpeList();
    }

    function gatherFormData() {
      return {
        name: dom.formName?.value || '',
        projectId: dom.formProject?.value || '',
        cpes: state.cpeList.length > 0 ? state.cpeList.join(', ') : (dom.formCpes?.value || ''),
        comments: dom.formComments?.value || '',
        options: {
          noRejected: dom.optNoRejected?.checked,
          isVulnerable: dom.optIsVulnerable?.checked,
          hasKev: dom.optHasKev?.checked,
          insecure: dom.optInsecure?.checked,
          httpProxy: dom.optHttpProxy?.value || null,
          httpsProxy: dom.optHttpsProxy?.value || null,
          caBundle: dom.optCaBundle?.value || null,
          timeout: dom.optTimeout?.value || null,
        },
      };
    }

    async function saveWatchlist() {
      const payload = gatherFormData();
      const watchId = dom.formId?.value;
      try {
        let response;
        if (watchId) {
          response = await api.updateWatchlist(watchId, payload);
        } else {
          response = await api.createWatchlist(payload);
          state.currentWatchId = response.watchlist?.id || null;
        }
        if (response?.watchlist) {
          const idx = state.lists.findIndex((w) => w.id === response.watchlist.id);
          if (idx >= 0) state.lists[idx] = response.watchlist;
          else state.lists.push(response.watchlist);
          renderSidebar();
          populateProjectSelect();
          fillForm(response.watchlist);
          showAlert('Team saved.', 'success', 2000);
        }
      } catch (err) {
        console.error('Save failed', err);
      }
    }

    async function deleteCurrentWatch() {
      const watchId = dom.formId?.value;
      if (!watchId) { clearForm(); return; }
      if (!confirm('Delete this team?')) return;
      try {
        await api.deleteWatchlist(watchId);
        state.lists = state.lists.filter((w) => w.id !== watchId);
        state.currentWatchId = null;
        clearForm();
        renderSidebar();
        showAlert('Team deleted.', 'success', 2000);
      } catch (err) {
        console.error('Delete failed', err);
      }
    }

    async function runCurrent(window) {
      if (state.pendingRun) return;
      const watchId = dom.formId?.value;
      if (!watchId) await saveWatchlist();
      const id = dom.formId?.value;
      if (!id) {
        showAlert('Save the team before running.', 'error');
        return;
      }
      state.pendingRun = true;
      showAlert('Scanning...', 'info', 2000);
      try {
        const result = await api.runWatchlist(id, window);
        state.originalResults = result.results || [];
        state.windowLabel = result.windowLabel || '';
        applyFilters();
        showAlert(`Fetched ${state.originalResults.length} CVEs.`, 'success', 2000);
        if (dom.windowLabel) dom.windowLabel.textContent = `Window: ${state.windowLabel || '-'}`;
      } catch (err) {
        console.error('Run failed', err);
      } finally {
        state.pendingRun = false;
      }
    }

    // CPE List management
    function renderCpeList() {
      if (!dom.cpeList) return;
      if (state.cpeList.length === 0) {
        dom.cpeList.innerHTML = '<div class="text-xs text-slate-400 italic">No CPEs added yet</div>';
        return;
      }
      dom.cpeList.innerHTML = '';
      state.cpeList.forEach((cpe, idx) => {
        const item = document.createElement('div');
        item.className = 'cpe-list-item';
        item.innerHTML = `
          <span class="truncate" title="${cpe}">${cpe}</span>
          <button class="cpe-list-item__remove" data-idx="${idx}">&times;</button>
        `;
        item.querySelector('button').addEventListener('click', () => {
          state.cpeList.splice(idx, 1);
          renderCpeList();
          updateFormCpes();
        });
        dom.cpeList.appendChild(item);
      });
    }

    function updateFormCpes() {
      if (dom.formCpes) dom.formCpes.value = state.cpeList.join(', ');
    }

    function addCpeToList(cpe) {
      if (!cpe || state.cpeList.includes(cpe)) return;
      state.cpeList.push(cpe);
      renderCpeList();
      updateFormCpes();
    }

    // Schedule management
    function renderScheduleIntervals() {
      if (!dom.scheduleIntervals) return;
      dom.scheduleIntervals.innerHTML = '';
      state.scheduleIntervals.forEach((time, idx) => {
        const item = document.createElement('div');
        item.className = 'interval-item';
        item.innerHTML = `
          <span class="interval-item__time">${time}</span>
          <span class="text-xs text-slate-500">Daily</span>
          <div class="interval-item__actions">
            <button class="interval-item__action" title="Edit">
              <svg viewBox="0 0 24 24" class="h-3 w-3" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            </button>
            <button class="interval-item__action interval-item__action--delete" title="Delete" data-idx="${idx}">
              <svg viewBox="0 0 24 24" class="h-3 w-3" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            </button>
          </div>
        `;
        item.querySelector('.interval-item__action--delete').addEventListener('click', () => {
          state.scheduleIntervals.splice(idx, 1);
          renderScheduleIntervals();
        });
        dom.scheduleIntervals.appendChild(item);
      });
    }

    // Filtering
    function applyFilters() {
      const cveFilter = (dom.filterCve?.value || '').toLowerCase();
      const textFilter = (dom.filterText?.value || '').toLowerCase();
      const minEpss = parseFloat(dom.filterEpss?.value || '') / 100;
      const minScore = parseFloat(dom.filterScore?.value || '');
      const kevFilter = dom.filterKev?.value || '';
      const showAll = state.filters.showAll;
      const showMitigated = state.filters.showMitigated;
      const showNew = state.filters.showNew;

      // Date filtering
      const dateFilter = state.filters.dateFilter;
      let dateThreshold = null;
      if (dateFilter !== 'custom') {
        const days = parseInt(dateFilter, 10);
        dateThreshold = new Date();
        dateThreshold.setDate(dateThreshold.getDate() - days);
      }

      state.filteredResults = state.originalResults.filter((item) => {
        // CVE filter
        if (cveFilter && !(item.id || '').toLowerCase().includes(cveFilter)) return false;

        // Text search
        const hay = `${item.id || ''} ${item.description || ''} ${(item.matchedCPE || []).join(' ')} ${item.sourceIdentifier || ''}`.toLowerCase();
        if (textFilter && !hay.includes(textFilter)) return false;

        // EPSS filter
        if (!isNaN(minEpss) && minEpss > 0) {
          const epss = parseFloat(item.epss);
          if (isNaN(epss) || epss < minEpss) return false;
        }

        // CVSS filter
        if (!isNaN(minScore) && minScore > 0) {
          const score = parseFloat(item.cvssScore);
          if (isNaN(score) || score < minScore) return false;
        }

        // KEV filter
        if (kevFilter === 'yes' && !item.kev) return false;
        if (kevFilter === 'no' && item.kev) return false;

        // Date filter
        if (dateThreshold && item.published) {
          const pubDate = new Date(item.published);
          if (pubDate < dateThreshold) return false;
        }

        // Status filters
        const isMitigated = mitigatedCves.has(item.id);
        const isNew = item.is_new;

        if (!showAll) {
          if (showNew && !showMitigated && !isNew) return false;
          if (showMitigated && !showNew && !isMitigated) return false;
          if (showNew && showMitigated && !isNew && !isMitigated) return false;
        }

        return true;
      });

      state.currentPage = 1;
      sortAndRender();
    }

    function sortAndRender() {
      const key = state.sortKey;
      const dir = state.sortDir;
      const accessor = {
        id: (item) => item.id || '',
        pub: (item) => item.published || '',
        publisher: (item) => item.sourceIdentifier || '',
        score: (item) => parseFloat(item.cvssScore) || -1,
        epss: (item) => parseFloat(item.epss) || -1,
      };

      state.filteredResults.sort((a, b) => {
        const va = accessor[key](a);
        const vb = accessor[key](b);
        if (va < vb) return -1 * dir;
        if (va > vb) return 1 * dir;
        return 0;
      });

      renderResults();
      updateSortIndicators();
    }

    function updateSortIndicators() {
      document.querySelectorAll('th.sortable').forEach((th) => {
        th.classList.remove('asc', 'desc');
        if (th.dataset.k === state.sortKey) {
          th.classList.add(state.sortDir > 0 ? 'asc' : 'desc');
        }
      });
    }

    function renderResults() {
      if (!dom.resBody) return;
      dom.resBody.innerHTML = '';

      const start = (state.currentPage - 1) * state.pageSize;
      const end = start + state.pageSize;
      const pageResults = state.filteredResults.slice(start, end);

      pageResults.forEach((item, idx) => {
        const globalIdx = start + idx;
        const isMitigated = mitigatedCves.has(item.id);
        const tr = document.createElement('tr');
        tr.className = state.detailIndex === globalIdx ? 'selected' : '';

        // Format CVSS with color
        const score = item.cvssScore;
        let cvssClass = '';
        if (score >= 9) cvssClass = 'cvss-critical';
        else if (score >= 7) cvssClass = 'cvss-high';
        else if (score >= 4) cvssClass = 'cvss-medium';
        else cvssClass = 'cvss-low';

        // Format EPSS with color
        const epss = item.epss;
        let epssClass = '';
        let epssDisplay = '-';
        if (epss !== null && epss !== undefined) {
          const epssPercent = (epss * 100).toFixed(2);
          epssDisplay = `${epssPercent}%`;
          if (epss >= 0.5) epssClass = 'epss-high';
          else if (epss >= 0.1) epssClass = 'epss-medium';
          else epssClass = 'epss-low';
        }

        // KEV icon
        const kevIcon = item.kev
          ? '<span class="kev-icon kev-icon--yes" title="CISA KEV">&check;</span>'
          : '<span class="kev-icon kev-icon--no">&times;</span>';

        // Status badges
        let badges = '';
        if (item.is_new) badges += '<span class="new-badge">NEW</span>';
        if (isMitigated) badges += '<span class="mitigated-badge">MITIGATED</span>';

        // Description (truncated)
        const desc = (item.description || '').substring(0, 100) + (item.description?.length > 100 ? '...' : '');

        tr.innerHTML = `
          <td class="text-indigo-700 font-medium">${item.id}${badges}</td>
          <td>${kevIcon}</td>
          <td>${item.published || '-'}</td>
          <td class="text-xs text-slate-500">${item.sourceIdentifier || '-'}</td>
          <td class="description-cell text-xs" title="${item.description || ''}">${desc}</td>
          <td class="${cvssClass}">${score ?? '-'}</td>
          <td class="${epssClass}">${epssDisplay}</td>
        `;

        tr.addEventListener('click', () => showDetails(globalIdx));
        dom.resBody.appendChild(tr);
      });

      if (dom.resCount) dom.resCount.textContent = String(state.filteredResults.length);
      renderPagination();
    }

    function renderPagination() {
      const totalPages = Math.ceil(state.filteredResults.length / state.pageSize) || 1;
      if (dom.pageInfo) dom.pageInfo.textContent = `Page ${state.currentPage} of ${totalPages}`;
      if (dom.btnPrevPage) dom.btnPrevPage.disabled = state.currentPage <= 1;
      if (dom.btnNextPage) dom.btnNextPage.disabled = state.currentPage >= totalPages;
    }

    function showDetails(index) {
      const item = state.filteredResults[index];
      if (!item || !dom.detailPanel) return;
      state.detailIndex = index;
      dom.detailPanel.hidden = false;

      const isMitigated = mitigatedCves.has(item.id);

      // Update CVE title
      if (dom.detailCve) {
        let title = item.id || '';
        if (item.kev) title += ' (KEV)';
        if (item.is_new) title += ' (NEW)';
        if (isMitigated) title += ' (MITIGATED)';
        dom.detailCve.textContent = title;
      }

      // Update metadata
      if (dom.detailMeta) {
        const epss = item.epss !== null && item.epss !== undefined ? `${(item.epss * 100).toFixed(2)}%` : 'N/A';
        const epssPct = item.epss_percentile !== null && item.epss_percentile !== undefined ? `${(item.epss_percentile * 100).toFixed(1)}th` : 'N/A';
        dom.detailMeta.textContent = `CVSS: ${item.cvssScore ?? 'N/A'} | EPSS: ${epss} (${epssPct} percentile) | Published: ${item.published || 'N/A'} | Publisher: ${item.sourceIdentifier || 'N/A'}`;
      }

      if (dom.detailMatched) {
        dom.detailMatched.textContent = (item.matchedCPE || []).length ? `Matched CPE: ${(item.matchedCPE || []).join(', ')}` : '';
      }

      if (dom.detailDesc) dom.detailDesc.textContent = item.description || '(no description)';

      if (dom.detailCwes) {
        dom.detailCwes.textContent = (item.cwes || []).length ? `CWE: ${(item.cwes || []).join(', ')}` : '';
      }

      // KEV details
      if (dom.detailKev && dom.detailKevDetails) {
        if (item.kev && item.kev_data) {
          dom.detailKev.classList.remove('hidden');
          const kd = item.kev_data;
          dom.detailKevDetails.innerHTML = `
            ${kd.dateAdded ? `<div>Added: ${kd.dateAdded}</div>` : ''}
            ${kd.dueDate ? `<div>Due: ${kd.dueDate}</div>` : ''}
            ${kd.requiredAction ? `<div>Action: ${kd.requiredAction}</div>` : ''}
          `;
        } else {
          dom.detailKev.classList.add('hidden');
        }
      }

      // References
      if (dom.detailRefs) {
        dom.detailRefs.innerHTML = '';
        (item.refs || item.references || []).forEach((ref) => {
          const li = document.createElement('li');
          const a = document.createElement('a');
          a.href = ref.url || '#';
          a.target = '_blank';
          a.className = 'text-indigo-700 underline';
          a.textContent = ref.tags?.length ? ref.tags.join(', ') : ref.source || ref.url || 'link';
          li.appendChild(a);
          dom.detailRefs.appendChild(li);
        });
      }

      if (dom.linkNvd) dom.linkNvd.href = `https://nvd.nist.gov/vuln/detail/${item.id}`;
      if (dom.btnMarkMitigated) {
        dom.btnMarkMitigated.textContent = isMitigated ? 'Unmark Mitigated' : 'Mark Mitigated';
      }

      // Highlight selected row
      renderResults();
    }

    function toggleMitigated() {
      const item = state.filteredResults[state.detailIndex];
      if (!item) return;
      if (mitigatedCves.has(item.id)) {
        mitigatedCves.delete(item.id);
        showAlert(`${item.id} unmarked as mitigated`, 'info', 2000);
      } else {
        mitigatedCves.add(item.id);
        showAlert(`${item.id} marked as mitigated`, 'success', 2000);
      }
      saveMitigated();
      showDetails(state.detailIndex);
    }

    function copyJson(item) {
      if (!navigator.clipboard) {
        showAlert('Clipboard not available', 'error');
        return;
      }
      navigator.clipboard.writeText(JSON.stringify(item, null, 2)).then(() => {
        showAlert('CVE JSON copied.', 'success', 2000);
      });
    }

    // Export functions
    function exportCsv() {
      const rows = [['CVE', 'KEV', 'Published', 'Publisher', 'CVSS', 'EPSS', 'Description', 'Mitigated']];
      state.filteredResults.forEach((item) => {
        rows.push([
          item.id || '',
          item.kev ? 'yes' : 'no',
          item.published || '',
          item.sourceIdentifier || '',
          item.cvssScore ?? '',
          item.epss !== null ? (item.epss * 100).toFixed(2) + '%' : '',
          (item.description || '').replace(/\n/g, ' '),
          mitigatedCves.has(item.id) ? 'yes' : 'no',
        ]);
      });
      const body = rows.map((cols) => cols.map(csvEscape).join(',')).join('\n');
      downloadFile(`cve_export_${Date.now()}.csv`, body, 'text/csv');
    }

    function csvEscape(value) {
      const text = String(value ?? '');
      if (/[,"\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
      return text;
    }

    function exportNdjson() {
      const body = state.filteredResults.map((item) => JSON.stringify(item)).join('\n');
      downloadFile(`cve_export_${Date.now()}.jsonl`, body, 'application/x-ndjson');
    }

    function downloadFile(filename, contents, mime) {
      const blob = new Blob([contents], { type: mime });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }

    // Bulk selection
    function updateBulkState() {
      const count = state.selectedIds.size;
      if (dom.selectedCount) dom.selectedCount.textContent = `${count} Selected`;
      if (dom.deleteSelectedBtn) dom.deleteSelectedBtn.disabled = count === 0;
    }

    function toggleSelectMode(on) {
      state.manageMode = on;
      if (dom.selectModeBtn) dom.selectModeBtn.textContent = on ? 'Done' : 'Select';
      if (dom.selectAllBox) dom.selectAllBox.disabled = !on;
      if (dom.deleteSelectedBtn) dom.deleteSelectedBtn.classList.toggle('hidden', !on);
      if (!on) {
        state.selectedIds.clear();
        if (dom.selectAllBox) dom.selectAllBox.checked = false;
      }
      renderSidebar();
    }

    // CPE Builder
    function escapeSegment(value) {
      if (!value) return '*';
      return value.replace(/\\/g, '\\\\').replace(/:/g, '\\:');
    }

    function buildCpe() {
      const values = builderFields.map((field) => {
        if (!field) return '*';
        const raw = 'value' in field ? field.value : '';
        return escapeSegment(raw.trim());
      });
      const part = values.shift() || 'o';
      return `cpe:2.3:${part}:${values.join(':')}`;
    }

    function updateBuilderOutput() {
      if (dom.builderOutput) dom.builderOutput.textContent = buildCpe();
    }

    // Settings modal
    function openSettingsModal() {
      if (dom.settingScanTimes) dom.settingScanTimes.value = settings.scanTimes;
      if (dom.settingCvssThreshold) dom.settingCvssThreshold.value = settings.cvssThreshold || '';
      if (dom.settingEpssThreshold) dom.settingEpssThreshold.value = settings.epssThreshold || '';
      if (dom.settingAutoRefresh) dom.settingAutoRefresh.checked = settings.autoRefresh;
      dom.settingsModal?.classList.remove('hidden');
    }

    function closeSettingsModal() {
      dom.settingsModal?.classList.add('hidden');
    }

    function saveSettingsFromModal() {
      settings.scanTimes = dom.settingScanTimes?.value || '07:30,12:30,16:00,19:30';
      settings.cvssThreshold = parseFloat(dom.settingCvssThreshold?.value) || 0;
      settings.epssThreshold = parseFloat(dom.settingEpssThreshold?.value) || 0;
      settings.autoRefresh = dom.settingAutoRefresh?.checked || false;
      state.scheduleIntervals = settings.scanTimes.split(',').filter(Boolean);
      saveSettings();
      renderScheduleIntervals();
      renderSidebar();
      closeSettingsModal();
      showAlert('Settings saved.', 'success', 2000);
    }

    // Interval modal
    function openIntervalModal() {
      dom.intervalModal?.classList.remove('hidden');
    }

    function closeIntervalModal() {
      dom.intervalModal?.classList.add('hidden');
    }

    function addIntervalFromModal() {
      const time = dom.intervalTime?.value || '12:00';
      if (!state.scheduleIntervals.includes(time)) {
        state.scheduleIntervals.push(time);
        state.scheduleIntervals.sort();
        settings.scanTimes = state.scheduleIntervals.join(',');
        saveSettings();
        renderScheduleIntervals();
        renderSidebar();
      }
      closeIntervalModal();
    }

    // Event bindings
    function initEvents() {
      // Sidebar
      dom.searchInput?.addEventListener('input', () => {
        const query = (dom.searchInput.value || '').toLowerCase();
        dom.projectsContainer?.querySelectorAll('.team-card').forEach((card) => {
          const text = card.textContent.toLowerCase();
          card.style.display = query && !text.includes(query) ? 'none' : '';
        });
      });

      dom.selectModeBtn?.addEventListener('click', () => toggleSelectMode(!state.manageMode));

      dom.selectAllBox?.addEventListener('change', () => {
        state.projects.forEach((p) => {
          if (dom.selectAllBox.checked) state.selectedIds.add(p.id);
          else state.selectedIds.delete(p.id);
        });
        renderSidebar();
      });

      dom.newWatchBtn?.addEventListener('click', () => {
        state.currentWatchId = null;
        clearForm();
        dom.form?.classList.remove('hidden');
        renderSidebar();
      });

      dom.newProjectBtn?.addEventListener('click', async () => {
        const name = prompt('Team name', 'New Team');
        if (!name) return;
        await api.createProject(name);
        await api.getWatchlists();
      });

      dom.deleteSelectedBtn?.addEventListener('click', async () => {
        if (!state.selectedIds.size) return;
        if (!confirm(`Delete ${state.selectedIds.size} team(s)?`)) return;
        for (const id of state.selectedIds) {
          try { await api.deleteProject(id); } catch (e) { /* ignore */ }
        }
        state.selectedIds.clear();
        await api.getWatchlists();
        showAlert('Teams deleted.', 'success', 2000);
      });

      // CPE Builder
      builderFields.forEach((field) => {
        field?.addEventListener('input', updateBuilderOutput);
      });

      dom.builderToggle?.addEventListener('click', () => {
        dom.builderBody?.classList.toggle('hidden');
        dom.builderToggle.textContent = dom.builderBody?.classList.contains('hidden') ? 'Show' : 'Hide';
      });

      dom.btnAddCpe?.addEventListener('click', () => {
        const cpe = buildCpe();
        if (cpe && cpe !== 'cpe:2.3:o:*:*:*:*:*:*:*:*:*:*') addCpeToList(cpe);
      });

      dom.btnAddManualCpe?.addEventListener('click', () => {
        const cpe = dom.manualCpeInput?.value?.trim();
        if (cpe) {
          addCpeToList(cpe);
          dom.manualCpeInput.value = '';
        }
      });

      // Schedule
      document.querySelectorAll('.scan-period-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('.scan-period-btn').forEach((b) => b.classList.remove('active'));
          btn.classList.add('active');
          state.scanPeriod = btn.dataset.period;
        });
      });

      dom.btnAddInterval?.addEventListener('click', openIntervalModal);
      dom.btnCloseInterval?.addEventListener('click', closeIntervalModal);
      dom.btnCancelInterval?.addEventListener('click', closeIntervalModal);
      dom.btnConfirmInterval?.addEventListener('click', addIntervalFromModal);

      dom.btnSaveAndScan?.addEventListener('click', async () => {
        await saveWatchlist();
        const period = state.scanPeriod === 'custom' ? '24h' : state.scanPeriod;
        await runCurrent(period);
      });

      // Form
      dom.btnSaveWatch?.addEventListener('click', saveWatchlist);
      dom.btnDeleteWatch?.addEventListener('click', deleteCurrentWatch);

      // Filters
      dom.btnFilter?.addEventListener('click', applyFilters);
      dom.filterCve?.addEventListener('keypress', (e) => { if (e.key === 'Enter') applyFilters(); });
      dom.filterText?.addEventListener('input', applyFilters);
      dom.filterEpss?.addEventListener('input', applyFilters);
      dom.filterScore?.addEventListener('input', applyFilters);
      dom.filterKev?.addEventListener('change', applyFilters);

      dom.filterClear?.addEventListener('click', () => {
        if (dom.filterCve) dom.filterCve.value = '';
        if (dom.filterText) dom.filterText.value = '';
        if (dom.filterEpss) dom.filterEpss.value = '';
        if (dom.filterScore) dom.filterScore.value = '';
        if (dom.filterKev) dom.filterKev.value = '';
        if (dom.filterAll) dom.filterAll.checked = false;
        if (dom.filterMitigated) dom.filterMitigated.checked = false;
        if (dom.filterNew) dom.filterNew.checked = true;
        state.filters.showAll = false;
        state.filters.showMitigated = false;
        state.filters.showNew = true;
        state.filters.dateFilter = 'custom';
        document.querySelectorAll('.date-filter-btn').forEach((b) => b.classList.remove('active'));
        document.querySelector('.date-filter-btn[data-days="custom"]')?.classList.add('active');
        applyFilters();
      });

      // Status filters
      dom.filterAll?.addEventListener('change', () => {
        state.filters.showAll = dom.filterAll.checked;
        if (dom.filterAll.checked) {
          if (dom.filterMitigated) dom.filterMitigated.checked = false;
          if (dom.filterNew) dom.filterNew.checked = false;
          state.filters.showMitigated = false;
          state.filters.showNew = false;
        }
        applyFilters();
      });

      dom.filterMitigated?.addEventListener('change', () => {
        state.filters.showMitigated = dom.filterMitigated.checked;
        if (dom.filterMitigated.checked && dom.filterAll) {
          dom.filterAll.checked = false;
          state.filters.showAll = false;
        }
        applyFilters();
      });

      dom.filterNew?.addEventListener('change', () => {
        state.filters.showNew = dom.filterNew.checked;
        if (dom.filterNew.checked && dom.filterAll) {
          dom.filterAll.checked = false;
          state.filters.showAll = false;
        }
        applyFilters();
      });

      // Date filter buttons
      document.querySelectorAll('.date-filter-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('.date-filter-btn').forEach((b) => b.classList.remove('active'));
          btn.classList.add('active');
          state.filters.dateFilter = btn.dataset.days;
          applyFilters();
        });
      });

      // Sorting
      document.querySelectorAll('th.sortable').forEach((th) => {
        th.addEventListener('click', () => {
          const key = th.dataset.k;
          if (!key) return;
          if (state.sortKey === key) state.sortDir = -state.sortDir;
          else {
            state.sortKey = key;
            state.sortDir = (key === 'score' || key === 'epss' || key === 'pub') ? -1 : 1;
          }
          sortAndRender();
        });
      });

      // Pagination
      dom.btnPrevPage?.addEventListener('click', () => {
        if (state.currentPage > 1) {
          state.currentPage--;
          renderResults();
        }
      });

      dom.btnNextPage?.addEventListener('click', () => {
        const totalPages = Math.ceil(state.filteredResults.length / state.pageSize);
        if (state.currentPage < totalPages) {
          state.currentPage++;
          renderResults();
        }
      });

      // Detail panel
      dom.btnPrev?.addEventListener('click', () => {
        if (state.detailIndex > 0) showDetails(state.detailIndex - 1);
      });

      dom.btnNext?.addEventListener('click', () => {
        if (state.detailIndex < state.filteredResults.length - 1) showDetails(state.detailIndex + 1);
      });

      dom.btnCopyJson?.addEventListener('click', () => {
        if (state.detailIndex >= 0) copyJson(state.filteredResults[state.detailIndex]);
      });

      dom.btnMarkMitigated?.addEventListener('click', toggleMitigated);

      // Exports
      dom.btnExportCsv?.addEventListener('click', exportCsv);
      dom.btnExportNdjson?.addEventListener('click', exportNdjson);

      // Settings modal
      dom.btnSettings?.addEventListener('click', openSettingsModal);
      dom.btnCloseSettings?.addEventListener('click', closeSettingsModal);
      dom.btnCancelSettings?.addEventListener('click', closeSettingsModal);
      dom.btnSaveSettings?.addEventListener('click', saveSettingsFromModal);
      dom.settingsModal?.querySelector('.modal__backdrop')?.addEventListener('click', closeSettingsModal);

      // Keyboard shortcuts
      window.addEventListener('keydown', (e) => {
        if (e.target?.tagName === 'INPUT' || e.target?.tagName === 'TEXTAREA') return;

        if (e.key === 'ArrowLeft' && state.detailIndex > 0) {
          showDetails(state.detailIndex - 1);
        } else if (e.key === 'ArrowRight' && state.detailIndex < state.filteredResults.length - 1) {
          showDetails(state.detailIndex + 1);
        } else if (e.key === 'Escape') {
          closeSettingsModal();
          closeIntervalModal();
        }
      });
    }

    function init() {
      renderSidebar();
      populateProjectSelect();
      renderCpeList();
      renderScheduleIntervals();
      updateBuilderOutput();
      initEvents();

      if (state.currentWatchId) {
        const watch = findWatchlist(state.currentWatchId);
        if (watch) fillForm(watch);
        else clearForm();
      } else {
        clearForm();
      }

      applyFilters();

      if (state.windowLabel && dom.windowLabel) {
        dom.windowLabel.textContent = `Window: ${state.windowLabel}`;
      }
    }

    return { init };
  }
})();

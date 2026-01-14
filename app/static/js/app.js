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
    const welcomeHiddenKey = 'cpexvtops-welcome-hidden';
    const DEFAULT_SOURCES = ['cvelist5', 'nvd'];

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

    // Check if welcome banner should be hidden
    let welcomeHidden = false;
    try {
      welcomeHidden = window.localStorage.getItem(welcomeHiddenKey) === 'true';
    } catch (err) {}

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
      scheduleIntervals: normalizeScheduleTimes(settings.scanTimes),
      scanPeriod: '7d',
      currentPage: 1,
      pageSize: 25,
      // New state for scan modes
      scanMode: 'quick', // 'quick' or 'full'
      currentStep: 1,
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
      newProjectBtn: document.getElementById('btnNewProject'),
      teamCountLabel: document.getElementById('teamCountLabel'),
      teamCountLabel: document.getElementById('teamCountLabel'),

      // Welcome banner
      welcomeBanner: document.getElementById('welcomeBanner'),
      btnHideWelcome: document.getElementById('btnHideWelcome'),
      btnStartQuickScan: document.getElementById('btnStartQuickScan'),
      btnStartFullScan: document.getElementById('btnStartFullScan'),

      // Mode selector
      scanModeSelector: document.getElementById('scanModeSelector'),
      modeQuickScan: document.getElementById('modeQuickScan'),
      modeFullScan: document.getElementById('modeFullScan'),
      quickModeDesc: document.getElementById('quickModeDesc'),
      fullModeDesc: document.getElementById('fullModeDesc'),

      // Steps
      stepsIndicator: document.querySelector('.steps-indicator'),
      step1Card: document.getElementById('step1Card'),
      step2CardQuick: document.getElementById('step2CardQuick'),
      step2CardFull: document.getElementById('step2CardFull'),
      btnStep1Next: document.getElementById('btnStep1Next'),
      btnStep2Back: document.getElementById('btnStep2Back'),
      btnStep2FullBack: document.getElementById('btnStep2FullBack'),

      // CPE Builder
      builderToggle: document.getElementById('builderToggle'),
      builderBody: document.getElementById('builderBody'),
      builderOutput: document.getElementById('b_output'),
      cpeList: document.getElementById('cpeList'),
      cpeListCount: document.getElementById('cpeListCount'),
      btnClearCpes: document.getElementById('btnClearCpes'),
      manualCpeInput: document.getElementById('manualCpeInput'),
      btnAddManualCpe: document.getElementById('btnAddManualCpe'),
      btnAddCpe: document.getElementById('b_add'),

      // Quick scan options
      quickOptKev: document.getElementById('quickOptKev'),
      btnQuickScan: document.getElementById('btnQuickScan'),

      // Full scan form
      formProject: document.getElementById('formProject'),
      formName: document.getElementById('formName'),
      formComments: document.getElementById('formComments'),
      formWatchId: document.getElementById('formWatchId'),
      formCpes: document.getElementById('formCpes'),
      optNoRejected: document.getElementById('optNoRejected'),
      optIsVulnerable: document.getElementById('optIsVulnerable'),
      optHasKev: document.getElementById('optHasKev'),
      optInsecure: document.getElementById('optInsecure'),
      optHttpProxy: document.getElementById('optHttpProxy'),
      optHttpsProxy: document.getElementById('optHttpsProxy'),
      optCaBundle: document.getElementById('optCaBundle'),
      optTimeout: document.getElementById('optTimeout'),

      // Schedule
      scheduleIntervals: document.getElementById('scheduleIntervals'),
      btnAddInterval: document.getElementById('btnAddInterval'),
      btnSaveOnly: document.getElementById('btnSaveOnly'),
      btnSaveAndScan: document.getElementById('btnSaveAndScan'),
      btnCreateTeamInline: document.getElementById('btnCreateTeamInline'),

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
      resultsEmptyState: document.getElementById('resultsEmptyState'),
      resultsLoading: document.getElementById('resultsLoading'),
      resultsTableWrapper: document.getElementById('resultsTableWrapper'),
      loadingStatus: document.getElementById('loadingStatus'),
      btnExportCsv: document.getElementById('btnExportCsv'),
      btnExportNdjson: document.getElementById('btnExportNdjson'),

      // Pagination
      tablePagination: document.getElementById('tablePagination'),
      btnPrevPage: document.getElementById('btnPrevPage'),
      btnNextPage: document.getElementById('btnNextPage'),
      pageInfo: document.getElementById('pageInfo'),

      // Detail panel
      detailPanel: document.getElementById('detailPanel'),
      detailCve: document.getElementById('d_cve'),
      detailMeta: document.getElementById('d_meta'),
      detailMatched: document.getElementById('d_matched'),
      detailDesc: document.getElementById('d_desc'),
      detailCvss: document.getElementById('d_cvss'),
      detailEpss: document.getElementById('d_epss'),
      detailEpssPercentile: document.getElementById('d_epss_percentile'),
      detailSeverity: document.getElementById('d_severity'),
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

      // Create team modal
      createTeamModal: document.getElementById('createTeamModal'),
      btnCloseCreateTeam: document.getElementById('btnCloseCreateTeam'),
      btnCancelCreateTeam: document.getElementById('btnCancelCreateTeam'),
      btnConfirmCreateTeam: document.getElementById('btnConfirmCreateTeam'),
      newTeamName: document.getElementById('newTeamName'),
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
      async quickScan(cpes, window, kevOnly = false, sources = []) {
        return requestJson('/api/quick-scan', { method: 'POST', body: { cpes, window, kevOnly, sources } });
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
    function escapeHtml(str) {
      if (!str) return '';
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    function normalizeScheduleTimes(times) {
      const list = Array.isArray(times) ? times : String(times || '').split(',');
      const normalized = list
        .map((time) => String(time || '').trim())
        .filter(Boolean);
      return Array.from(new Set(normalized)).sort();
    }

    function formatCvssScore(score) {
      if (score === null || score === undefined || score === '') {
        return { display: 'N/A', value: null };
      }
      const numeric = Number.parseFloat(score);
      if (Number.isNaN(numeric)) {
        return { display: String(score), value: null };
      }
      return { display: numeric.toFixed(1), value: numeric };
    }

    function showAlert(message, level = 'info', timeout = 5000) {
      if (!dom.alerts) return;
      const box = document.createElement('div');
      box.className = `flash flash--${level}`;
      box.textContent = message;
      dom.alerts.appendChild(box);
      if (timeout) setTimeout(() => box.remove(), timeout);
    }

    function getSelectedSources(scope) {
      return Array.from(document.querySelectorAll(`input[data-source][data-scope="${scope}"]`))
        .filter((input) => input.checked)
        .map((input) => input.dataset.source)
        .filter(Boolean);
    }

    function setSelectedSources(scope, sources = []) {
      const selected = new Set((sources && sources.length ? sources : DEFAULT_SOURCES).map((s) => s.toLowerCase()));
      document.querySelectorAll(`input[data-source][data-scope="${scope}"]`).forEach((input) => {
        input.checked = selected.has((input.dataset.source || '').toLowerCase());
      });
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

    // Mode and Step Management
    function setScanMode(mode) {
      state.scanMode = mode;

      // Update mode toggle buttons
      if (dom.modeQuickScan) {
        dom.modeQuickScan.classList.toggle('mode-toggle__btn--active', mode === 'quick');
      }
      if (dom.modeFullScan) {
        dom.modeFullScan.classList.toggle('mode-toggle__btn--active', mode === 'full');
      }

      // Update mode descriptions
      if (dom.quickModeDesc) dom.quickModeDesc.classList.toggle('hidden', mode !== 'quick');
      if (dom.fullModeDesc) dom.fullModeDesc.classList.toggle('hidden', mode !== 'full');

      // Show appropriate step 2 card
      updateStepCards();
    }

    function setCurrentStep(step) {
      state.currentStep = step;
      updateStepIndicator();
      updateStepCards();
    }

    function updateStepIndicator() {
      if (!dom.stepsIndicator) return;
      const steps = dom.stepsIndicator.querySelectorAll('.step');
      const connectors = dom.stepsIndicator.querySelectorAll('.step__connector');

      steps.forEach((stepEl, idx) => {
        const stepNum = idx + 1;
        stepEl.classList.remove('step--active', 'step--complete');
        if (stepNum === state.currentStep) {
          stepEl.classList.add('step--active');
        } else if (stepNum < state.currentStep) {
          stepEl.classList.add('step--complete');
        }
      });

      connectors.forEach((conn, idx) => {
        conn.classList.toggle('step__connector--active', idx + 1 < state.currentStep);
      });
    }

    function updateStepCards() {
      // Step 1 always visible
      if (dom.step1Card) {
        dom.step1Card.classList.toggle('step-card--active', state.currentStep === 1);
        dom.step1Card.classList.toggle('hidden', false);
      }

      // Step 2 - show appropriate card based on mode
      if (dom.step2CardQuick) {
        const showQuick = state.scanMode === 'quick' && state.currentStep >= 2;
        dom.step2CardQuick.classList.toggle('hidden', !showQuick);
        dom.step2CardQuick.classList.toggle('step-card--active', state.currentStep === 2 && state.scanMode === 'quick');
      }

      if (dom.step2CardFull) {
        const showFull = state.scanMode === 'full' && state.currentStep >= 2;
        dom.step2CardFull.classList.toggle('hidden', !showFull);
        dom.step2CardFull.classList.toggle('step-card--active', state.currentStep === 2 && state.scanMode === 'full');
      }

      // Update step 1 next button state
      updateStep1NextButton();
    }

    function updateStep1NextButton() {
      if (dom.btnStep1Next) {
        dom.btnStep1Next.disabled = state.cpeList.length === 0;
      }
    }

    // Sidebar rendering with team cards
    function renderSidebar() {
      if (!dom.projectsContainer) return;
      dom.projectsContainer.innerHTML = '';

      if (dom.teamCountLabel) {
        const teamCount = state.projects.length;
        dom.teamCountLabel.textContent = `${teamCount} team${teamCount === 1 ? '' : 's'}`;
      }

      // Empty state
      if (state.projects.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'text-center py-6 px-4';
        emptyState.innerHTML = `
          <svg viewBox="0 0 24 24" class="h-10 w-10 mx-auto text-slate-300 mb-2" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <p class="text-slate-500 text-sm mb-1">No saved watchlists</p>
          <p class="text-slate-400 text-xs">Use Full Scan mode to create one</p>
        `;
        dom.projectsContainer.appendChild(emptyState);
        return;
      }

      state.projects.slice().sort((a, b) => (a.order || 0) - (b.order || 0)).forEach((project) => {
        const lists = sortedListsFor(project.id);

        const wrapper = document.createElement('section');
        wrapper.className = 'team-card';
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
        if (lists.length === 0) {
          playBtn.disabled = true;
          playBtn.classList.add('opacity-40', 'cursor-not-allowed');
          playBtn.title = 'Add a watchlist to enable scans';
        }
        playBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (lists.length > 0) {
            selectWatchlist(lists[0].id, true, state.scanPeriod === 'custom' ? '7d' : state.scanPeriod);
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

        // Collapse indicator
        const collapseIcon = document.createElement('span');
        collapseIcon.className = 'text-slate-400 text-xs';
        collapseIcon.textContent = state.collapsed.has(project.id) ? '+' : '-';

        header.appendChild(checkbox);
        header.appendChild(playBtn);
        header.appendChild(nameEl);
        header.appendChild(collapseIcon);
        wrapper.appendChild(header);

        const meta = document.createElement('div');
        meta.className = 'team-card__meta';
        const watchlistCount = document.createElement('span');
        watchlistCount.className = 'team-card__count';
        watchlistCount.textContent = `${lists.length} watchlist${lists.length === 1 ? '' : 's'}`;
        meta.appendChild(watchlistCount);
        wrapper.appendChild(meta);

        // CPE list (collapsible)
        if (!state.collapsed.has(project.id)) {
          const cpeContainer = document.createElement('div');
          cpeContainer.className = 'mt-2 space-y-1';

          if (lists.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'team-card__empty';
            empty.textContent = 'No watchlists yet. Use Full Scan to create one.';
            cpeContainer.appendChild(empty);
          } else {
            lists.forEach((watch) => {
              const watchItem = document.createElement('div');
              watchItem.className = 'p-2 bg-slate-50 rounded text-xs cursor-pointer hover:bg-slate-100';
              watchItem.innerHTML = `
                <div class="font-medium text-slate-700">${escapeHtml(watch.name)}</div>
                <div class="text-slate-500 mt-1">${watch.cpes.length} CPE(s)</div>
              `;
              watchItem.addEventListener('click', () => selectWatchlist(watch.id, false));
              cpeContainer.appendChild(watchItem);
            });
          }

          wrapper.appendChild(cpeContainer);
        }

        dom.projectsContainer.appendChild(wrapper);
      });

      updateBulkState();
    }

    function populateProjectSelect() {
      if (!dom.formProject) return;
      const currentValue = dom.formProject.value;
      dom.formProject.innerHTML = '';

      if (state.projects.length === 0) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = '-- Create a team first --';
        dom.formProject.appendChild(option);
        return;
      }

      state.projects.slice().sort((a, b) => (a.order || 0) - (b.order || 0)).forEach((project) => {
        const option = document.createElement('option');
        option.value = project.id;
        option.textContent = project.name;
        dom.formProject.appendChild(option);
      });

      if (currentValue && state.projects.some((project) => project.id === currentValue)) {
        dom.formProject.value = currentValue;
      } else {
        dom.formProject.value = state.projects[0].id;
      }
    }

    function selectWatchlist(id, runImmediately = false, window = '7d') {
      state.currentWatchId = id;
      state.detailIndex = -1;
      state.selectedIds.clear();
      const watch = findWatchlist(id);
      if (!watch) {
        clearForm();
        renderSidebar();
        return;
      }

      // Switch to full mode and fill form
      setScanMode('full');
      setCurrentStep(2);
      fillForm(watch);
      renderSidebar();
      updateBulkState();
      if (runImmediately) runWatchlistScan(window);
    }

    function clearForm() {
      if (dom.formWatchId) dom.formWatchId.value = '';
      if (dom.formProject && state.projects.length > 0) dom.formProject.value = state.projects[0].id;
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
      setSelectedSources('full', DEFAULT_SOURCES);
      state.scheduleIntervals = normalizeScheduleTimes(settings.scanTimes);
      renderScheduleIntervals();
    }

    function fillForm(watch) {
      if (dom.formWatchId) dom.formWatchId.value = watch.id;
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
      setSelectedSources('full', options.sources || DEFAULT_SOURCES);
      state.scheduleIntervals = normalizeScheduleTimes(options.scheduleTimes || settings.scanTimes);
      renderScheduleIntervals();
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
          sources: getSelectedSources('full'),
          scheduleTimes: normalizeScheduleTimes(state.scheduleIntervals),
        },
      };
    }

    async function ensureProjectSelected() {
      if (!dom.formProject) return '';
      if (dom.formProject.value) return dom.formProject.value;

      if (state.projects.length === 0) {
        const response = await api.createProject('Default Team');
        if (response?.project) {
          state.projects.push(response.project);
          populateProjectSelect();
          renderSidebar();
          return response.project.id;
        }
      }

      if (state.projects.length > 0) {
        dom.formProject.value = state.projects[0].id;
        return dom.formProject.value;
      }

      return '';
    }

    async function saveWatchlist() {
      const projectId = await ensureProjectSelected();
      const payload = gatherFormData();
      if (projectId && !payload.projectId) payload.projectId = projectId;

      if (!payload.projectId) {
        showAlert('Please select a team first.', 'error');
        return null;
      }

      if (!payload.name) {
        showAlert('Please enter a watchlist name.', 'error');
        return null;
      }

      if (state.cpeList.length === 0) {
        showAlert('Please add at least one CPE to the watchlist.', 'error');
        return null;
      }

      if (!payload.options.sources.length) {
        showAlert('Please select at least one data source.', 'error');
        return null;
      }

      const watchId = dom.formWatchId?.value;
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
          showAlert('Watchlist saved.', 'success', 2000);
          return response.watchlist;
        }
      } catch (err) {
        console.error('Save failed', err);
      }
      return null;
    }

    // Scan functions
    async function runQuickScan() {
      if (state.pendingRun) return;
      if (state.cpeList.length === 0) {
        showAlert('Please add at least one CPE to scan.', 'error');
        return;
      }

      const sources = getSelectedSources('quick');
      if (!sources.length) {
        showAlert('Please select at least one data source.', 'error');
        return;
      }

      state.pendingRun = true;
      setRunButtonsDisabled(true);
      showLoadingState('Connecting to vulnerability database...');

      const kevOnly = dom.quickOptKev?.checked || false;

      try {
        updateLoadingStatus('Scanning CPEs for vulnerabilities...');
        const result = await api.quickScan(state.cpeList, state.scanPeriod, kevOnly, sources);

        state.originalResults = result.results || [];
        state.windowLabel = result.windowLabel || '';
        hideLoadingState();
        applyFilters();

        showAlert(`Found ${state.originalResults.length} vulnerabilities.`, 'success', 3000);
        if (dom.windowLabel) dom.windowLabel.textContent = `Quick Scan - ${state.windowLabel}`;

        // Move to step 3 (results)
        setCurrentStep(3);

        // Enable export buttons
        if (dom.btnExportCsv) dom.btnExportCsv.disabled = false;
        if (dom.btnExportNdjson) dom.btnExportNdjson.disabled = false;

      } catch (err) {
        console.error('Quick scan failed', err);
        hideLoadingState();
        showAlert('Scan failed. Please try again.', 'error', 5000);
      } finally {
        state.pendingRun = false;
        setRunButtonsDisabled(false);
      }
    }

    async function runWatchlistScan(window) {
      if (state.pendingRun) return;

      const watchId = dom.formWatchId?.value;
      if (!watchId) {
        // Need to save first
        const saved = await saveWatchlist();
        if (!saved) return;
      }

      const id = dom.formWatchId?.value;
      if (!id) {
        showAlert('Save the watchlist before running.', 'error');
        return;
      }

      state.pendingRun = true;
      setRunButtonsDisabled(true);
      showLoadingState('Connecting to vulnerability database...');

      try {
        updateLoadingStatus('Scanning CPEs for vulnerabilities...');
        const result = await api.runWatchlist(id, window);

        state.originalResults = result.results || [];
        state.windowLabel = result.windowLabel || '';
        hideLoadingState();
        applyFilters();

        showAlert(`Found ${state.originalResults.length} vulnerabilities.`, 'success', 3000);
        if (dom.windowLabel) dom.windowLabel.textContent = `Watchlist Scan - ${state.windowLabel}`;

        // Move to step 3 (results)
        setCurrentStep(3);

        // Enable export buttons
        if (dom.btnExportCsv) dom.btnExportCsv.disabled = false;
        if (dom.btnExportNdjson) dom.btnExportNdjson.disabled = false;

      } catch (err) {
        console.error('Scan failed', err);
        hideLoadingState();
        showAlert('Scan failed. Please try again.', 'error', 5000);
      } finally {
        state.pendingRun = false;
        setRunButtonsDisabled(false);
      }
    }

    function showLoadingState(message) {
      if (dom.resultsEmptyState) dom.resultsEmptyState.classList.add('hidden');
      if (dom.resultsTableWrapper) dom.resultsTableWrapper.classList.add('hidden');
      if (dom.tablePagination) dom.tablePagination.classList.add('hidden');
      if (dom.resultsLoading) dom.resultsLoading.classList.remove('hidden');
      if (dom.loadingStatus) dom.loadingStatus.textContent = message || 'Loading...';
      if (dom.alerts) dom.alerts.innerHTML = '';
    }

    function updateLoadingStatus(message) {
      if (dom.loadingStatus) dom.loadingStatus.textContent = message;
    }

    function hideLoadingState() {
      if (dom.resultsLoading) dom.resultsLoading.classList.add('hidden');
    }

    // CPE List management
    function renderCpeList() {
      if (!dom.cpeList) return;

      // Update count
      if (dom.cpeListCount) dom.cpeListCount.textContent = String(state.cpeList.length);

      // Show/hide clear button
      if (dom.btnClearCpes) {
        dom.btnClearCpes.classList.toggle('hidden', state.cpeList.length === 0);
      }

      if (state.cpeList.length === 0) {
        dom.cpeList.innerHTML = `
          <div class="empty-state">
            <svg viewBox="0 0 24 24" class="h-8 w-8 text-slate-300 mx-auto mb-2" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M9 12h6m-3-3v6m-7 4h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
            </svg>
            <p class="text-xs text-slate-400">No CPEs added yet</p>
            <p class="text-xs text-slate-400">Build or paste a CPE above</p>
          </div>
        `;
        updateStep1NextButton();
        return;
      }

      dom.cpeList.innerHTML = '';
      state.cpeList.forEach((cpe, idx) => {
        const item = document.createElement('div');
        item.className = 'cpe-list-item';
        item.innerHTML = `
          <span class="truncate flex-1" title="${escapeHtml(cpe)}">${escapeHtml(cpe)}</span>
          <button class="cpe-list-item__remove" data-idx="${idx}" title="Remove">&times;</button>
        `;
        item.querySelector('button').addEventListener('click', () => {
          state.cpeList.splice(idx, 1);
          renderCpeList();
          updateFormCpes();
        });
        dom.cpeList.appendChild(item);
      });

      updateStep1NextButton();
      updateQuickScanState();
      updateWatchlistActionState();
    }

    function updateFormCpes() {
      if (dom.formCpes) dom.formCpes.value = state.cpeList.join(', ');
    }

    function addCpeToList(cpe) {
      if (!cpe) return;
      const trimmed = cpe.trim();
      if (!trimmed || state.cpeList.includes(trimmed)) return;
      state.cpeList.push(trimmed);
      renderCpeList();
      updateFormCpes();
      showAlert('CPE added to list.', 'success', 1500);
    }

    // Schedule management
    function renderScheduleIntervals() {
      if (!dom.scheduleIntervals) return;
      if (state.scheduleIntervals.length === 0) {
        dom.scheduleIntervals.innerHTML = '<div class="text-xs text-slate-400 italic">No scheduled scans</div>';
        return;
      }

      dom.scheduleIntervals.innerHTML = '';
      state.scheduleIntervals = normalizeScheduleTimes(state.scheduleIntervals);
      state.scheduleIntervals.forEach((time, idx) => {
        const item = document.createElement('div');
        item.className = 'interval-item';
        item.innerHTML = `
          <span class="interval-item__time">${escapeHtml(time)}</span>
          <span class="text-xs text-slate-500">UTC</span>
          <div class="interval-item__actions">
            <button class="interval-item__action interval-item__action--delete" title="Remove" data-idx="${idx}">
              <svg viewBox="0 0 24 24" class="h-3 w-3" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
        `;
        item.querySelector('.interval-item__action--delete').addEventListener('click', () => {
          state.scheduleIntervals.splice(idx, 1);
          state.scheduleIntervals = normalizeScheduleTimes(state.scheduleIntervals);
          settings.scanTimes = state.scheduleIntervals.join(',');
          saveSettings();
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
        dateThreshold.setHours(0, 0, 0, 0);
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

      // Show/hide states based on results
      const hasResults = state.filteredResults.length > 0;

      if (dom.resultsEmptyState) dom.resultsEmptyState.classList.toggle('hidden', hasResults || state.originalResults.length > 0);
      if (dom.resultsTableWrapper) dom.resultsTableWrapper.classList.toggle('hidden', !hasResults);
      if (dom.tablePagination) dom.tablePagination.classList.toggle('hidden', !hasResults);

      if (!hasResults) {
        if (state.originalResults.length > 0 && dom.resultsEmptyState) {
          // Filters resulted in no matches
          dom.resultsEmptyState.classList.remove('hidden');
          dom.resultsEmptyState.innerHTML = `
            <svg viewBox="0 0 24 24" class="h-12 w-12 text-slate-300 mx-auto mb-3" fill="none" stroke="currentColor" stroke-width="1">
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.3-4.3"/>
            </svg>
            <h3 class="text-base font-semibold text-slate-600 mb-1">No Matching Results</h3>
            <p class="text-sm text-slate-500">Try adjusting your filters</p>
          `;
        }
        return;
      }

      const start = (state.currentPage - 1) * state.pageSize;
      const end = start + state.pageSize;
      const pageResults = state.filteredResults.slice(start, end);

      pageResults.forEach((item, idx) => {
        const globalIdx = start + idx;
        const isMitigated = mitigatedCves.has(item.id);
        const tr = document.createElement('tr');
        tr.className = state.detailIndex === globalIdx ? 'selected' : '';

        // Format CVSS with color
        const scoreInfo = formatCvssScore(item.cvssScore);
        let cvssClass = 'cvss-unknown';
        if (scoreInfo.value !== null) {
          if (scoreInfo.value >= 9) cvssClass = 'cvss-critical';
          else if (scoreInfo.value >= 7) cvssClass = 'cvss-high';
          else if (scoreInfo.value >= 4) cvssClass = 'cvss-medium';
          else cvssClass = 'cvss-low';
        }

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
          ? '<span class="kev-icon kev-icon--yes" title="CISA Known Exploited Vulnerability">!</span>'
          : '<span class="kev-icon kev-icon--no">-</span>';

        // Status badges
        let badges = '';
        if (item.is_new) badges += '<span class="new-badge">NEW</span>';
        if (isMitigated) badges += '<span class="mitigated-badge">MITIGATED</span>';

        // Description (truncated and escaped)
        const rawDesc = item.description || '';
        const desc = rawDesc.substring(0, 80) + (rawDesc.length > 80 ? '...' : '');

        const sourceLabel = item.sourceIdentifier || 'Unspecified';

        tr.innerHTML = `
          <td class="text-indigo-700 font-medium whitespace-nowrap">${escapeHtml(item.id)}${badges}</td>
          <td>${kevIcon}</td>
          <td class="whitespace-nowrap">${escapeHtml(item.published?.split('T')[0]) || '-'}</td>
          <td class="text-xs text-slate-500">${escapeHtml(sourceLabel)}</td>
          <td class="description-cell text-xs" title="${escapeHtml(rawDesc)}">${escapeHtml(desc)}</td>
          <td class="${cvssClass}">${scoreInfo.display}</td>
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
        let badges = '';
        if (item.kev) badges += ' <span class="badge sev-Critical">KEV</span>';
        if (item.is_new) badges += ' <span class="new-badge">NEW</span>';
        if (isMitigated) badges += ' <span class="mitigated-badge">MITIGATED</span>';
        dom.detailCve.innerHTML = `${escapeHtml(item.id)}${badges}`;
      }

      // Update metadata
      if (dom.detailMeta) {
        dom.detailMeta.textContent = `Published: ${item.published || 'N/A'} | Source: ${item.sourceIdentifier || 'Unspecified'}`;
      }

      // Update stats
      if (dom.detailCvss) {
        const scoreInfo = formatCvssScore(item.cvssScore);
        let cvssClass = 'cvss-unknown';
        if (scoreInfo.value !== null) {
          if (scoreInfo.value >= 9) cvssClass = 'cvss-critical';
          else if (scoreInfo.value >= 7) cvssClass = 'cvss-high';
          else if (scoreInfo.value >= 4) cvssClass = 'cvss-medium';
          else cvssClass = 'cvss-low';
        }
        dom.detailCvss.className = `detail-stat__value ${cvssClass}`;
        dom.detailCvss.textContent = scoreInfo.display;
      }

      if (dom.detailEpss) {
        const epss = item.epss;
        let epssClass = 'epss-low';
        let epssText = 'N/A';
        if (epss !== null && epss !== undefined) {
          epssText = `${(epss * 100).toFixed(2)}%`;
          if (epss >= 0.5) epssClass = 'epss-high';
          else if (epss >= 0.1) epssClass = 'epss-medium';
        }
        dom.detailEpss.className = `detail-stat__value ${epssClass}`;
        dom.detailEpss.textContent = epssText;
      }

      if (dom.detailEpssPercentile) {
        const percentile = item.epss_percentile;
        dom.detailEpssPercentile.textContent = percentile !== null && percentile !== undefined
          ? `${(percentile * 100).toFixed(2)}%`
          : 'N/A';
      }

      if (dom.detailSeverity) {
        const severity = item.severity || 'Unknown';
        dom.detailSeverity.innerHTML = `<span class="badge sev-${severity}">${severity}</span>`;
      }

      if (dom.detailMatched) {
        dom.detailMatched.textContent = (item.matchedCPE || []).length ? `Matched CPE: ${(item.matchedCPE || []).join(', ')}` : '';
      }

      if (dom.detailDesc) dom.detailDesc.textContent = item.description || '(no description available)';

      if (dom.detailCwes) {
        if ((item.cwes || []).length) {
          dom.detailCwes.innerHTML = `<h4 class="text-sm font-semibold text-slate-700 mb-1">CWEs</h4><p class="text-sm text-slate-600">${(item.cwes || []).join(', ')}</p>`;
        } else {
          dom.detailCwes.innerHTML = '';
        }
      }

      // KEV details
      if (dom.detailKev && dom.detailKevDetails) {
        if (item.kev && item.kev_data) {
          dom.detailKev.classList.remove('hidden');
          const kd = item.kev_data;
          dom.detailKevDetails.innerHTML = `
            ${kd.dateAdded ? `<div><strong>Date Added:</strong> ${escapeHtml(kd.dateAdded)}</div>` : ''}
            ${kd.dueDate ? `<div><strong>Due Date:</strong> ${escapeHtml(kd.dueDate)}</div>` : ''}
            ${kd.requiredAction ? `<div><strong>Required Action:</strong> ${escapeHtml(kd.requiredAction)}</div>` : ''}
            ${kd.vulnerabilityName ? `<div><strong>Vulnerability:</strong> ${escapeHtml(kd.vulnerabilityName)}</div>` : ''}
            ${kd.vendorProject ? `<div><strong>Vendor/Project:</strong> ${escapeHtml(kd.vendorProject)}</div>` : ''}
            ${kd.product ? `<div><strong>Product:</strong> ${escapeHtml(kd.product)}</div>` : ''}
            ${kd.knownRansomwareCampaignUse ? `<div><strong>Ransomware:</strong> ${escapeHtml(kd.knownRansomwareCampaignUse)}</div>` : ''}
            ${kd.notes ? `<div><strong>Notes:</strong> ${escapeHtml(kd.notes)}</div>` : ''}
          `;
        } else {
          dom.detailKev.classList.add('hidden');
        }
      }

      // References
      if (dom.detailRefs) {
        dom.detailRefs.innerHTML = '';
        const refs = item.refs || item.references || [];
        if (refs.length === 0) {
          dom.detailRefs.innerHTML = '<li class="text-slate-400 italic">No references available</li>';
        } else {
          refs.slice(0, 10).forEach((ref) => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.href = ref.url || '#';
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.className = 'text-indigo-600 hover:underline';
            a.textContent = ref.tags?.length ? `[${ref.tags.join(', ')}] ${ref.url}` : ref.url || 'link';
            li.appendChild(a);
            dom.detailRefs.appendChild(li);
          });
          if (refs.length > 10) {
            const li = document.createElement('li');
            li.className = 'text-slate-500 italic';
            li.textContent = `... and ${refs.length - 10} more`;
            dom.detailRefs.appendChild(li);
          }
        }
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
        showAlert('JSON copied to clipboard.', 'success', 2000);
      });
    }

    // Export functions
    function exportCsv() {
      const rows = [['CVE', 'KEV', 'Published', 'Source', 'CVSS', 'Severity', 'EPSS', 'Description', 'Mitigated']];
      state.filteredResults.forEach((item) => {
        rows.push([
          item.id || '',
          item.kev ? 'yes' : 'no',
          item.published || '',
          item.sourceIdentifier || '',
          item.cvssScore ?? '',
          item.severity || '',
          item.epss !== null ? (item.epss * 100).toFixed(2) + '%' : '',
          (item.description || '').replace(/[\n\r]+/g, ' ').substring(0, 500),
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
      const part = values.shift() || 'a';
      return `cpe:2.3:${part}:${values.join(':')}`;
    }

    function updateBuilderOutput() {
      if (dom.builderOutput) dom.builderOutput.textContent = buildCpe();
    }

    // Modal functions
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
      state.scheduleIntervals = normalizeScheduleTimes(settings.scanTimes);
      saveSettings();
      renderScheduleIntervals();
      closeSettingsModal();
      showAlert('Settings saved.', 'success', 2000);
    }

    function openIntervalModal() {
      dom.intervalModal?.classList.remove('hidden');
    }

    function closeIntervalModal() {
      dom.intervalModal?.classList.add('hidden');
    }

    function addIntervalFromModal() {
      const time = dom.intervalTime?.value || '12:00';
      if (!state.scheduleIntervals.includes(time)) {
        state.scheduleIntervals = normalizeScheduleTimes([...state.scheduleIntervals, time]);
        settings.scanTimes = state.scheduleIntervals.join(',');
        saveSettings();
        renderScheduleIntervals();
      }
      closeIntervalModal();
    }

    function openCreateTeamModal() {
      if (dom.newTeamName) dom.newTeamName.value = '';
      dom.createTeamModal?.classList.remove('hidden');
    }

    function closeCreateTeamModal() {
      dom.createTeamModal?.classList.add('hidden');
    }

    async function createTeamFromModal() {
      const name = dom.newTeamName?.value?.trim();
      if (!name) {
        showAlert('Please enter a team name.', 'error');
        return;
      }
      try {
        await api.createProject(name);
        await api.getWatchlists();
        closeCreateTeamModal();
        showAlert(`Team "${name}" created.`, 'success', 2000);
      } catch (err) {
        console.error('Create team failed', err);
      }
    }

    function updateWatchlistActionState() {
      const hasTeam = Boolean(dom.formProject?.value);
      const hasName = Boolean(dom.formName?.value?.trim());
      const hasCpes = state.cpeList.length > 0;
      const hasSources = getSelectedSources('full').length > 0;
      const canSave = hasTeam && hasName && hasCpes && hasSources;
      if (dom.btnSaveOnly) dom.btnSaveOnly.disabled = !canSave;
      if (dom.btnSaveAndScan) dom.btnSaveAndScan.disabled = !canSave || state.pendingRun;
    }

    function updateQuickScanState() {
      const hasCpes = state.cpeList.length > 0;
      const hasSources = getSelectedSources('quick').length > 0;
      if (dom.btnQuickScan) dom.btnQuickScan.disabled = !hasCpes || !hasSources || state.pendingRun;
    }

    function setRunButtonsDisabled(disabled) {
      if (dom.btnQuickScan) dom.btnQuickScan.disabled = disabled;
      if (dom.btnSaveAndScan) dom.btnSaveAndScan.disabled = disabled;
      if (dom.btnSaveOnly) dom.btnSaveOnly.disabled = disabled;
    }

    // Event bindings
    function initEvents() {
      // Welcome banner
      if (dom.btnHideWelcome) {
        dom.btnHideWelcome.addEventListener('click', () => {
          dom.welcomeBanner?.classList.add('hidden');
          try { window.localStorage.setItem(welcomeHiddenKey, 'true'); } catch (e) {}
        });
      }

      if (dom.btnStartQuickScan) {
        dom.btnStartQuickScan.addEventListener('click', () => {
          setScanMode('quick');
          setCurrentStep(1);
        });
      }

      if (dom.btnStartFullScan) {
        dom.btnStartFullScan.addEventListener('click', () => {
          setScanMode('full');
          setCurrentStep(1);
        });
      }

      // Mode selector
      if (dom.modeQuickScan) {
        dom.modeQuickScan.addEventListener('click', () => setScanMode('quick'));
      }
      if (dom.modeFullScan) {
        dom.modeFullScan.addEventListener('click', () => setScanMode('full'));
      }

      // Step navigation
      if (dom.btnStep1Next) {
        dom.btnStep1Next.addEventListener('click', () => {
          if (state.cpeList.length > 0) setCurrentStep(2);
        });
      }

      if (dom.btnStep2Back) {
        dom.btnStep2Back.addEventListener('click', () => setCurrentStep(1));
      }

      if (dom.btnStep2FullBack) {
        dom.btnStep2FullBack.addEventListener('click', () => setCurrentStep(1));
      }

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

      dom.newProjectBtn?.addEventListener('click', openCreateTeamModal);

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
        dom.builderToggle.textContent = dom.builderBody?.classList.contains('hidden') ? 'Show Builder' : 'Hide Builder';
      });

      dom.btnAddCpe?.addEventListener('click', () => {
        const vendorField = document.getElementById('b_vendor');
        const productField = document.getElementById('b_product');
        const vendor = vendorField?.value?.trim() || '';
        const product = productField?.value?.trim() || '';

        if (!vendor || !product) {
          showAlert('Please fill in at least vendor and product fields.', 'warning');
          return;
        }

        const cpe = buildCpe();
        addCpeToList(cpe);
      });

      dom.btnAddManualCpe?.addEventListener('click', () => {
        const cpe = dom.manualCpeInput?.value?.trim();
        if (cpe) {
          addCpeToList(cpe);
          dom.manualCpeInput.value = '';
        }
      });

      dom.manualCpeInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const cpe = dom.manualCpeInput?.value?.trim();
          if (cpe) {
            addCpeToList(cpe);
            dom.manualCpeInput.value = '';
          }
        }
      });

      dom.btnClearCpes?.addEventListener('click', () => {
        if (confirm('Clear all CPEs from the list?')) {
          state.cpeList = [];
          renderCpeList();
          updateFormCpes();
        }
      });

      // Scan period buttons
      document.querySelectorAll('.scan-period-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          const container = btn.closest('.card, .mb-4');
          container?.querySelectorAll('.scan-period-btn').forEach((b) => b.classList.remove('active'));
          btn.classList.add('active');
          state.scanPeriod = btn.dataset.period;
        });
      });

      // Quick scan
      dom.btnQuickScan?.addEventListener('click', runQuickScan);

      // Full scan
      dom.btnCreateTeamInline?.addEventListener('click', openCreateTeamModal);

      dom.btnAddInterval?.addEventListener('click', openIntervalModal);

      dom.btnSaveOnly?.addEventListener('click', async () => {
        await saveWatchlist();
      });

      dom.btnSaveAndScan?.addEventListener('click', async () => {
        const saved = await saveWatchlist();
        if (saved) {
          await runWatchlistScan(state.scanPeriod === 'custom' ? '7d' : state.scanPeriod);
        }
      });

      dom.formName?.addEventListener('input', updateWatchlistActionState);
      dom.formProject?.addEventListener('change', updateWatchlistActionState);
      dom.formComments?.addEventListener('input', updateWatchlistActionState);
      dom.optNoRejected?.addEventListener('change', updateWatchlistActionState);
      dom.optHasKev?.addEventListener('change', updateWatchlistActionState);
      dom.optIsVulnerable?.addEventListener('change', updateWatchlistActionState);
      dom.optInsecure?.addEventListener('change', updateWatchlistActionState);
      dom.optHttpProxy?.addEventListener('input', updateWatchlistActionState);
      dom.optHttpsProxy?.addEventListener('input', updateWatchlistActionState);
      dom.optCaBundle?.addEventListener('input', updateWatchlistActionState);
      dom.optTimeout?.addEventListener('input', updateWatchlistActionState);

      document.querySelectorAll('input[data-source][data-scope="full"]').forEach((input) => {
        input.addEventListener('change', updateWatchlistActionState);
      });

      document.querySelectorAll('input[data-source][data-scope="quick"]').forEach((input) => {
        input.addEventListener('change', updateQuickScanState);
      });

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

      // Interval modal
      dom.btnCloseInterval?.addEventListener('click', closeIntervalModal);
      dom.btnCancelInterval?.addEventListener('click', closeIntervalModal);
      dom.btnConfirmInterval?.addEventListener('click', addIntervalFromModal);
      dom.intervalModal?.querySelector('.modal__backdrop')?.addEventListener('click', closeIntervalModal);

      // Create team modal
      dom.btnCloseCreateTeam?.addEventListener('click', closeCreateTeamModal);
      dom.btnCancelCreateTeam?.addEventListener('click', closeCreateTeamModal);
      dom.btnConfirmCreateTeam?.addEventListener('click', createTeamFromModal);
      dom.createTeamModal?.querySelector('.modal__backdrop')?.addEventListener('click', closeCreateTeamModal);
      dom.newTeamName?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') createTeamFromModal();
      });

      // Keyboard shortcuts
      window.addEventListener('keydown', (e) => {
        if (e.target?.tagName === 'INPUT' || e.target?.tagName === 'TEXTAREA' || e.target?.tagName === 'SELECT') return;

        if (e.key === 'ArrowLeft' && state.detailIndex > 0) {
          showDetails(state.detailIndex - 1);
        } else if (e.key === 'ArrowRight' && state.detailIndex < state.filteredResults.length - 1) {
          showDetails(state.detailIndex + 1);
        } else if (e.key === 'Escape') {
          closeSettingsModal();
          closeIntervalModal();
          closeCreateTeamModal();
        }
      });
    }

    function init() {
      // Hide welcome banner if previously dismissed
      if (welcomeHidden && dom.welcomeBanner) {
        dom.welcomeBanner.classList.add('hidden');
      }

      renderSidebar();
      populateProjectSelect();
      renderCpeList();
      renderScheduleIntervals();
      updateBuilderOutput();
      initEvents();
      updateQuickScanState();
      updateWatchlistActionState();

      // Set initial mode and step
      setScanMode('quick');
      setCurrentStep(1);
      setSelectedSources('quick', DEFAULT_SOURCES);
      setSelectedSources('full', DEFAULT_SOURCES);

      // Apply initial filters
      applyFilters();

      if (state.windowLabel && dom.windowLabel) {
        dom.windowLabel.textContent = state.windowLabel;
      }
    }

    return { init };
  }
})();

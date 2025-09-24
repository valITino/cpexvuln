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
    const csrfToken = bootstrap.csrfToken || document.querySelector('meta[name="csrf-token"]').content || '';
    const collapsedKey = 'cpe-watch-collapsed-projects';
    const collapsedInitial = new Set();
    try {
      const stored = window.localStorage.getItem(collapsedKey);
      if (stored) {
        JSON.parse(stored).forEach((id) => collapsedInitial.add(id));
      }
    } catch (err) {
      console.warn('Unable to read collapsed state', err);
    }

    const state = {
      projects: bootstrap.projects || [],
      lists: bootstrap.lists || [],
      currentWatchId: bootstrap.currentWatchId || null,
      originalResults: bootstrap.results || [],
      filteredResults: [],
      windowLabel: bootstrap.windowLabel || '',
      filters: { text: '', severity: '', minScore: '', kevOnly: false },
      sortKey: 'mod',
      sortDir: -1,
      detailIndex: -1,
      manageMode: false,
      selectedIds: new Set(),
      collapsed: collapsedInitial,
      pendingRun: false,
    };

    const dom = {
      alerts: document.getElementById('alerts'),
      projectsContainer: document.getElementById('projectsContainer'),
      searchInput: document.getElementById('wlSearch'),
      selectModeBtn: document.getElementById('selectMode'),
      selectAllBox: document.getElementById('wlSelectAll'),
      deleteSelectedBtn: document.getElementById('btnDeleteSelected'),
      newWatchBtn: document.getElementById('btnNewWatch'),
      newProjectBtn: document.getElementById('btnNewProject'),
      collapseAllBtn: document.getElementById('btnCollapseAll'),
      expandAllBtn: document.getElementById('btnExpandAll'),
      form: document.getElementById('watchForm'),
      formId: document.getElementById('formWatchId'),
      formTitle: document.getElementById('formTitle'),
      formProjectLabel: document.getElementById('formProjectLabel'),
      formProject: document.getElementById('formProject'),
      formName: document.getElementById('formName'),
      formCpes: document.getElementById('formCpes'),
      optNoRejected: document.getElementById('optNoRejected'),
      optIsVulnerable: document.getElementById('optIsVulnerable'),
      optHasKev: document.getElementById('optHasKev'),
      optInsecure: document.getElementById('optInsecure'),
      optMinCvss: document.getElementById('optMinCvss'),
      optApiKey: document.getElementById('optApiKey'),
      optHttpProxy: document.getElementById('optHttpProxy'),
      optHttpsProxy: document.getElementById('optHttpsProxy'),
      optCaBundle: document.getElementById('optCaBundle'),
      optTimeout: document.getElementById('optTimeout'),
      optCveId: document.getElementById('optCveId'),
      optCweId: document.getElementById('optCweId'),
      optCvssV3Severity: document.getElementById('optCvssV3Severity'),
      optCvssV4Severity: document.getElementById('optCvssV4Severity'),
      optCvssV3Metrics: document.getElementById('optCvssV3Metrics'),
      optCvssV4Metrics: document.getElementById('optCvssV4Metrics'),
      apiKeyHint: document.getElementById('apiKeyHint'),
      formWarnings: document.getElementById('formWarnings'),
      btnRun24: document.getElementById('btnRun24'),
      btnRun90: document.getElementById('btnRun90'),
      btnRun120: document.getElementById('btnRun120'),
      btnSaveOnly: document.getElementById('btnSaveOnly'),
      btnDeleteWatch: document.getElementById('btnDeleteWatch'),
      builderToggle: document.getElementById('builderToggle'),
      builderBody: document.getElementById('builderBody'),
      builderOutput: document.getElementById('b_output'),
      builderSuggestions: document.getElementById('builderSuggestions'),
      filterText: document.getElementById('f_text'),
      filterSeverity: document.getElementById('f_sev'),
      filterScore: document.getElementById('f_score'),
      filterKev: document.getElementById('f_kev'),
      filterClear: document.getElementById('f_clear'),
      filterPills: document.getElementById('filterPills'),
      windowLabel: document.getElementById('windowLabel'),
      resCount: document.getElementById('resCount'),
      resBody: document.getElementById('resBody'),
      detailPanel: document.getElementById('detailPanel'),
      detailCve: document.getElementById('d_cve'),
      detailMeta: document.getElementById('d_meta'),
      detailMatched: document.getElementById('d_matched'),
      detailDesc: document.getElementById('d_desc'),
      detailCwes: document.getElementById('d_cwes'),
      detailRefs: document.getElementById('d_refs_list'),
      btnPrev: document.getElementById('btnPrev'),
      btnNext: document.getElementById('btnNext'),
      btnCopyJson: document.getElementById('btnCopyJson'),
      linkNvd: document.getElementById('d_link'),
      btnExportCsv: document.getElementById('btnExportCsv'),
      btnExportNdjson: document.getElementById('btnExportNdjson'),
    };

    const builderFields = [
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
    ].map((id) => document.getElementById(id));

    const api = {
      async getWatchlists() {
        const data = await requestJson('/api/watchlists');
        state.projects = data.projects || [];
        state.lists = data.lists || [];
        renderSidebar();
        populateProjectSelect();
      },
      async createProject(name) {
        return requestJson('/api/projects', {
          method: 'POST',
          body: { name },
        });
      },
      async renameProject(id, name) {
        return requestJson(`/api/projects/${id}`, {
          method: 'PATCH',
          body: { name },
        });
      },
      async deleteProject(id) {
        return requestJson(`/api/projects/${id}`, { method: 'DELETE' });
      },
      async importProject(id, payload) {
        return requestJson(`/api/projects/${id}/import`, {
          method: 'POST',
          body: payload,
        });
      },
      async createWatchlist(payload) {
        return requestJson('/api/watchlists', {
          method: 'POST',
          body: payload,
        });
      },
      async updateWatchlist(id, payload) {
        return requestJson(`/api/watchlists/${id}`, {
          method: 'PUT',
          body: payload,
        });
      },
      async deleteWatchlist(id) {
        return requestJson(`/api/watchlists/${id}`, { method: 'DELETE' });
      },
      async reorder(projectId, order) {
        return requestJson('/api/watchlists/reorder', {
          method: 'POST',
          body: { projectId, order },
        });
      },
      async runWatchlist(id, window) {
        return requestJson('/api/run', {
          method: 'POST',
          body: { watchlistId: id, window },
        });
      },
      async suggestCpe(params) {
        const qs = new URLSearchParams(params);
        return requestJson(`/api/cpe_suggest?${qs.toString()}`);
      },
    };

    function toJsonBody(body) {
      return body instanceof FormData ? body : JSON.stringify(body || {});
    }

    async function requestJson(url, options = {}) {
      const opts = { method: 'GET', headers: { 'X-CSRF-Token': csrfToken } };
      if (options.method) {
        opts.method = options.method;
      }
      if (options.body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = toJsonBody(options.body);
      }
      try {
        const res = await fetch(url, opts);
        if (!res.ok) {
          const text = await res.text();
          throw new Error(text || res.statusText);
        }
        const data = await res.json();
        return data;
      } catch (err) {
        showAlert(err.message || 'Request failed', 'error');
        throw err;
      }
    }

    function saveCollapsed() {
      try {
        window.localStorage.setItem(collapsedKey, JSON.stringify(Array.from(state.collapsed)));
      } catch (err) {
        console.warn('Unable to persist collapsed state', err);
      }
    }

    function showAlert(message, level = 'info', timeout = 5000) {
      if (!dom.alerts) return;
      const box = document.createElement('div');
      box.className = `flash flash--${level}`;
      box.textContent = message;
      dom.alerts.appendChild(box);
      if (timeout) {
        setTimeout(() => {
          box.remove();
        }, timeout);
      }
    }

    function clearAlerts() {
      dom.alerts.innerHTML = '';
    }

    function findWatchlist(id) {
      return state.lists.find((w) => w.id === id) || null;
    }

    function sortedListsFor(projectId) {
      return state.lists
        .filter((w) => w.projectId === projectId)
        .sort((a, b) => (a.order || 0) - (b.order || 0));
    }

    function renderSidebar() {
      if (!dom.projectsContainer) return;
      dom.projectsContainer.innerHTML = '';
      state.projects
        .slice()
        .sort((a, b) => (a.order || 0) - (b.order || 0))
        .forEach((project) => {
          const wrapper = document.createElement('section');
          wrapper.className = 'project-block';
          wrapper.dataset.projectId = project.id;

          const header = document.createElement('div');
          header.className = 'project-header';
          const collapseBtn = document.createElement('button');
          collapseBtn.type = 'button';
          collapseBtn.className = 'link';
          collapseBtn.textContent = state.collapsed.has(project.id) ? '▶' : '▼';
          collapseBtn.addEventListener('click', () => {
            if (state.collapsed.has(project.id)) {
              state.collapsed.delete(project.id);
            } else {
              state.collapsed.add(project.id);
            }
            saveCollapsed();
            renderSidebar();
          });

          const title = document.createElement('span');
          title.className = 'font-semibold flex-1 truncate';
          title.textContent = project.name;

          const count = document.createElement('span');
          const lists = sortedListsFor(project.id);
          const activeCount = lists.length;
          const projectCpes = lists.flatMap((wl) => wl.cpes);
          const projectMatches = state.filteredResults.filter((item) => (item.matchedCPE || []).some((cpe) => projectCpes.includes(cpe))).length;
          count.className = 'text-xs text-slate-500';
          count.textContent = `${activeCount} watch${activeCount === 1 ? '' : 'es'} • ${projectMatches} match${projectMatches === 1 ? '' : 'es'}`;

          const menuBtn = document.createElement('button');
          menuBtn.type = 'button';
          menuBtn.className = 'more-btn';
          menuBtn.textContent = '⋯';
          menuBtn.addEventListener('click', (evt) => {
            evt.preventDefault();
            evt.stopPropagation();
            toggleProjectMenu(wrapper, project.id);
          });

          header.appendChild(collapseBtn);
          header.appendChild(title);
          header.appendChild(count);
          header.appendChild(menuBtn);

          wrapper.appendChild(header);

          const menu = document.createElement('div');
          menu.className = 'menuPanel hidden';
          menu.innerHTML = `
            <button class="menuPanel__item" data-action="rename">Rename</button>
            <button class="menuPanel__item" data-action="import">Import JSON</button>
            <a class="menuPanel__item" data-action="export" href="/api/projects/${project.id}/export">Export JSON</a>
            <button class="menuPanel__item menuPanel__item--danger" data-action="delete">Delete</button>
          `;
          menu.addEventListener('click', (evt) => {
            const target = evt.target;
            if (!(target instanceof HTMLElement)) return;
            const action = target.dataset.action;
            if (!action) return;
            evt.preventDefault();
            handleProjectAction(project.id, action);
            menu.classList.add('hidden');
          });
          wrapper.appendChild(menu);

          const listEl = document.createElement('ul');
          listEl.className = 'project-watchlists';
          if (state.collapsed.has(project.id)) {
            listEl.classList.add('hidden');
          }

          lists.forEach((watch) => {
            const li = document.createElement('li');
            li.className = `watchlist-entry ${state.currentWatchId === watch.id ? 'watchlist-entry--active' : ''}`;
            li.draggable = true;
            li.dataset.id = watch.id;
            li.dataset.projectId = project.id;

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = `wlbox h-4 w-4 mt-0.5 ${state.manageMode ? '' : 'hidden'}`;
            checkbox.checked = state.selectedIds.has(watch.id);
            checkbox.addEventListener('change', () => {
              if (checkbox.checked) {
                state.selectedIds.add(watch.id);
              } else {
                state.selectedIds.delete(watch.id);
              }
              updateBulkState();
            });

            const nameLink = document.createElement('a');
            nameLink.href = '#';
            nameLink.className = 'wlLink min-w-0';
            nameLink.innerHTML = `
              <div class="text-sm font-medium truncate">${watch.name}</div>
              <div class="text-xs text-slate-500 truncate">${watch.cpes.length} CPE${watch.cpes.length === 1 ? '' : 's'}</div>
            `;
            nameLink.addEventListener('click', (evt) => {
              evt.preventDefault();
              if (state.manageMode) return;
              selectWatchlist(watch.id, false);
            });

            const quickContainer = document.createElement('div');
            quickContainer.className = 'entry-actions';
            quickContainer.innerHTML = `
              <button class="quick-btn" data-win="24h">24h</button>
              <button class="quick-btn" data-win="90d">90d</button>
              <button class="quick-btn" data-win="120d">120d</button>
            `;
            quickContainer.querySelectorAll('.quick-btn').forEach((btn) => {
              btn.addEventListener('click', (evt) => {
                evt.preventDefault();
                evt.stopPropagation();
                const win = btn.dataset.win || '24h';
                selectWatchlist(watch.id, true, win);
              });
            });

            li.appendChild(checkbox);
            li.appendChild(nameLink);
            li.appendChild(quickContainer);

            li.addEventListener('dragstart', (evt) => {
              evt.dataTransfer.effectAllowed = 'move';
              evt.dataTransfer.setData('text/plain', watch.id);
              setTimeout(() => {
                li.classList.add('dragging');
              }, 0);
            });
            li.addEventListener('dragend', () => {
              li.classList.remove('dragging');
            });

            listEl.appendChild(li);
          });

          listEl.addEventListener('dragover', (evt) => {
            evt.preventDefault();
            const dragging = document.querySelector('.dragging');
            if (!(dragging instanceof HTMLElement)) return;
            const after = getDragAfterElement(listEl, evt.clientY);
            if (after == null) {
              listEl.appendChild(dragging);
            } else {
              listEl.insertBefore(dragging, after);
            }
          });

          listEl.addEventListener('drop', (evt) => {
            evt.preventDefault();
            const watchId = evt.dataTransfer.getData('text/plain');
            if (!watchId) return;
            const ids = Array.from(listEl.querySelectorAll('li')).map((li) => li.dataset.id).filter(Boolean);
            moveWatchlist(watchId, project.id, ids);
          });

          wrapper.appendChild(listEl);
          dom.projectsContainer.appendChild(wrapper);
        });
    }

    function toggleProjectMenu(wrapper, projectId) {
      wrapper.querySelectorAll('.menuPanel').forEach((panel) => {
        panel.classList.toggle('hidden');
      });
      document.addEventListener(
        'click',
        function handler(evt) {
          if (!(evt.target instanceof Node)) return;
          if (!wrapper.contains(evt.target)) {
            wrapper.querySelectorAll('.menuPanel').forEach((panel) => panel.classList.add('hidden'));
            document.removeEventListener('click', handler);
          }
        },
        { once: true }
      );
    }

    function getDragAfterElement(container, y) {
      const draggableElements = [...container.querySelectorAll('li:not(.dragging)')];
      return draggableElements.reduce(
        (closest, child) => {
          const box = child.getBoundingClientRect();
          const offset = y - box.top - box.height / 2;
          if (offset < 0 && offset > closest.offset) {
            return { offset, element: child };
          }
          return closest;
        },
        { offset: Number.NEGATIVE_INFINITY, element: null }
      ).element;
    }

    async function moveWatchlist(watchId, projectId, orderIds) {
      const watch = findWatchlist(watchId);
      if (!watch) return;
      const oldProject = watch.projectId;
      watch.projectId = projectId;
      watch.order = orderIds.indexOf(watchId);
      const projectOrder = orderIds.filter(Boolean);
      state.lists
        .filter((w) => w.projectId === projectId)
        .forEach((w, idx) => {
          const pos = projectOrder.indexOf(w.id);
          if (pos >= 0) {
            w.order = pos;
          }
        });
      renderSidebar();
      populateProjectSelect();
      try {
        await api.updateWatchlist(watchId, { projectId });
        await api.reorder(projectId, projectOrder);
        if (oldProject !== projectId) {
          await api.reorder(oldProject, sortedListsFor(oldProject).map((w) => w.id));
        }
        showAlert('Watchlist moved.', 'success', 2000);
      } catch (err) {
        console.error('Failed to move watchlist', err);
        api.getWatchlists();
      }
    }

    function populateProjectSelect() {
      if (!dom.formProject) return;
      dom.formProject.innerHTML = '';
      state.projects
        .slice()
        .sort((a, b) => (a.order || 0) - (b.order || 0))
        .forEach((project) => {
          const option = document.createElement('option');
          option.value = project.id;
          option.textContent = project.name;
          dom.formProject.appendChild(option);
        });
      if (state.currentWatchId) {
        const current = findWatchlist(state.currentWatchId);
        if (current) {
          dom.formProject.value = current.projectId;
        }
      }
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
      if (runImmediately) {
        runCurrent(window);
      }
    }

    function clearForm() {
      dom.formId.value = '';
      dom.formTitle.textContent = 'Create watch';
      dom.formProjectLabel.textContent = '';
      dom.formName.value = '';
      dom.formCpes.value = '';
      dom.optNoRejected.checked = true;
      dom.optIsVulnerable.checked = false;
      dom.optHasKev.checked = false;
      dom.optInsecure.checked = false;
      dom.optMinCvss.value = '';
      dom.optApiKey.value = '';
      dom.apiKeyHint.textContent = '';
      dom.optHttpProxy.value = '';
      dom.optHttpsProxy.value = '';
      dom.optCaBundle.value = '';
      dom.optTimeout.value = '';
      dom.optCveId.value = '';
      dom.optCweId.value = '';
      dom.optCvssV3Severity.value = '';
      dom.optCvssV4Severity.value = '';
      dom.optCvssV3Metrics.value = '';
      dom.optCvssV4Metrics.value = '';
      dom.formWarnings.textContent = '';
      if (dom.formProject.options.length > 0) {
        dom.formProject.selectedIndex = 0;
      }
      checkFormWarnings();
    }

    function fillForm(watch) {
      dom.formId.value = watch.id;
      dom.formTitle.textContent = 'Edit watch';
      const project = state.projects.find((p) => p.id === watch.projectId);
      dom.formProjectLabel.textContent = project ? project.name : '';
      dom.formProject.value = watch.projectId;
      dom.formName.value = watch.name || '';
      dom.formCpes.value = watch.cpes.join(', ');
      const options = watch.options || {};
      dom.optNoRejected.checked = options.noRejected !== false;
      dom.optIsVulnerable.checked = Boolean(options.isVulnerable);
      dom.optHasKev.checked = Boolean(options.hasKev);
      dom.optInsecure.checked = Boolean(options.insecure);
      dom.optMinCvss.value = options.minCvss ? String(options.minCvss) : '';
      dom.optHttpProxy.value = options.httpProxy || '';
      dom.optHttpsProxy.value = options.httpsProxy || '';
      dom.optCaBundle.value = options.caBundle || '';
      dom.optTimeout.value = options.timeout || '';
      dom.optCveId.value = options.cveId || '';
      dom.optCweId.value = options.cweId || '';
      dom.optCvssV3Severity.value = options.cvssV3Severity || '';
      dom.optCvssV4Severity.value = options.cvssV4Severity || '';
      dom.optCvssV3Metrics.value = options.cvssV3Metrics || '';
      dom.optCvssV4Metrics.value = options.cvssV4Metrics || '';
      dom.optApiKey.value = '';
      dom.apiKeyHint.textContent = options.hasApiKey ? 'API key stored (leave blank to keep, enter blank space to clear).' : '';
      dom.formWarnings.textContent = '';
      checkFormWarnings();
    }

    function gatherFormData() {
      const payload = {
        name: dom.formName.value,
        projectId: dom.formProject.value,
        cpes: dom.formCpes.value,
        options: {
          noRejected: dom.optNoRejected.checked,
          isVulnerable: dom.optIsVulnerable.checked,
          hasKev: dom.optHasKev.checked,
          insecure: dom.optInsecure.checked,
          minCvss: dom.optMinCvss.value,
          apiKey: dom.optApiKey.value || null,
          httpProxy: dom.optHttpProxy.value || null,
          httpsProxy: dom.optHttpsProxy.value || null,
          caBundle: dom.optCaBundle.value || null,
          timeout: dom.optTimeout.value || null,
          cveId: dom.optCveId.value || null,
          cweId: dom.optCweId.value || null,
          cvssV3Severity: dom.optCvssV3Severity.value || null,
          cvssV4Severity: dom.optCvssV4Severity.value || null,
          cvssV3Metrics: dom.optCvssV3Metrics.value || null,
          cvssV4Metrics: dom.optCvssV4Metrics.value || null,
        },
      };
      if (dom.optApiKey.value === '') {
        payload.options.apiKey = '';
      }
      return payload;
    }

    async function saveWatchlist() {
      const payload = gatherFormData();
      const watchId = dom.formId.value;
      try {
        let response;
        if (watchId) {
          response = await api.updateWatchlist(watchId, payload);
        } else {
          response = await api.createWatchlist(payload);
          state.currentWatchId = response.watchlist?.id || null;
        }
        if (response && response.watchlist) {
          const idx = state.lists.findIndex((w) => w.id === response.watchlist.id);
          if (idx >= 0) {
            state.lists[idx] = response.watchlist;
          } else {
            state.lists.push(response.watchlist);
          }
          renderSidebar();
          populateProjectSelect();
          fillForm(response.watchlist);
          showAlert('Watchlist saved.', 'success', 2000);
          if (Array.isArray(response.warnings) && response.warnings.length) {
            dom.formWarnings.textContent = response.warnings.join(' ');
          } else {
            dom.formWarnings.textContent = '';
          }
        }
      } catch (err) {
        console.error('Save failed', err);
      }
    }

    async function deleteCurrentWatch() {
      const watchId = dom.formId.value;
      if (!watchId) {
        clearForm();
        return;
      }
      if (!confirm('Delete this watchlist?')) {
        return;
      }
      try {
        await api.deleteWatchlist(watchId);
        state.lists = state.lists.filter((w) => w.id !== watchId);
        state.currentWatchId = null;
        clearForm();
        renderSidebar();
        showAlert('Watchlist deleted.', 'success', 2000);
      } catch (err) {
        console.error('Delete failed', err);
      } finally {
        updateBulkState();
      }
    }

    async function runCurrent(window) {
      if (state.pendingRun) {
        return;
      }
      const watchId = dom.formId.value;
      if (!watchId) {
        await saveWatchlist();
      }
      const id = dom.formId.value;
      if (!id) {
        showAlert('Save the watchlist before running.', 'error');
        return;
      }
      state.pendingRun = true;
      try {
        const result = await api.runWatchlist(id, window);
        state.originalResults = result.results || [];
        state.windowLabel = result.windowLabel || '';
        applyFilters();
        showAlert(`Fetched ${state.originalResults.length} CVEs.`, 'success', 2000);
        dom.windowLabel.textContent = `Window: ${state.windowLabel || '—'}`;
      } catch (err) {
        console.error('Run failed', err);
      } finally {
        state.pendingRun = false;
      }
    }

    function applyFilters() {
      const text = (dom.filterText.value || '').toLowerCase();
      const severity = dom.filterSeverity.value || '';
      const minScore = parseFloat(dom.filterScore.value || '');
      const kevOnly = dom.filterKev.checked;
      state.filters = { text, severity, minScore: dom.filterScore.value, kevOnly };
      state.filteredResults = state.originalResults.filter((item) => {
        const hay = `${item.id || ''} ${item.description || ''} ${(item.matchedCPE || []).join(' ')}`.toLowerCase();
        if (text && !hay.includes(text)) {
          return false;
        }
        if (severity && (item.cvssSeverity || '') !== severity) {
          return false;
        }
        if (!Number.isNaN(minScore)) {
          const score = parseFloat(item.cvssScore);
          if (Number.isNaN(score) || score < minScore) {
            return false;
          }
        }
        if (kevOnly && !item.kev) {
          return false;
        }
        return true;
      });
      renderFilterPills();
      sortAndRender();
    }

    function renderFilterPills() {
      if (!dom.filterPills) return;
      dom.filterPills.innerHTML = '';
      const pills = [];
      if (state.filters.text) {
        pills.push({ key: 'text', label: `Search: ${state.filters.text}` });
      }
      if (state.filters.severity) {
        pills.push({ key: 'severity', label: `Severity: ${state.filters.severity}` });
      }
      if (state.filters.minScore) {
        pills.push({ key: 'minScore', label: `Min score: ${state.filters.minScore}` });
      }
      if (state.filters.kevOnly) {
        pills.push({ key: 'kevOnly', label: 'KEV only' });
      }
      pills.forEach((pill) => {
        const el = document.createElement('span');
        el.className = 'pill';
        el.textContent = pill.label;
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = '×';
        btn.addEventListener('click', () => {
          clearFilter(pill.key);
        });
        el.appendChild(btn);
        dom.filterPills.appendChild(el);
      });
    }

    function clearFilter(key) {
      switch (key) {
        case 'text':
          dom.filterText.value = '';
          break;
        case 'severity':
          dom.filterSeverity.value = '';
          break;
        case 'minScore':
          dom.filterScore.value = '';
          break;
        case 'kevOnly':
          dom.filterKev.checked = false;
          break;
        default:
          break;
      }
      applyFilters();
    }

    function sortAndRender() {
      const key = state.sortKey;
      const dir = state.sortDir;
      const accessor = {
        id: (item) => item.id || '',
        sev: (item) => item.cvssSeverity || 'None',
        score: (item) => parseFloat(item.cvssScore) || -1,
        pub: (item) => item.published || '',
        mod: (item) => item.lastModified || '',
      };
      state.filteredResults.sort((a, b) => {
        const va = accessor[key](a);
        const vb = accessor[key](b);
        if (va < vb) return -1 * dir;
        if (va > vb) return 1 * dir;
        return 0;
      });
      renderResults();
    }

    function renderResults() {
      if (!dom.resBody) return;
      dom.resBody.innerHTML = '';
      state.filteredResults.forEach((item, idx) => {
        const tr = document.createElement('tr');
        tr.className = 'border-t hover:bg-slate-50';
        tr.innerHTML = `
          <td class="px-4 py-2 text-indigo-700 underline"><button class="link" data-action="detail">${item.id}</button></td>
          <td class="px-4 py-2">${item.kev ? '✅' : '—'}</td>
          <td class="px-4 py-2"><span class="badge sev-${item.cvssSeverity || 'None'}">${item.cvssSeverity || 'None'}</span></td>
          <td class="px-4 py-2">${item.cvssScore ?? ''}</td>
          <td class="px-4 py-2">${item.published || ''}</td>
          <td class="px-4 py-2">${item.lastModified || ''}</td>
          <td class="px-4 py-2 truncate max-w-[14rem]" title="${(item.matchedCPE || []).join(', ')}">${(item.matchedCPE || []).join(', ')}</td>
          <td class="px-4 py-2 text-sm">
            <button class="link" data-action="copy">Copy JSON</button>
            <a class="link" data-action="open" href="https://nvd.nist.gov/vuln/detail/${item.id}" target="_blank">NVD</a>
          </td>
        `;
        tr.dataset.index = String(idx);
        tr.addEventListener('click', (evt) => {
          if (!(evt.target instanceof HTMLElement)) return;
          const action = evt.target.dataset.action;
          if (action === 'copy') {
            evt.stopPropagation();
            copyJson(item);
            return;
          }
          if (action === 'open') {
            return;
          }
          showDetails(idx);
        });
        dom.resBody.appendChild(tr);
      });
      dom.resCount.textContent = String(state.filteredResults.length);
      if (state.detailIndex >= state.filteredResults.length) {
        state.detailIndex = -1;
      }
      if (state.detailIndex >= 0) {
        showDetails(state.detailIndex);
      } else {
        dom.detailPanel.hidden = true;
      }
    }

    function showDetails(index) {
      const item = state.filteredResults[index];
      if (!item || !dom.detailPanel) return;
      state.detailIndex = index;
      dom.detailPanel.hidden = false;
      dom.detailCve.textContent = item.id || '';
      dom.detailMeta.textContent = `Severity: ${item.cvssSeverity || 'None'} • Score: ${item.cvssScore ?? ''} • Modified: ${item.lastModified || ''}`;
      dom.detailMatched.textContent = (item.matchedCPE || []).length ? `Matched CPE: ${(item.matchedCPE || []).join(', ')}` : '';
      dom.detailDesc.textContent = item.description || '(no description)';
      dom.detailCwes.textContent = (item.cwes || []).length ? `CWE: ${(item.cwes || []).join(', ')}` : '';
      dom.detailRefs.innerHTML = '';
      (item.references || []).forEach((ref) => {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = ref.url || '#';
        a.target = '_blank';
        a.className = 'text-indigo-700 underline';
        a.textContent = ref.tags && ref.tags.length ? ref.tags.join(', ') : ref.source || ref.url || 'link';
        li.appendChild(a);
        dom.detailRefs.appendChild(li);
      });
      dom.linkNvd.href = `https://nvd.nist.gov/vuln/detail/${item.id}`;
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

    function exportCsv() {
      const rows = [
        ['CVE', 'Severity', 'Score', 'Published', 'LastModified', 'MatchedCPE', 'KEV', 'CWEs', 'Description'],
      ];
      state.filteredResults.forEach((item) => {
        rows.push([
          item.id || '',
          item.cvssSeverity || '',
          item.cvssScore ?? '',
          item.published || '',
          item.lastModified || '',
          (item.matchedCPE || []).join(';'),
          item.kev ? 'yes' : '',
          (item.cwes || []).join(';'),
          (item.description || '').replace(/\n/g, ' '),
        ]);
      });
      const body = rows.map((cols) => cols.map(csvEscape).join(',')).join('\n');
      downloadFile(`cve_export_${Date.now()}.csv`, body, 'text/csv');
    }

    function csvEscape(value) {
      const text = String(value ?? '');
      if (/[,\"\n]/.test(text)) {
        return `"${text.replace(/"/g, '""')}"`;
      }
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

    function updateBulkState() {
      if (!dom.selectAllBox) return;
      const visibleIds = Array.from(dom.projectsContainer.querySelectorAll('.watchlist-entry')).map((el) => el.dataset.id).filter(Boolean);
      const selectedVisible = visibleIds.filter((id) => state.selectedIds.has(id));
      dom.selectAllBox.checked = visibleIds.length > 0 && selectedVisible.length === visibleIds.length;
      dom.selectAllBox.indeterminate = selectedVisible.length > 0 && selectedVisible.length < visibleIds.length;
      if (dom.deleteSelectedBtn) {
        dom.deleteSelectedBtn.disabled = !state.manageMode || state.selectedIds.size === 0;
      }
    }

    function toggleSelectMode(on) {
      state.manageMode = on;
      dom.selectModeBtn.textContent = on ? 'Done' : 'Select';
      dom.selectAllBox.disabled = !on;
      if (dom.deleteSelectedBtn) {
        dom.deleteSelectedBtn.classList.toggle('hidden', !on);
      }
      if (!on) {
        state.selectedIds.clear();
        dom.selectAllBox.checked = false;
        dom.selectAllBox.indeterminate = false;
      }
      renderSidebar();
      updateBulkState();
    }

    async function bulkDelete() {
      if (!state.selectedIds.size) return;
      if (!confirm(`Delete ${state.selectedIds.size} watchlist(s)?`)) {
        return;
      }
      try {
        const ids = Array.from(state.selectedIds);
        for (const id of ids) {
          await api.deleteWatchlist(id);
          state.lists = state.lists.filter((w) => w.id !== id);
          if (state.currentWatchId === id) {
            state.currentWatchId = null;
          }
        }
        state.selectedIds.clear();
        renderSidebar();
        showAlert('Watchlists deleted.', 'success', 2000);
      } catch (err) {
        console.error('Bulk delete failed', err);
      } finally {
        updateBulkState();
      }
    }

    async function handleProjectAction(id, action) {
      switch (action) {
        case 'rename': {
          const current = state.projects.find((p) => p.id === id);
          const name = prompt('Project name', current ? current.name : '');
          if (!name) return;
          await api.renameProject(id, name);
          await api.getWatchlists();
          break;
        }
        case 'delete': {
          if (!confirm('Delete project? Projects must be empty.')) return;
          await api.deleteProject(id);
          await api.getWatchlists();
          break;
        }
        case 'import': {
          const input = document.createElement('input');
          input.type = 'file';
          input.accept = 'application/json';
          input.addEventListener('change', async () => {
            const file = input.files?.[0];
            if (!file) return;
            try {
              const text = await file.text();
              const data = JSON.parse(text);
              const resp = await api.importProject(id, data);
              state.projects = resp.projects || state.projects;
              state.lists = resp.lists || state.lists;
              renderSidebar();
              if (Array.isArray(resp.warnings) && resp.warnings.length) {
                showAlert(resp.warnings.join(' '), 'info', 6000);
              }
            } catch (err) {
              showAlert('Import failed', 'error');
              console.error(err);
            }
          });
          input.click();
          break;
        }
        default:
          break;
      }
    }

    function initBuilder() {
      updateBuilderOutput();
      builderFields.forEach((field) => {
        field?.addEventListener('input', () => {
          updateBuilderOutput();
          scheduleSuggestions();
        });
      });
      dom.builderToggle?.addEventListener('click', (evt) => {
        evt.preventDefault();
        if (!dom.builderBody) return;
        dom.builderBody.classList.toggle('hidden');
        dom.builderToggle.textContent = dom.builderBody.classList.contains('hidden') ? 'Show' : 'Hide';
      });
      dom.builderOutput.textContent = buildCpe();
      const buildBtn = document.getElementById('b_build');
      const addBtn = document.getElementById('b_add');
      buildBtn?.addEventListener('click', (evt) => {
        evt.preventDefault();
        updateBuilderOutput();
      });
      addBtn?.addEventListener('click', (evt) => {
        evt.preventDefault();
        updateBuilderOutput();
        if (!dom.builderOutput || !dom.formCpes) return;
        const value = dom.builderOutput.textContent.trim();
        if (!value) return;
        const existing = dom.formCpes.value.trim();
        dom.formCpes.value = existing ? `${existing.replace(/\s*$/, '')}, ${value}` : value;
      });
    }

    function escapeSegment(value) {
      if (!value) return '*';
      return value.replace(/\\/g, '\\\\').replace(/:/g, '\\:');
    }

    function buildCpe() {
      const values = builderFields.map((field, idx) => {
        if (!field) return '*';
        const raw = 'value' in field ? field.value : '';
        return escapeSegment(raw.trim());
      });
      const part = values.shift() || 'o';
      return `cpe:2.3:${part}:${values.join(':')}`;
    }

    function updateBuilderOutput() {
      if (!dom.builderOutput) return;
      dom.builderOutput.textContent = buildCpe();
    }

    let suggestTimer = null;
    function scheduleSuggestions() {
      clearTimeout(suggestTimer);
      suggestTimer = setTimeout(fetchSuggestions, 400);
    }

    async function fetchSuggestions() {
      const payload = {
        part: document.getElementById('b_part')?.value || '*',
        vendor: document.getElementById('b_vendor')?.value || '',
        product: document.getElementById('b_product')?.value || '',
        version: document.getElementById('b_version')?.value || '',
        limit: 50,
      };
      if (!payload.vendor && !payload.product && !payload.version) {
        dom.builderSuggestions?.classList.add('hidden');
        dom.builderSuggestions.innerHTML = '';
        return;
      }
      try {
        const data = await api.suggestCpe(payload);
        const items = data.items || [];
        if (!items.length) {
          dom.builderSuggestions?.classList.add('hidden');
          dom.builderSuggestions.innerHTML = '';
          return;
        }
        const list = document.createElement('ul');
        list.className = 'space-y-1';
        items.slice(0, 20).forEach((item) => {
          const li = document.createElement('li');
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'suggestion';
          btn.textContent = item.cpeName;
          btn.addEventListener('click', () => {
            dom.formCpes.value = dom.formCpes.value ? `${dom.formCpes.value.replace(/\s*$/, '')}, ${item.cpeName}` : item.cpeName;
          });
          li.appendChild(btn);
          list.appendChild(li);
        });
        dom.builderSuggestions.innerHTML = '';
        dom.builderSuggestions.appendChild(list);
        dom.builderSuggestions.classList.remove('hidden');
      } catch (err) {
        console.error('Suggestion fetch failed', err);
      }
    }

    function initEvents() {
      dom.searchInput?.addEventListener('input', () => {
        const query = (dom.searchInput.value || '').toLowerCase();
        dom.projectsContainer.querySelectorAll('.watchlist-entry').forEach((entry) => {
          const watch = findWatchlist(entry.dataset.id);
          if (!watch) return;
          const hay = `${watch.name} ${watch.cpes.join(' ')}`.toLowerCase();
          entry.classList.toggle('hidden', Boolean(query) && !hay.includes(query));
        });
      });

      dom.selectModeBtn?.addEventListener('click', (evt) => {
        evt.preventDefault();
        toggleSelectMode(!state.manageMode);
      });

      dom.selectAllBox?.addEventListener('change', () => {
        const check = dom.selectAllBox.checked;
        state.selectedIds.clear();
        dom.projectsContainer.querySelectorAll('.watchlist-entry').forEach((entry) => {
          if (!entry.classList.contains('hidden')) {
            const id = entry.dataset.id;
            if (!id) return;
            const box = entry.querySelector('.wlbox');
            if (box instanceof HTMLInputElement) {
              box.checked = check;
            }
            if (check) {
              state.selectedIds.add(id);
            }
          }
        });
        updateBulkState();
      });

      dom.newWatchBtn?.addEventListener('click', (evt) => {
        evt.preventDefault();
        state.currentWatchId = null;
        clearForm();
        renderSidebar();
      });

      dom.newProjectBtn?.addEventListener('click', async (evt) => {
        evt.preventDefault();
        const name = prompt('Project name', 'New Project');
        if (!name) return;
        await api.createProject(name);
        await api.getWatchlists();
      });

      dom.collapseAllBtn?.addEventListener('click', (evt) => {
        evt.preventDefault();
        state.projects.forEach((p) => state.collapsed.add(p.id));
        saveCollapsed();
        renderSidebar();
      });

      dom.expandAllBtn?.addEventListener('click', (evt) => {
        evt.preventDefault();
        state.collapsed.clear();
        saveCollapsed();
        renderSidebar();
      });

      dom.btnRun24?.addEventListener('click', () => runCurrent('24h'));
      dom.btnRun90?.addEventListener('click', () => runCurrent('90d'));
      dom.btnRun120?.addEventListener('click', () => runCurrent('120d'));
      dom.btnSaveOnly?.addEventListener('click', () => {
        saveWatchlist();
      });
      dom.btnDeleteWatch?.addEventListener('click', (evt) => {
        evt.preventDefault();
        deleteCurrentWatch();
      });

      dom.deleteSelectedBtn?.addEventListener('click', (evt) => {
        evt.preventDefault();
        bulkDelete();
      });

      dom.filterText?.addEventListener('input', applyFilters);
      dom.filterSeverity?.addEventListener('change', applyFilters);
      dom.filterScore?.addEventListener('input', applyFilters);
      dom.filterKev?.addEventListener('change', applyFilters);
      dom.filterClear?.addEventListener('click', (evt) => {
        evt.preventDefault();
        dom.filterText.value = '';
        dom.filterSeverity.value = '';
        dom.filterScore.value = '';
        dom.filterKev.checked = false;
        applyFilters();
      });

      document.querySelectorAll('th.sortable').forEach((th) => {
        th.addEventListener('click', () => {
          const key = th.dataset.k;
          if (!key) return;
          if (state.sortKey === key) {
            state.sortDir = -state.sortDir;
          } else {
            state.sortKey = key;
            state.sortDir = key === 'score' || key === 'mod' || key === 'pub' ? -1 : 1;
          }
          sortAndRender();
        });
      });

      dom.btnPrev?.addEventListener('click', () => {
        if (state.detailIndex > 0) {
          showDetails(state.detailIndex - 1);
        }
      });
      dom.btnNext?.addEventListener('click', () => {
        if (state.detailIndex >= 0 && state.detailIndex < state.filteredResults.length - 1) {
          showDetails(state.detailIndex + 1);
        }
      });
      dom.btnCopyJson?.addEventListener('click', () => {
        if (state.detailIndex >= 0) {
          copyJson(state.filteredResults[state.detailIndex]);
        }
      });

      dom.btnExportCsv?.addEventListener('click', exportCsv);
      dom.btnExportNdjson?.addEventListener('click', exportNdjson);

      window.addEventListener('keydown', (evt) => {
        if (evt.target && (evt.target.tagName === 'INPUT' || evt.target.tagName === 'TEXTAREA')) {
          return;
        }
        if (evt.key === 'Delete') {
          if (state.manageMode && state.selectedIds.size) {
            evt.preventDefault();
            bulkDelete();
          }
        } else if (evt.key.toLowerCase() === 'a') {
          evt.preventDefault();
          toggleSelectMode(true);
          dom.selectAllBox.checked = true;
          dom.selectAllBox.dispatchEvent(new Event('change'));
        } else if (evt.key.toLowerCase() === 'n') {
          evt.preventDefault();
          state.currentWatchId = null;
          clearForm();
          renderSidebar();
        } else if (evt.key.toLowerCase() === 'p') {
          evt.preventDefault();
          dom.newProjectBtn.click();
        } else if (evt.key === 'ArrowLeft' && state.detailIndex > 0) {
          showDetails(state.detailIndex - 1);
        } else if (evt.key === 'ArrowRight' && state.detailIndex >= 0 && state.detailIndex < state.filteredResults.length - 1) {
          showDetails(state.detailIndex + 1);
        }
      });

      dom.optIsVulnerable?.addEventListener('change', checkFormWarnings);
      dom.formCpes?.addEventListener('input', checkFormWarnings);
      dom.optApiKey?.addEventListener('input', () => {
        if (dom.optApiKey.value === '') {
          dom.apiKeyHint.textContent = 'API key cleared on save.';
        }
      });
    }

    function checkFormWarnings() {
      const isVuln = dom.optIsVulnerable.checked;
      if (!isVuln) {
        dom.formWarnings.textContent = '';
        return;
      }
      const cpes = dom.formCpes.value.split(',').map((s) => s.trim()).filter(Boolean);
      const warning = cpes.some((cpe) => /:\*(:|$)/.test(cpe))
        ? 'Warning: isVulnerable requires specific versions. Wildcards may cause 400 responses.'
        : '';
      dom.formWarnings.textContent = warning;
    }

    function init() {
      renderSidebar();
      populateProjectSelect();
      initBuilder();
      initEvents();
      if (state.currentWatchId) {
        const watch = findWatchlist(state.currentWatchId);
        if (watch) {
          fillForm(watch);
        } else {
          clearForm();
        }
      } else {
        clearForm();
      }
      state.originalResults = state.originalResults || [];
      applyFilters();
      if (state.windowLabel) {
        dom.windowLabel.textContent = `Window: ${state.windowLabel}`;
      }
    }

    return { init };
  }
})();

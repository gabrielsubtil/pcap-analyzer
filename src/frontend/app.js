// App Logic - Vanilla JS
// Replica comportamentos do React app original

const app = {
    state: {
        files: [],
        report: null,
        viewMode: 'dashboard', // dashboard, strings, threats
        stringFilter: null,
        catalog: [],
        loadedStrings: [],
        stringsOffset: 0,
        hasMoreStrings: true,
        isLoadingStrings: false,
        stringFilterTypes: [],
        dashboardRendered: false,
        dashboardLimits: {
            sizes: 10,
            talkersSrc: 10,
            talkersDst: 10,
            portsSrc: 10,
            portsDst: 10
        },
        loadedDns: [],
        dnsOffset: 0,
        hasMoreDns: true,
        isLoadingDns: false
    },

    init: async function () {
        console.log("App initialized");
        this.bindEvents();
        // Carrega catalogo do backend assim que a bridge estiver pronta
        window.addEventListener('pywebviewready', async () => {
            try {
                const catalog = await window.pywebview.api.get_catalog();
                this.state.catalog = catalog;

                // Build map for quick lookup in UI (Port Highlights)
                this.state.suspiciousPortsMap = {};
                catalog.forEach(item => {
                    if (item.id.startsWith('suspicious_port_')) {
                        const p = parseInt(item.id.replace('suspicious_port_', ''));
                        if (!isNaN(p)) {
                            this.state.suspiciousPortsMap[p] = item.title;
                        }
                    }
                });

                this.renderThreatsCatalog();
            } catch (e) {
                console.error("Erro ao carregar catálogo:", e);
            }
        });
    },

    bindEvents: function () {
        // Dropzone
        const dropzone = document.getElementById('dropzone');

        dropzone.addEventListener('click', () => this.pickFiles());

        this.bindContextMenu();

        // Drag & Drop visual feedback (opcional - pywebview lida bem com input file, mas aqui usaremos dialog nativo via click)
        // Para drag and drop de arquivos reais funcionar no webview, é complexo sem events nativos.
        // Vamos focar no click por enquanto.

        // Botões de Navegação (já possuem onclicks no HTML, mas poderiam ser bindados aqui)
    },

    bindContextMenu: function () {
        const menu = document.getElementById('custom-context-menu');

        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            const selection = window.getSelection().toString();

            if (selection.length > 0) {
                menu.style.display = 'block';
                // Garante que o menu não saia da tela
                let x = e.pageX;
                let y = e.pageY;

                if (x + 150 > window.innerWidth) x -= 130;
                if (y + 40 > window.innerHeight) y -= 40;

                menu.style.left = `${x}px`;
                menu.style.top = `${y}px`;
            } else {
                menu.style.display = 'none';
            }
        });

        document.addEventListener('click', () => {
            menu.style.display = 'none';
        });
    },

    copySelection: function () {
        document.execCommand('copy');
        document.getElementById('custom-context-menu').style.display = 'none';
    },

    pickFiles: async function () {
        // Pywebview 5.x+ tem api de file dialog nativa injetada?
        // Se nao, chamamos backend. Mas window.pywebview.api.dialog não existe.
        // O pywebview cria window.pywebview.api para nossa classe Api.
        // Precisamos usar inputs file hidden se quisermos nativo do browser engine ou...
        // IMPLEMENTAÇÃO: Vamos criar um input file dinamicamente, clicar nele, e pegar o resultado.
        // Porém, input file não dá full path para o Python ler.
        // SOLUÇÃO: Vamos pedir pro Python abrir o dialog.
        // Precisamos adicionar open_file_dialog no boot.py?
        // Sim, seria melhor. Mas wait!
        // O usuário pediu "Satinizar...".
        // Vamos tentar usar input type file. Se o pywebview estiver configurado corretamente,
        // ele pode não conseguir ler o arquivo local via JS FileReader se for muito grande (bloqueio de memoria).
        // Mas a abordagem correta para app desktop é o Python ler o arquivo pelo PATH.
        // O Chrome/Edge não entrega o PATH no input file.
        // Então TEMOS que abrir o dialog pelo Python (backend).

        // Como não adicionei open_file_dialog no boot.py ainda, vou adicionar um input file modificado
        // que envia s o arquivo via JS para o Python? Não, parser é Python.
        // Vou assumir que vou adicionar um método pick_files no boot.py.
        // (Vou fazer essa alteração no próximo passo se falhar, mas vou codar o JS assumindo que existe ou que vou chamar API.pick_files())

        // UPDATE: Vou usar window.pywebview.api.pick_files() E adicionar no backend.
        // Se eu não adicionar, vai falhar.
        // Vou adicionar a chamada aqui.
        try {
            const filePaths = await window.pywebview.api.pick_files();
            if (filePaths && filePaths.length > 0) {
                this.handleFilesSelected(filePaths);
            }
        } catch (e) {
            console.error("Erro ao abrir dialog:", e);
            // Fallback: mostrar erro
            this.showError("Erro ao abrir seletor de arquivos. A API Python não respondeu.");
        }
    },

    handleFilesSelected: function (paths) {
        if (paths.length > 50) {
            this.showError('Máximo de 50 arquivos permitidos.');
            return;
        }

        // Simula objetos File apenas com nome/path para UI
        this.state.files = paths.map(p => ({
            name: p.split(/[\\/]/).pop(), // Extrai nome do arquivo
            path: p
        }));

        this.renderUploadState();
    },

    renderUploadState: function () {
        const dropzoneContent = document.getElementById('dropzone-content');
        const dropzoneSelected = document.getElementById('dropzone-selected');
        const dropzoneIcon = document.getElementById('dropzone-icon');
        const btnAnalyze = document.getElementById('btn-analyze');
        const selectedName = document.getElementById('selected-name');
        const selectedCount = document.getElementById('selected-count');

        if (this.state.files.length > 0) {
            dropzoneContent.classList.add('hidden');
            dropzoneSelected.classList.remove('hidden');

            // Estilo ativo
            dropzoneIcon.classList.remove('bg-slate-800');
            dropzoneIcon.classList.add('bg-blue-500');
            dropzoneIcon.innerHTML = `<i data-lucide="files" class="w-10 h-10 text-white"></i>`;

            selectedCount.innerText = `${this.state.files.length} arquivo(s)`;
            selectedName.innerText = this.state.files[0].name + (this.state.files.length > 1 ? ` + ${this.state.files.length - 1} outros` : '');

            btnAnalyze.disabled = false;
            btnAnalyze.classList.remove('bg-slate-800', 'text-slate-600', 'cursor-not-allowed');
            btnAnalyze.classList.add('bg-blue-600', 'text-white', 'hover:bg-blue-500'); // hover effects via css classes

        } else {
            dropzoneContent.classList.remove('hidden');
            dropzoneSelected.classList.add('hidden');

            dropzoneIcon.classList.remove('bg-blue-500');
            dropzoneIcon.classList.add('bg-slate-800');
            dropzoneIcon.innerHTML = `<i data-lucide="upload" class="w-10 h-10 text-slate-400"></i>`;

            btnAnalyze.disabled = true;
            btnAnalyze.classList.add('bg-slate-800', 'text-slate-600', 'cursor-not-allowed');
            btnAnalyze.classList.remove('bg-blue-600', 'text-white');
        }
        lucide.createIcons();
    },

    clearFiles: function () {
        this.state.files = [];
        this.renderUploadState();
        this.hideError();
    },

    analyze: async function () {
        if (this.state.files.length === 0) return;

        // UI State: Loading
        document.getElementById('btn-analyze').classList.add('hidden');
        document.getElementById('progress-container').classList.remove('hidden');

        // Simula progresso visual (já que Python executa em bloco por enquanto)
        // Se o Python suportasse yield progresso, seria melhor.
        const progressBar = document.getElementById('progress-bar');
        progressBar.style.width = '30%';

        try {
            // Chama backend
            const report = await window.pywebview.api.analyze_files(this.state.files.map(f => f.path));

            progressBar.style.width = '100%';

            if (report.error) {
                throw new Error(report.error);
            }

            this.state.report = report;
            this.state.dashboardRendered = false;

            // Reset Limits
            this.state.dashboardLimits = {
                sizes: 10,
                talkersSrc: 10,
                talkersDst: 10,
                portsSrc: 10,
                portsDst: 10
            };

            // Reset strings pagination
            this.state.loadedStrings = [];
            this.state.stringsOffset = 0;
            this.state.hasMoreStrings = true;
            this.state.stringFilter = null;
            this.state.stringFilter = null;
            this.state.stringFilterTypes = [];

            // Reset DNS pagination
            this.state.loadedDns = [];
            this.state.dnsOffset = 0;
            this.state.hasMoreDns = true;

            // Delay para transição suave
            setTimeout(() => {
                this.setView('dashboard');
            }, 500);

        } catch (e) {
            console.error(e);
            this.showError(e.message || "Erro desconhecido na análise.");
            // Reset loading UI
            document.getElementById('btn-analyze').classList.remove('hidden');
            document.getElementById('progress-container').classList.add('hidden');
            progressBar.style.width = '0%';
        }
    },

    setView: function (mode) {
        this.state.viewMode = mode;

        // Toggle Views
        document.getElementById('view-upload').classList.add('hidden');
        document.getElementById('view-dashboard').classList.add('hidden');
        document.getElementById('view-strings').classList.add('hidden');
        document.getElementById('view-dns').classList.add('hidden');
        document.getElementById('view-threats').classList.add('hidden');

        // Show active
        if (mode === 'dashboard') {
            document.getElementById('view-dashboard').classList.remove('hidden');
            this.renderDashboard();
        } else if (mode === 'strings') {
            document.getElementById('view-strings').classList.remove('hidden');
            this.renderStringsView();
        } else if (mode === 'dns') {
            document.getElementById('view-dns').classList.remove('hidden');
            this.renderDnsView();
        } else if (mode === 'threats') {
            document.getElementById('view-threats').classList.remove('hidden');
            // Já renderizado no init, mas ok
        }

        // Se report existe, mostra header actions
        if (this.state.report) {
            document.getElementById('nav-actions').classList.remove('hidden');
            // Atualiza botões ativos
            ['dashboard', 'strings', 'dns', 'threats'].forEach(m => {
                const btn = document.getElementById(`btn-${m}`);
                if (mode === m) {
                    btn.classList.remove('bg-slate-800', 'text-slate-400', 'hover:bg-slate-700');
                    btn.classList.add('bg-blue-600', 'text-white');
                } else {
                    btn.classList.add('bg-slate-800', 'text-slate-400', 'hover:bg-slate-700');
                    btn.classList.remove('bg-blue-600', 'text-white');
                }
            });
        }
        lucide.createIcons();
    },

    reset: function () {
        this.state.files = [];
        this.state.report = null;
        this.state.stringFilter = null;

        document.getElementById('nav-actions').classList.add('hidden');
        document.getElementById('btn-analyze').classList.remove('hidden');
        document.getElementById('progress-container').classList.add('hidden');
        document.getElementById('progress-bar').style.width = '0%';

        document.getElementById('view-dashboard').classList.add('hidden');
        document.getElementById('view-strings').classList.add('hidden');
        document.getElementById('view-dns').classList.add('hidden');
        document.getElementById('view-threats').classList.add('hidden');
        document.getElementById('view-upload').classList.remove('hidden');

        this.renderUploadState();
    },

    renderDashboard: function () {
        const report = this.state.report;
        if (!report) return;

        // --- Cards de Topo ---
        // Ameaças
        const threatsContainer = document.getElementById('card-threats-container');
        if (report.threatStats.length > 0) {
            let html = `
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col max-h-80">
                    <h3 class="text-lg font-bold text-white mb-4 flex items-center gap-2 flex-shrink-0">
                        <i data-lucide="shield-alert" class="w-5 h-5 text-red-500"></i>
                        <span><span class="text-red-400 mr-2">${report.threatStats.length}</span>Ameaças Identificadas</span>
                    </h3>
                    <div class="space-y-3 overflow-y-auto custom-scrollbar pr-2 flex-grow">
            `;
            html += report.threatStats.map(t => `
                <div class="flex items-center justify-between border-b border-slate-800/50 pb-2 mb-2 last:border-0 last:mb-0 last:pb-0">
                     <div class="flex flex-col gap-1">
                        <div class="flex items-center gap-2">
                            <div class="px-2 py-1 rounded text-xs font-mono font-bold bg-red-500/20 text-red-400">
                                ${t.title}
                            </div>
                        </div>
                        <span class="text-xs text-slate-500 ml-1">${t.description}</span>
                     </div>
                     <span class="text-xs text-slate-500 font-mono">${t.count} pkts</span>
                </div>
            `).join('');
            html += `</div></div>`;
            threatsContainer.innerHTML = html;
        } else {
            threatsContainer.innerHTML = `
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col max-h-80 justify-center">
                    <div class="flex items-center gap-4">
                        <div class="p-3 bg-emerald-500/20 rounded-full text-emerald-400">
                             <i data-lucide="shield-check" class="w-6 h-6"></i>
                        </div>
                        <div>
                            <h3 class="text-emerald-400 font-bold">Nenhuma ameaça crítica</h3>
                            <p class="text-emerald-500/60 text-sm">A análise baseada em assinaturas não encontrou padrões maliciosos óbvios.</p>
                        </div>
                    </div>
                </div>
            `;
        }

        this.renderSizesCard();
        this.renderStatsGrid();

        // Lists Renderers
        this.renderList('list-talkers-src', report.topTalkers, report.totalPackets, 'text-blue-400', 'bg-blue-600', 'talkersSrc');
        this.renderList('list-talkers-dst', report.topDestinations, report.totalPackets, 'text-purple-400', 'bg-purple-600', 'talkersDst');

        this.renderPorts('list-ports-src', report.srcPortStats, 'portsSrc');
        this.renderPorts('list-ports-dst', report.portStats, 'portsDst');

        lucide.createIcons();
    },

    renderSizesCard: function () {
        const report = this.state.report;
        const limit = this.state.dashboardLimits.sizes;
        const sortedSizes = Object.entries(report.packetSizeStats)
            .sort(([, a], [, b]) => b - a);

        const hasMore = sortedSizes.length > limit;
        const visibleSizes = sortedSizes.slice(0, limit);

        const sizesContainer = document.getElementById('card-sizes-container');
        let sizesHtml = `
             <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col max-h-80">
                <h3 class="text-lg font-bold text-white mb-4 flex items-center gap-2 flex-shrink-0">
                    <i data-lucide="bar-chart-3" class="w-5 h-5 text-indigo-400"></i>
                    Tamanhos de Pacote Comuns
                </h3>
                <div id="list-sizes" class="space-y-3 overflow-y-auto custom-scrollbar pr-2 flex-grow">
        `;
        sizesHtml += visibleSizes.map(([size, count]) => `
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="px-2 py-1 rounded text-xs font-mono font-bold bg-slate-800 text-slate-400">${size} Bytes</div>
                </div>
                <span class="text-xs text-slate-500 font-mono">${count} pkts</span>
            </div>
        `).join('');

        if (hasMore) {
            sizesHtml += `
                <div class="pt-2 text-center">
                    <button onclick="app.loadMoreDashboard('sizes')" class="text-xs text-blue-400 hover:text-blue-300 transition-colors bg-blue-500/10 hover:bg-blue-500/20 px-3 py-1 rounded font-medium w-full">
                        Carregar mais 10...
                    </button>
                </div>
            `;
        }

        sizesHtml += `</div></div>`;
        sizesContainer.innerHTML = sizesHtml;
    },

    renderStatsGrid: function () {
        // Just extracts the grid generation to clean up renderDashboard
        const report = this.state.report;
        const statsGrid = document.getElementById('stats-grid');
        statsGrid.innerHTML = `
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                <div class="text-slate-500 text-xs font-bold uppercase tracking-wider mb-1">Pacotes</div>
                <div class="text-2xl font-mono text-white">${report.totalPackets.toLocaleString()}</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                <div class="text-slate-500 text-xs font-bold uppercase tracking-wider mb-1">Volume</div>
                <div class="text-2xl font-mono text-white">${this.formatBytes(report.totalBytes)}</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                <div class="text-slate-500 text-xs font-bold uppercase tracking-wider mb-2">Endereços</div>
                <div class="flex justify-between items-end">
                    <div>
                        <div class="text-xs text-slate-500 mb-0.5">Origem</div>
                        <div class="text-xl font-mono text-white">${report.uniqueSrcIpsCount}</div>
                    </div>
                    <div class="text-right">
                         <div class="text-xs text-slate-500 mb-0.5">Destino</div>
                         <div class="text-xl font-mono text-white">${report.uniqueDstIpsCount}</div>
                    </div>
                </div>
            </div>
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                <div class="text-slate-500 text-xs font-bold uppercase tracking-wider mb-1">Protocolos</div>
                <div class="flex gap-2 mt-1 flex-wrap">
                    ${Object.keys(report.protocolStats).map(p => `<span class="px-2 py-0.5 bg-slate-800 rounded text-xs text-slate-300">${p}</span>`).join('')}
                </div>
            </div>
        `;
    },

    loadMoreDashboard: function (type) {
        if (this.state.dashboardLimits[type]) {
            this.state.dashboardLimits[type] += 10;
        }

        // Re-render specific component based on type
        const report = this.state.report;
        if (type === 'sizes') {
            this.renderSizesCard();
        } else if (type === 'talkersSrc') {
            this.renderList('list-talkers-src', report.topTalkers, report.totalPackets, 'text-blue-400', 'bg-blue-600', 'talkersSrc');
        } else if (type === 'talkersDst') {
            this.renderList('list-talkers-dst', report.topDestinations, report.totalPackets, 'text-purple-400', 'bg-purple-600', 'talkersDst');
        } else if (type === 'portsSrc') {
            this.renderPorts('list-ports-src', report.srcPortStats, 'portsSrc');
        } else if (type === 'portsDst') {
            this.renderPorts('list-ports-dst', report.portStats, 'portsDst');
        }
        lucide.createIcons();
    },

    renderList: function (elementId, items, total, colorClass, barColorClass, limitType) {
        const el = document.getElementById(elementId);
        const limit = this.state.dashboardLimits[limitType];

        if (items.length === 0) { el.innerHTML = `<p class="text-slate-600 text-sm">Nenhum dado.</p>`; return; }

        const hasMore = items.length > limit;
        const visibleItems = items.slice(0, limit);

        let html = visibleItems.map(([label, count], idx) => `
             <div class="flex items-center justify-between group">
                <div class="flex items-center gap-3">
                    <span class="text-slate-600 font-mono text-sm w-8 text-right">${idx + 1}</span>
                    <div class="font-mono text-slate-300 group-hover:${colorClass} transition-colors">${label}</div>
                </div>
                <div class="flex items-center gap-3">
                    <div class="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div class="h-full ${barColorClass} rounded-full" style="width: ${(count / total) * 100}%"></div>
                    </div>
                    <span class="text-xs text-slate-500 font-mono w-12 text-right">${count}</span>
                </div>
             </div>
        `).join('');

        if (hasMore) {
            html += `
                <div class="pt-2 text-center">
                    <button onclick="app.loadMoreDashboard('${limitType}')" class="text-xs text-blue-400 hover:text-blue-300 transition-colors bg-blue-500/10 hover:bg-blue-500/20 px-3 py-1 rounded font-medium w-full">
                        Carregar mais 10...
                    </button>
                </div>
            `;
        }

        el.innerHTML = html;
    },

    renderPorts: function (elementId, portStats, limitType) {
        const el = document.getElementById(elementId);
        const sorted = Object.entries(portStats).sort(([, a], [, b]) => b - a);
        const limit = this.state.dashboardLimits[limitType];

        if (sorted.length === 0) { el.innerHTML = `<p class="text-slate-600 text-sm">Nenhum dado.</p>`; return; }

        const hasMore = sorted.length > limit;
        const visibleItems = sorted.slice(0, limit);

        let html = visibleItems.map(([port, count]) => {
            const isNull = port === '_null';
            const label = isNull ? 'Vazio' : port;
            // Style null differently or keep basic style
            const styleClass = isNull ? 'bg-slate-700 text-slate-500 italic' : (this.state.suspiciousPortsMap && this.state.suspiciousPortsMap[port] ? 'bg-red-500/20 text-red-400' : 'bg-slate-800 text-slate-400');

            // Logic for suspicious check (only if not null)
            const threatDesc = !isNull && this.state.suspiciousPortsMap ? this.state.suspiciousPortsMap[port] : null;
            const isSuspicious = !!threatDesc;

            return `
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="px-2 py-1 rounded text-xs font-mono font-bold ${styleClass}">
                        ${label}
                    </div>
                    ${isSuspicious ? `<span class="text-xs text-red-500/70">${threatDesc}</span>` : ''}
                </div>
                <span class="text-xs text-slate-500 font-mono">${count} pkts</span>
            </div>
            `;
        }).join('');

        if (hasMore) {
            html += `
                <div class="pt-2 text-center">
                    <button onclick="app.loadMoreDashboard('${limitType}')" class="text-xs text-blue-400 hover:text-blue-300 transition-colors bg-blue-500/10 hover:bg-blue-500/20 px-3 py-1 rounded font-medium w-full">
                        Carregar mais 10...
                    </button>
                </div>
            `;
        }

        el.innerHTML = html;
    },

    renderStringsView: async function (append = false) {
        if (!this.state.report) return;

        const listEl = document.getElementById('strings-list');
        const filtersEl = document.getElementById('strings-filters');

        // Se não é append (primeira carga ou filtro mudou), limpa lista
        if (!append) {
            listEl.innerHTML = '<div class="text-center py-10 text-slate-500">Carregando strings...</div>';
            this.state.loadedStrings = [];
            this.state.stringsOffset = 0;
            this.state.hasMoreStrings = true;

            // Fetch filters only once
            try {
                this.state.stringFilterTypes = await window.pywebview.api.get_string_filter_types();
            } catch (e) { console.error(e); }
        }

        // Render Filters (From API types)
        if (this.state.stringFilterTypes.length > 0) {
            filtersEl.innerHTML = this.state.stringFilterTypes.map(type => {
                const isActive = this.state.stringFilter === type;
                let colorClass = 'bg-red-500/20 text-red-400 border-red-500/20';
                return `
                <button onclick="app.filterStrings('${type}')" 
                    class="px-2 py-1 rounded text-xs font-mono font-bold border transition-all flex items-center gap-2 ${colorClass} ${isActive ? 'ring-2 ring-offset-1 ring-offset-slate-900 ring-blue-500' : 'opacity-80 hover:opacity-100'}">
                    ${type}
                    ${isActive ? '<i data-lucide="x" class="w-3 h-3"></i>' : ''}
                </button>
                `;
            }).join('');
        } else {
            filtersEl.innerHTML = '';
        }

        // Fetch Data batch
        const LIMIT = 50;
        try {
            this.state.isLoadingStrings = true;
            const newStrings = await window.pywebview.api.get_analysis_strings(
                LIMIT,
                this.state.stringsOffset,
                this.state.stringFilter
            );

            this.state.isLoadingStrings = false;

            if (newStrings.length < LIMIT) {
                this.state.hasMoreStrings = false;
            }

            this.state.loadedStrings = append ? [...this.state.loadedStrings, ...newStrings] : newStrings;
            this.state.stringsOffset += newStrings.length;

            // Build List HTML
            const itemsHtml = this.state.loadedStrings.map(item => `
                <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition-colors">
                        <div class="mb-3">
                        <div class="flex items-center gap-2 mb-1">
                            <i data-lucide="alert-octagon" class="w-4 h-4 text-red-500"></i>
                            <span class="text-sm font-bold text-red-400">${item.threatType}</span>
                        </div>
                        <div class="text-sm text-slate-400 mb-2">${item.threatDesc}</div>
                        ${item.threatExplanation ? `<div class="text-xs text-slate-500 mb-2 leading-relaxed">${item.threatExplanation}</div>` : ''}
                        <div class="text-xs font-mono text-slate-500">${item.count} pacotes com a mesma string</div>
                    </div>
                    <div class="bg-slate-900/50 rounded-lg p-3 border border-slate-800/50">
                        <pre class="text-[10px] text-slate-300 font-mono whitespace-pre-wrap break-all overflow-hidden leading-relaxed select-text">"${item.payload}"</pre>
                    </div>
                </div>
                </div>
            `).join('');

            // Container Update
            if (this.state.loadedStrings.length > 0) {
                listEl.innerHTML = itemsHtml;

                // Append Load More Button
                if (this.state.hasMoreStrings) {
                    const btnMore = document.createElement('div');
                    btnMore.className = "text-center pt-4";
                    btnMore.innerHTML = `
                        <button onclick="app.loadMoreStrings()" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-sm transition-colors">
                            Carregar mais...
                        </button>
                     `;
                    listEl.appendChild(btnMore);
                }

                document.getElementById('strings-count').innerText = `${this.state.loadedStrings.length}${this.state.hasMoreStrings ? '+' : ''} strings exibidas`;

            } else {
                listEl.innerHTML = `<div class="text-center py-20 text-slate-600">Nenhuma string encontrada.</div>`;
                document.getElementById('strings-count').innerText = `0 strings`;
            }

        } catch (e) {
            console.error("Erro ao buscar strings:", e);
            listEl.innerHTML = `<div class="text-center py-10 text-red-500">Erro ao carregar dados.</div>`;
        }
        lucide.createIcons();
    },

    loadMoreStrings: function () {
        if (!this.state.isLoadingStrings && this.state.hasMoreStrings) {
            this.renderStringsView(true); // append = true
        }
    },

    filterStrings: function (type) {
        if (this.state.stringFilter === type) {
            this.state.stringFilter = null;
        } else {
            this.state.stringFilter = type;
        }
        // Reset and reload
        this.renderStringsView(false);
    },

    renderDnsView: async function (append = false) {
        if (!this.state.report) return;

        const listEl = document.getElementById('dns-list');

        // Se não é append (primeira carga), limpa lista
        if (!append) {
            listEl.innerHTML = '<div class="text-center py-10 text-slate-500">Carregando registros DNS...</div>';
            this.state.loadedDns = [];
            this.state.dnsOffset = 0;
            this.state.hasMoreDns = true;
        }

        // Fetch Data batch
        const LIMIT = 50;
        try {
            this.state.isLoadingDns = true;
            const newRecords = await window.pywebview.api.get_dns_records(
                LIMIT,
                this.state.dnsOffset
            );

            this.state.isLoadingDns = false;

            if (newRecords.length < LIMIT) {
                this.state.hasMoreDns = false;
            }

            this.state.loadedDns = append ? [...this.state.loadedDns, ...newRecords] : newRecords;
            this.state.dnsOffset += newRecords.length;

            // Build List HTML
            const itemsHtml = this.state.loadedDns.map(item => `
                <div class="bg-slate-950 border border-slate-800 rounded-xl p-3 hover:border-slate-700 transition-colors flex items-center justify-between">
                    <div class="flex flex-col gap-1 overflow-hidden">
                        <div class="flex items-center gap-2">
                             <div class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-pink-500/20 text-pink-400 min-w-[35px] text-center">
                                ${item.queryType}
                             </div>
                             <span class="text-sm font-bold text-slate-200 truncate font-mono" title="${item.queryName}">${item.queryName}</span>
                        </div>
                        <div class="text-[10px] text-slate-500 font-mono ml-1">
                            Transação: ${item.transactionId || 'N/A'}
                        </div>
                    </div>
                    
                    <div class="flex flex-col items-end min-w-[60px]">
                        <span class="text-xs font-bold text-white">${item.count}</span>
                        <span class="text-[10px] text-slate-600">queries</span>
                    </div>
                </div>
            `).join('');

            // Container Update
            if (this.state.loadedDns.length > 0) {
                listEl.innerHTML = itemsHtml;

                // Append Load More Button
                if (this.state.hasMoreDns) {
                    const btnMore = document.createElement('div');
                    btnMore.className = "text-center pt-4";
                    btnMore.innerHTML = `
                        <button onclick="app.loadMoreDns()" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-sm transition-colors">
                            Carregar mais...
                        </button>
                     `;
                    listEl.appendChild(btnMore);
                }

                document.getElementById('dns-count').innerText = `${this.state.loadedDns.length}${this.state.hasMoreDns ? '+' : ''} registros exibidos`;

            } else {
                listEl.innerHTML = `<div class="text-center py-20 text-slate-600">Nenhum tráfego DNS encontrado na porta 53.</div>`;
                document.getElementById('dns-count').innerText = `0 registros`;
            }

        } catch (e) {
            console.error("Erro ao buscar DNS:", e);
            listEl.innerHTML = `<div class="text-center py-10 text-red-500">Erro ao carregar dados.</div>`;
        }
        lucide.createIcons();
    },

    loadMoreDns: function () {
        if (!this.state.isLoadingDns && this.state.hasMoreDns) {
            this.renderDnsView(true); // append = true
        }
    },

    renderThreatsCatalog: function () {
        const list = document.getElementById('threats-catalog-list');
        const countEl = document.getElementById('threats-total-count');
        const catalog = this.state.catalog;

        if (countEl) {
            countEl.innerText = `${catalog.length} ameaças neste catálogo`;
        }

        if (catalog.length === 0) {
            list.innerHTML = `<div class="col-span-full text-center py-20 text-slate-600">Carregando catálogo de ameaças...</div>`;
            return;
        }

        list.innerHTML = catalog.map(item => `
            <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition-colors">
                <div class="mb-3">
                    <div class="flex items-center gap-2 mb-1">
                        <span class="text-sm font-bold text-red-400">${item.title}</span>
                    </div>
                    <div class="text-sm text-slate-400 mb-2">${item.comment}</div>
                    <div class="text-xs text-slate-500 leading-relaxed">
                        ${item.explanation}
                    </div>
                </div>
            </div>
        `).join('');
        lucide.createIcons();
    },

    showError: function (msg) {
        document.getElementById('error-msg').innerText = msg;
        document.getElementById('error-alert').classList.remove('hidden');
    },

    hideError: function () {
        document.getElementById('error-alert').classList.add('hidden');
    },

    formatBytes: function (bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
};

window.app = app;
app.init();

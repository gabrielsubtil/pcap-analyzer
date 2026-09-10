(() => {
  const unavailable = (title, detail) => `<div class="web-unavailable" role="status"><span aria-hidden="true">⚠</span><div><strong>${title}</strong>${detail}</div></div>`;
  const originalSetView = window.app.setView.bind(window.app);
  const buttons = ['dashboard','strings','all-strings','dns','whois','threats'];
  const syncSidebar = mode => buttons.forEach(name => document.querySelector(`#web-sidebar [data-view="${name}"]`)?.classList.toggle('is-active', mode === name));
  window.app.setView = mode => { originalSetView(mode); syncSidebar(mode); };
  const originalReset = window.app.reset.bind(window.app);
  window.app.reset = () => { originalReset(); syncSidebar('upload'); document.querySelector('#web-analysis-status').textContent = 'Nenhuma análise carregada'; buttons.forEach(name => { const b=document.querySelector(`#web-sidebar [data-view="${name}"]`); if(b) b.disabled=true; }); };
  window.app.renderWhoisView = () => {
    const view = document.querySelector('#view-whois');
    if (!view) return;
    view.innerHTML = `<div class="bg-slate-900 border border-slate-800 rounded-2xl p-6"><h3 class="text-lg font-bold text-white mb-4">Whois de endereços</h3>${unavailable('Whois indisponível nesta implantação Web.', 'O backend Web ainda não expõe o endpoint de enriquecimento Whois usado pelo Desktop. Nenhum dado foi inventado.')}</div>`;
  };
  const enable = () => { buttons.forEach(name => { const b=document.querySelector(`#web-sidebar [data-view="${name}"]`); if(b) b.disabled=false; }); document.querySelector('#web-analysis-status').textContent='Análise carregada'; };
  const oldAnalyze = window.app.analyze.bind(window.app);
  window.app.analyze = async () => { await oldAnalyze(); if(window.app.state.report) enable(); };
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('#web-sidebar [data-view]').forEach(button => button.addEventListener('click', () => window.app.setView(button.dataset.view)));
    syncSidebar(window.app.state.report ? window.app.state.viewMode : 'upload');
  }, {once:true});
})();

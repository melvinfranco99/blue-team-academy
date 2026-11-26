/* Blue Team Academy — utilidades comunes (header, footer, tabs, quiz, reveal) */
(function () {
  const LOGO = `<svg class="logo" viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#22d3ee"/><stop offset="1" stop-color="#3b82f6"/></linearGradient></defs><path d="M32 4 8 13v17c0 15 10 26 24 30 14-4 24-15 24-30V13z" fill="none" stroke="url(#lg)" stroke-width="4"/><path d="M22 32l7 7 14-15" fill="none" stroke="#22d3ee" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  const links = [
    ['index.html', 'Inicio'],
    ['fundamentos.html', 'Fundamentos'],
    ['perfiles.html', 'Perfiles'],
    ['videos.html', 'Videos'],
    ['laboratorios.html', 'Laboratorios'],
    ['soc.html', 'SOC simulado'],
    ['ia.html', 'IA en el SOC'],
    ['ruta.html', 'Ruta y Quiz'],
  ];
  const here = (location.pathname.split('/').pop() || 'index.html');

  const header = document.getElementById('site-header');
  if (header) {
    header.className = 'site-header';
    header.innerHTML = `<nav class="nav"><a class="brand" href="index.html">${LOGO}<span>Blue Team Academy<small>Ciberseguridad defensiva</small></span></a>
      <button class="menu-btn" aria-label="Abrir menú">☰</button>
      <ul class="nav-links">${links.map(([h, t]) => `<li><a href="${h}" class="${h === here ? 'active' : ''} ${h === 'videos.html' && h !== here ? 'cta' : ''}">${h === 'videos.html' ? '▶ ' : ''}${t}</a></li>`).join('')}</ul></nav>`;
    header.querySelector('.menu-btn').onclick = () => header.querySelector('.nav-links').classList.toggle('open');
    const bar = document.createElement('div'); bar.className = 'progress-top'; document.body.prepend(bar);
    addEventListener('scroll', () => {
      const h = document.documentElement; bar.style.width = (h.scrollTop / (h.scrollHeight - h.clientHeight) * 100 || 0) + '%';
    }, { passive: true });
  }

  const footer = document.getElementById('site-footer');
  if (footer) {
    footer.className = 'site-footer';
    footer.innerHTML = `<div class="container"><div class="foot-grid">
      <div><a class="brand" href="index.html">${LOGO}<span>Blue Team Academy</span></a><p style="margin-top:12px">Plataforma educativa gratuita para aprender ciberseguridad defensiva desde cero: perfiles profesionales, fundamentos, videos prácticos y uso de IA en el SOC.</p></div>
      <div><h4>Aprender</h4><ul><li><a href="fundamentos.html">Fundamentos</a></li><li><a href="perfiles.html">Perfiles</a></li><li><a href="ruta.html">Ruta de aprendizaje</a></li></ul></div>
      <div><h4>Practicar</h4><ul><li><a href="videos.html">Videos prácticos</a></li><li><a href="laboratorios.html">Laboratorios</a></li><li><a href="soc.html">SOC simulado</a></li><li><a href="ia.html">Tutor IA</a></li></ul></div>
      <div><h4>Uso ético</h4><ul><li>Practica solo en sistemas propios o con autorización por escrito.</li></ul></div>
      </div><div class="copy">© ${new Date().getFullYear()} Blue Team Academy · Contenido educativo. Las marcas (Splunk, Nessus, Snort, Suricata, Zabbix, Shodan, Maltego, Nmap…) pertenecen a sus propietarios; los videos son simulaciones didácticas de sus interfaces.</div></div>`;
  }

  // Reveal on scroll
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }), { threshold: .12 });
  document.querySelectorAll('.reveal').forEach(el => io.observe(el));

  // Tabs
  document.querySelectorAll('[data-tabs]').forEach(root => {
    const btns = root.querySelectorAll('.tabs button');
    btns.forEach(b => b.onclick = () => {
      btns.forEach(x => x.classList.toggle('active', x === b));
      root.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === b.dataset.tab));
    });
  });

  // Quiz genérico: <div class="quiz-q" data-answer="1"><button>..</button>..<div class="exp"></div></div>
  document.querySelectorAll('.quiz-q').forEach(q => {
    const ans = +q.dataset.answer;
    q.querySelectorAll('.opts button').forEach((b, i) => b.onclick = () => {
      if (q.classList.contains('answered')) return;
      q.classList.add('answered');
      b.classList.add(i === ans ? 'right' : 'wrong');
      q.querySelectorAll('.opts button')[ans].classList.add('right');
      document.dispatchEvent(new CustomEvent('quiz-answer', { detail: { ok: i === ans } }));
    });
  });

  // TOC activo
  const toc = document.querySelector('.toc');
  if (toc) {
    const as = [...toc.querySelectorAll('a')];
    const secs = as.map(a => document.querySelector(a.getAttribute('href'))).filter(Boolean);
    addEventListener('scroll', () => {
      let cur = secs[0];
      secs.forEach(s => { if (s.getBoundingClientRect().top < 140) cur = s; });
      as.forEach(a => a.classList.toggle('active', cur && a.getAttribute('href') === '#' + cur.id));
    }, { passive: true });
  }

  // Botón copiar en bloques <pre>
  document.querySelectorAll('pre').forEach(pre => {
    const b = document.createElement('button');
    b.textContent = 'Copiar'; b.className = 'btn small';
    b.style.cssText = 'position:absolute;top:8px;right:8px;padding:3px 9px;font-size:.72rem;opacity:.75';
    b.onclick = () => { navigator.clipboard.writeText(pre.innerText.replace(/Copiar$/, '').trim()); b.textContent = '✓ Copiado'; setTimeout(() => b.textContent = 'Copiar', 1500); };
    pre.appendChild(b);
  });
})();

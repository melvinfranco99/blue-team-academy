/* =====================================================================
   CyberCast — motor de "videos" animados con narración (Web Speech API),
   subtítulos, capítulos, transcripción y escenas que simulan herramientas
   reales (terminal, Splunk, Suricata, Nessus, Zabbix, Shodan, Maltego…).
   Cada video es una lista de escenas declarativas (assets/js/videos/*.js).
   ===================================================================== */
window.VIDEOS = window.VIDEOS || [];
(function () {
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const md = s => esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`(.+?)`/g, '<code>$1</code>');
  const div = (cls, html) => { const d = document.createElement('div'); d.className = cls; d.innerHTML = html; return d; };
  const head = s => s.title ? `<div class="s-h">${s.icon ? `<span class="ic">${s.icon}</span>` : ''}<span>${md(s.title)}</span></div>` : '';
  const win = (title, body) => `<div class="win"><div class="win-bar"><i></i><i></i><i></i><span>${esc(title)}</span></div>${body}</div>`;
  const fmt = t => { t = Math.max(0, Math.floor(t)); return Math.floor(t / 60) + ':' + String(t % 60).padStart(2, '0'); };
  const sentences = s => (s || '').split(/(?<=[.!?…:])\s+(?=[¿¡A-ZÁÉÍÓÚÑ0-9"(])/).filter(Boolean);
  const durOf = s => s.d || Math.max(7, Math.min(70, (s.say || '').length / 14.2 + 1.8));

  /* ---------------- Resaltado de sintaxis sencillo ---------------- */
  const KW = /\b(alert|drop|pass|reject|log|tcp|udp|icmp|http|dns|tls|any|msg|sid|rev|content|flow|established|to_server|to_client|nocase|classtype|threshold|detection_filter|track|by_src|by_dst|count|seconds|pcre|depth|offset|http\.uri|http\.method|http\.user_agent|dns\.query|title|status|logsource|product|service|category|detection|selection|filter|condition|level|tags|falsepositives|rule|meta|strings|and|or|not|of|them|index|sourcetype|stats|where|eval|table|sort|timechart|search|by|as|def|import|for|in|if|return|print|from|with|true|false|vars|address-groups|HOME_NET|EXTERNAL_NET|sudo|systemctl|apt|install|enable|start|cat|tail|grep|jq)\b/g;
  function hilite(line) {
    let h = esc(line);
    const ci = h.search(/(^|\s)(#|\/\/)/);
    let com = '';
    if (ci >= 0 && !/^\s*#!/.test(line)) { com = h.slice(ci); h = h.slice(0, ci); }
    h = h.replace(/(&quot;[^&]*?&quot;|"[^"]*")/g, '\u0001s$1\u0002')
      .replace(KW, m => `\u0001k${m}\u0002`)
      .replace(/\b(\d+(\.\d+)?)\b/g, '\u0001n$1\u0002');
    // evitar anidamiento: tokens dentro de strings
    h = h.replace(/\u0001s(.*?)\u0002/g, (m, x) => '<span class="s">' + x.replace(/\u0001[kn]|\u0002/g, '') + '</span>')
      .replace(/\u0001k(.*?)\u0002/g, '<span class="k">$1</span>')
      .replace(/\u0001n(.*?)\u0002/g, '<span class="n">$1</span>');
    return h + (com ? `<span class="cm">${com}</span>` : '');
  }
  function hiliteSPL(q) {
    return esc(q).replace(/\|/g, '<span class="pipe">|</span>')
      .replace(/\b(stats|where|eval|table|sort|timechart|search|rex|top|rare|iplocation|lookup|bin|dedup|rename|transaction|fields|head|tstats|chart|eventstats|streamstats)\b/g, '<span class="kw">$1</span>')
      .replace(/\b(count|dc|values|sum|avg|max|min|earliest|latest|if|len|round|strftime)\(/g, '<span class="fn">$1</span>(');
  }

  /* ---------------- Renderizadores de escena ---------------- */
  const R = {};
  R.title = s => ({ el: div('cp-scene s-title', `<div class="ic">${s.icon || '🛡️'}</div><div class="kick">${esc(s.kick || '')}</div><h1>${md(s.title)}</h1><p>${md(s.sub || '')}</p>`), up() { } });

  R.bul = s => {
    const el = div('cp-scene s-bul', head(s) + `<ul>${s.items.map(i => `<li><span>${md(i)}</span></li>`).join('')}</ul>`);
    const lis = [...el.querySelectorAll('li')];
    return { el, up(p) { lis.forEach((li, i) => li.classList.toggle('v', p >= (i / lis.length) * 0.8)); } };
  };

  R.ana = s => {
    const el = div('cp-scene s-ana', `<div class="big">${s.icon || '💡'}</div><div class="lab">${esc(s.lab || 'ANALOGÍA')}</div><h2>${md(s.title || '')}</h2><p>${md(s.text || '')}</p>` +
      (s.vs ? `<div class="vs"><div>${md(s.vs[0])}</div><span>⟷</span><div>${md(s.vs[1])}</div></div>` : ''));
    const vs = el.querySelector('.vs');
    return { el, up(p) { if (vs) vs.style.opacity = p > .35 ? 1 : 0; } };
  };

  R.cmp = s => {
    const col = c => `<div style="border-top:4px solid ${c.c || '#22d3ee'}"><h3>${md(c.t)}</h3><ul>${c.items.map(i => `<li>${md(i)}</li>`).join('')}</ul></div>`;
    const el = div('cp-scene', head(s) + `<div class="cmp">${col(s.l)}${col(s.r)}</div>`);
    const cs = el.querySelectorAll('.cmp>div');
    return { el, up(p) { cs[0].classList.toggle('v', p > .02); cs[1].classList.toggle('v', p > .4); } };
  };

  R.term = s => {
    const prompt = s.prompt || 'analista@soc:~$';
    const lines = s.lines.replace(/^\n/, '').split('\n').map(l => {
      if (l.startsWith('$ ')) return { k: 'cmd', t: l.slice(2) };
      if (l.startsWith('# ')) return { k: 'cm', t: l };
      const m = { '!': 'bad', '+': 'good', '~': 'acc', '^': 'hl' }[l[0]];
      return m ? { k: m, t: l.slice(1) } : { k: 'out', t: l };
    });
    const w = l => l.k === 'cmd' ? l.t.length + 6 : l.k === 'cm' ? l.t.length * .5 : 2.2;
    const W = lines.reduce((a, l) => a + w(l), 0);
    const el = div('cp-scene', head(s) + win(s.win || 'Terminal — ' + prompt.replace(/\$$/, ''), '<div class="term"></div>'));
    const term = el.querySelector('.term'); let last = -1;
    return {
      el, up(p) {
        let budget = Math.min(1, p / (s.speed || .82)) * W;
        const key = Math.floor(budget); if (key === last) return; last = key;
        let html = '';
        for (const l of lines) {
          const need = w(l);
          if (budget <= 0) break;
          if (l.k === 'cmd') {
            const n = Math.max(0, Math.min(l.t.length, Math.floor(budget)));
            const done = budget >= need;
            html += `<div><span class="p">${esc(prompt)}</span> <span class="c">${esc(l.t.slice(0, n))}</span>${done ? '' : '<span class="cursor"></span>'}</div>`;
            if (!done) { budget = 0; break; }
          } else if (l.k === 'cm') {
            const n = Math.min(l.t.length, Math.floor(budget / .5));
            html += `<div class="cm">${esc(l.t.slice(0, n))}</div>`;
            if (budget < need) { budget = 0; break; }
          } else html += `<div class="${l.k === 'out' ? '' : l.k}">${esc(l.t) || '&nbsp;'}</div>`;
          budget -= need;
        }
        if (budget > 0) html += `<div><span class="p">${esc(prompt)}</span> <span class="cursor"></span></div>`;
        term.innerHTML = html;
      }
    };
  };

  R.code = s => {
    const ls = s.code.replace(/^\n/, '').split('\n');
    const el = div('cp-scene', head(s) + win(s.file || 'editor', `<div class="code">${ls.map((l, i) => `<div><em>${i + 1}</em><span>${hilite(l) || ' '}</span></div>`).join('')}</div>`));
    const ds = [...el.querySelectorAll('.code div')];
    const hl = new Set(s.hl || []);
    return { el, up(p) { ds.forEach((d, i) => { d.classList.toggle('v', p >= (i / ds.length) * .55); d.classList.toggle('h', hl.has(i + 1) && p > .6); }); } };
  };

  R.flow = s => {
    const W = 1140, H = s.h || 520;
    const nodes = s.nodes.map((n, i) => ({ w: 200, h: 86, s: i, ...n }));
    const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
    const edges = (s.edges || []).map(e => { const a = byId[e[0]], b = byId[e[1]]; return { a, b, label: e[2], c: e[3] || '#22d3ee', s: e[4] ?? Math.max(a.s, b.s) }; });
    const total = Math.max(...nodes.map(n => n.s), ...edges.map(e => e.s)) + 1;
    const clip = (n, dx, dy) => {
      if (n.shape === 'circle') { const r = 50, L = Math.hypot(dx, dy) || 1; return [n.x + dx / L * r, n.y + dy / L * r]; }
      const hw = n.w / 2 + 4, hh = n.h / 2 + 4; const t = Math.min(hw / Math.abs(dx || 1e-6), hh / Math.abs(dy || 1e-6)); return [n.x + dx * t, n.y + dy * t];
    };
    let svg = `<svg class="flow-svg" viewBox="0 0 ${W} ${H}"><defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="context-stroke"/></marker></defs>`;
    (s.zones || []).forEach(z => { svg += `<g><rect x="${z.x}" y="${z.y}" width="${z.w}" height="${z.h}" rx="16" fill="${z.c}" fill-opacity=".06" stroke="${z.c}" stroke-opacity=".5" stroke-dasharray="7 6"/><text x="${z.x + 14}" y="${z.y + 26}" fill="${z.c}" font-size="17" font-family="JetBrains Mono,monospace" font-weight="700">${esc(z.label)}</text></g>`; });
    edges.forEach((e, i) => {
      const [x1, y1] = clip(e.a, e.b.x - e.a.x, e.b.y - e.a.y), [x2, y2] = clip(e.b, e.a.x - e.b.x, e.a.y - e.b.y);
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      svg += `<g class="ed" data-s="${e.s}"><path d="M${x1} ${y1}L${x2} ${y2}" stroke="${e.c}" stroke-width="3" fill="none" marker-end="url(#ar)"/>` +
        (e.label ? `<rect x="${mx - e.label.length * 4.6 - 8}" y="${my - 15}" width="${e.label.length * 9.2 + 16}" height="26" rx="6" fill="#060b16" stroke="${e.c}" stroke-opacity=".4"/><text x="${mx}" y="${my + 4}" text-anchor="middle" fill="#e6edf7" font-size="15" font-family="JetBrains Mono,monospace">${esc(e.label)}</text>` : '') + '</g>';
    });
    nodes.forEach(n => {
      const c = n.c || '#22d3ee';
      if (n.shape === 'circle') {
        svg += `<g class="nd" data-s="${n.s}"><circle cx="${n.x}" cy="${n.y}" r="46" fill="#0c1424" stroke="${c}" stroke-width="3"/><text x="${n.x}" y="${n.y + 14}" text-anchor="middle" font-size="38">${n.icon || '●'}</text><text x="${n.x}" y="${n.y + 76}" text-anchor="middle" fill="#e6edf7" font-size="17" font-weight="700" font-family="Inter,sans-serif">${esc(n.label)}</text>${n.sub ? `<text x="${n.x}" y="${n.y + 97}" text-anchor="middle" fill="#93a4c0" font-size="14" font-family="JetBrains Mono,monospace">${esc(n.sub)}</text>` : ''}</g>`;
      } else {
        const x = n.x - n.w / 2, y = n.y - n.h / 2;
        svg += `<g class="nd" data-s="${n.s}"><rect x="${x}" y="${y}" width="${n.w}" height="${n.h}" rx="14" fill="#0c1424" stroke="${c}" stroke-width="2.5"/><rect x="${x}" y="${y}" width="6" height="${n.h}" rx="3" fill="${c}"/>` +
          `<text x="${x + 20}" y="${n.y + 12}" font-size="32">${n.icon || ''}</text><text x="${x + (n.icon ? 64 : 22)}" y="${n.y + (n.sub ? -3 : 7)}" fill="#e6edf7" font-size="${n.fs || 19}" font-weight="700" font-family="Inter,sans-serif">${esc(n.label)}</text>` +
          (n.sub ? `<text x="${x + (n.icon ? 64 : 22)}" y="${n.y + 21}" fill="#93a4c0" font-size="14" font-family="JetBrains Mono,monospace">${esc(n.sub)}</text>` : '') + '</g>';
      }
    });
    svg += '</svg>';
    const el = div('cp-scene', head(s) + svg);
    const parts = [...el.querySelectorAll('[data-s]')];
    return { el, up(p) { parts.forEach(g => g.classList.toggle('v', p >= (+g.dataset.s / total) * .85)); } };
  };

  R.table = s => {
    const el = div('cp-scene', head(s) + `<div class="win" style="flex:none"><table class="tbl ${s.mono ? 'mono' : ''}"><thead><tr>${s.head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${s.rows.map((r, i) => `<tr class="${(s.hl || []).includes(i) ? 'hx' : ''}">${r.map(c => `<td>${md(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
    const trs = [...el.querySelectorAll('tbody tr')];
    return { el, up(p) { trs.forEach((t, i) => { t.classList.toggle('v', p >= (i / trs.length) * .7); t.classList.toggle('h', t.classList.contains('hx') && p > .75); }); } };
  };

  R.splunk = s => {
    const bars = s.bars ? `<div class="bars">${s.bars.map(b => `<div class="b ${b[2] ? 'r' : ''}" data-h="${b[1]}"><em>${b[1]}</em><span>${esc(b[0])}</span></div>`).join('')}</div>` : '';
    const tbl = s.head ? `<div style="flex:1.3;overflow:hidden"><table class="tbl"><thead><tr>${s.head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${s.rows.map((r, i) => `<tr class="${(s.hl || []).includes(i) ? 'hx' : ''}">${r.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : '';
    const el = div('cp-scene', head(s) + `<div class="spl"><div class="spl-top"><b>splunk<span>&gt;</span></b><span>Search &amp; Reporting</span><span>Dashboards</span><span>Alerts</span><span style="margin-left:auto">${esc(s.range || 'Últimas 24 horas')}</span></div>
      <div class="spl-q"><div></div><button>🔍</button></div><div class="spl-meta"><span>${esc(s.count || '')}</span><span class="${s.tab === 'Events' ? 'a' : ''}">Events</span><span class="${s.tab !== 'Events' && s.tab !== 'Visualization' ? 'a' : ''}">Statistics</span><span class="${s.tab === 'Visualization' ? 'a' : ''}">Visualization</span></div>
      <div class="spl-res">${tbl}${bars}</div></div>`);
    const q = el.querySelector('.spl-q div'), trs = [...el.querySelectorAll('tbody tr')], bs = [...el.querySelectorAll('.bars .b')], meta = el.querySelector('.spl-meta');
    const mx = Math.max(1, ...(s.bars || []).map(b => b[1]));
    let lastN = -1;
    return {
      el, up(p) {
        const n = Math.floor(Math.min(1, p / .4) * s.q.length);
        if (n !== lastN) { lastN = n; q.innerHTML = hiliteSPL(s.q.slice(0, n)) + (n < s.q.length ? '<span class="cursor"></span>' : ''); }
        meta.style.opacity = p > .42 ? 1 : 0;
        trs.forEach((t, i) => { t.classList.toggle('v', p >= .45 + (i / trs.length) * .35); t.classList.toggle('h', t.classList.contains('hx') && p > .85); });
        bs.forEach((b, i) => b.style.height = p >= .45 + i * .03 ? (b.dataset.h / mx * 88) + '%' : 0);
      }
    };
  };

  R.alerts = s => {
    const el = div('cp-scene', head(s) + win(s.win || 'alerts', `<div class="alerts">${s.items.map(a => `<div class="al ${a.sv}"><span class="sv">${a.sv.toUpperCase()}</span><span class="ts">${esc(a.ts)}</span><span>${md(a.msg)}</span><span class="ip">${esc(a.ip)}</span></div>`).join('')}</div>`));
    const as = [...el.querySelectorAll('.al')];
    return { el, up(p) { as.forEach((a, i) => a.classList.toggle('v', p >= (i / as.length) * .75)); } };
  };

  function widget(w) {
    const cls = `wd ${w.w ? 'w' + w.w : ''} ${w.h ? 'h' + w.h : ''}`;
    let body = '';
    if (w.k === 'stat') body = `<div class="big" style="color:${w.c || '#fff'}">${esc(w.v)}<small>${esc(w.u || '')}</small></div>${w.n ? `<div style="font-size:15px;color:#93a4c0;margin-top:8px">${esc(w.n)}</div>` : ''}`;
    if (w.k === 'hbars') { const mx = Math.max(...w.data.map(d => d[1])); body = w.data.map(d => `<div class="hb"><span>${esc(d[0])}</span><i data-w="${d[1] / mx * 100}" style="width:0;background:${d[2] || '#22d3ee'}"></i><b style="font-size:14px">${d[1]}</b></div>`).join(''); }
    if (w.k === 'list') body = `<ul>${w.items.map(i => `<li><span class="sev ${i[0]}" style="font-size:12px">${i[0].toUpperCase()}</span><span>${md(i[1])}</span></li>`).join('')}</ul>`;
    if (w.k === 'line') {
      const mx = Math.max(...w.data, w.thr || 0) * 1.1, n = w.data.length;
      const pts = w.data.map((v, i) => `${(i / (n - 1) * 400).toFixed(1)},${(130 - v / mx * 120).toFixed(1)}`).join(' ');
      body = `<svg viewBox="0 0 400 135" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="${w.c || '#22d3ee'}" stroke-width="2.5" pathLength="100" stroke-dasharray="100" stroke-dashoffset="100" class="ln"/>${w.thr ? `<line x1="0" x2="400" y1="${130 - w.thr / mx * 120}" y2="${130 - w.thr / mx * 120}" stroke="#ef4444" stroke-dasharray="6 5"/><text x="396" y="${124 - w.thr / mx * 120}" fill="#ef4444" font-size="11" text-anchor="end">umbral ${w.thr}</text>` : ''}</svg>`;
    }
    if (w.k === 'donut') {
      const tot = w.data.reduce((a, d) => a + d[1], 0); let off = 0;
      body = `<div style="display:flex;align-items:center;gap:16px;flex:1"><svg viewBox="0 0 42 42" style="width:150px;flex:none">${w.data.map(d => { const pc = d[1] / tot * 100; const c = `<circle cx="21" cy="21" r="15.9" fill="none" stroke="${d[2]}" stroke-width="6" stroke-dasharray="${pc} ${100 - pc}" stroke-dashoffset="${25 - off}"/>`; off += pc; return c; }).join('')}<text x="21" y="23.5" text-anchor="middle" fill="#fff" font-size="7" font-weight="800">${tot}</text></svg><ul style="flex:1">${w.data.map(d => `<li style="border:0;padding:2px 0"><i style="width:12px;height:12px;border-radius:3px;background:${d[2]};display:inline-block"></i>${esc(d[0])} <b style="margin-left:auto">${d[1]}</b></li>`).join('')}</ul></div>`;
    }
    return `<div class="${cls}"><h5>${esc(w.t)}</h5>${body}</div>`;
  }
  R.dash = s => {
    const el = div('cp-scene', head(s) + win(s.app || 'dashboard', `<div class="dash" style="${s.cols ? `grid-template-columns:repeat(${s.cols},1fr)` : ''}">${s.widgets.map(widget).join('')}</div>`));
    const ws = [...el.querySelectorAll('.wd')];
    return {
      el, up(p) {
        ws.forEach((w, i) => {
          const on = p >= (i / ws.length) * .6; w.classList.toggle('v', on);
          w.querySelectorAll('[data-w]').forEach(b => b.style.width = on ? b.dataset.w + '%' : 0);
          const ln = w.querySelector('.ln'); if (ln) ln.style.strokeDashoffset = on ? Math.max(0, 100 - (p - i / ws.length * .6) * 260) : 100;
        });
      }
    };
  };

  R.shodan = s => {
    const el = div('cp-scene', head(s) + `<div class="brw"><div class="brw-url">🔒<div>https://www.shodan.io/search?query=${esc(encodeURIComponent(s.q))}</div></div>
      <div class="sh-head"><b>SHODAN</b><div class="q"></div></div>
      <div class="sh-body"><div class="sh-side"><span>TOTAL RESULTS</span><b>${esc(s.total)}</b>${(s.side || []).map(g => `<h6>${esc(g[0])}</h6>${g[1].map(x => `<div style="display:flex;justify-content:space-between"><span>${esc(x[0])}</span><span>${esc(x[1])}</span></div>`).join('')}`).join('')}</div>
      <div class="sh-res">${s.results.map(r => `<div class="sh-r"><div><div class="ip">${esc(r.ip)}</div><div class="meta">${esc(r.org)}<br>${esc(r.loc)}<br>Puerto <b style="color:#fff">${esc(r.port)}</b></div>${r.vulns ? `<div class="vl">⚠ ${esc(r.vulns)}</div>` : ''}</div><pre>${esc(r.banner)}</pre></div>`).join('')}</div></div></div>`);
    const q = el.querySelector('.q'), rs = [...el.querySelectorAll('.sh-r')], side = el.querySelector('.sh-side');
    return { el, up(p) { const n = Math.floor(Math.min(1, p / .3) * s.q.length); q.textContent = s.q.slice(0, n); side.style.opacity = p > .32 ? 1 : 0; rs.forEach((r, i) => r.classList.toggle('v', p >= .34 + i * .12)); } };
  };

  R.quiz = s => {
    const el = div('cp-scene quizs', `<div class="s-h"><span class="ic">🧠</span>Pregunta de repaso</div><div class="q">${md(s.q)}</div>${s.o.map((o, i) => `<div class="o">${String.fromCharCode(65 + i)}) ${md(o)}</div>`).join('')}`);
    const os = [...el.querySelectorAll('.o')];
    return { el, up(p) { os.forEach((o, i) => { o.classList.toggle('ok', p > .62 && i === s.a); o.classList.toggle('no', p > .62 && i !== s.a); }); } };
  };

  R.chat = s => {
    const el = div('cp-scene', head(s) + win(s.app || 'Asistente IA', '<div class="chatv"></div>'));
    const box = el.querySelector('.chatv');
    const W = s.msgs.reduce((a, m) => a + (m[0] === 'u' ? 30 : m[1].length), 0);
    let last = -1;
    return {
      el, up(p) {
        let b = Math.min(1, p / .85) * W; const k = Math.floor(b / 3); if (k === last) return; last = k;
        let h = '';
        for (const [who, t] of s.msgs) {
          if (b <= 0) break;
          if (who === 'u') { h += `<div class="m u"><div class="who">TÚ</div>${md(t)}</div>`; b -= 30; }
          else { const n = Math.min(t.length, Math.floor(b)); h += `<div class="m a"><div class="who">${esc(s.bot || 'IA')}</div>${md(t.slice(0, n))}${n < t.length ? '<span class="cursor"></span>' : ''}</div>`; b -= t.length; }
        }
        box.innerHTML = h;
      }
    };
  };

  /* ---------------- Voz ---------------- */
  const synth = window.speechSynthesis;
  let esVoice = null;
  function pickVoice() {
    if (!synth) return;
    const vs = synth.getVoices();
    esVoice = vs.find(v => /es[-_]ES/i.test(v.lang) && /google|microsoft|natural|online/i.test(v.name)) || vs.find(v => /es[-_]ES/i.test(v.lang)) || vs.find(v => /^es/i.test(v.lang)) || null;
  }
  if (synth) { pickVoice(); synth.onvoiceschanged = pickVoice; }

  /* ---------------- Reproductor ---------------- */
  class Player {
    constructor(root, side) {
      this.root = root; this.side = side; this.rate = 1; this.voice = !!synth; this.playing = false; this.spk = 0; this.speaking = false;
      root.classList.add('cp');
      root.innerHTML = `<div class="cp-stage-wrap"><div class="cp-stage"><div class="cp-bg"></div><div class="cp-chap"></div><div class="cp-wm"></div><div class="cp-host"></div><div class="cp-sub"></div></div><div class="cp-big"><div>▶</div></div></div>
      <div class="cp-ctrl"><button data-a="prev" title="Escena anterior (←)">⏮</button><button data-a="play" title="Reproducir/Pausa (espacio)">▶</button><button data-a="next" title="Escena siguiente (→)">⏭</button>
      <span class="cp-time">0:00 / 0:00</span><div class="cp-bar"><div class="trk"><div class="fill"></div></div><div class="tip"></div></div>
      <select data-a="rate" title="Velocidad"><option value=".75">0.75×</option><option value="1" selected>1×</option><option value="1.25">1.25×</option><option value="1.5">1.5×</option><option value="2">2×</option></select>
      <button data-a="voice" class="on" title="Narración por voz (M)">🔊</button><button data-a="cc" class="on" title="Subtítulos (C)">CC</button><button data-a="fs" title="Pantalla completa (F)">⛶</button></div>`;
      this.stage = root.querySelector('.cp-stage'); this.host = root.querySelector('.cp-host'); this.sub = root.querySelector('.cp-sub');
      this.fill = root.querySelector('.fill'); this.time = root.querySelector('.cp-time'); this.big = root.querySelector('.cp-big'); this.bar = root.querySelector('.cp-bar');
      const wrap = root.querySelector('.cp-stage-wrap');
      new ResizeObserver(() => { const w = wrap.clientWidth, h = wrap.clientHeight; const sc = Math.min(w / 1280, h / 720); this.stage.style.transform = `translate(${(w - 1280 * sc) / 2}px,${(h - 720 * sc) / 2}px) scale(${sc})`; }).observe(wrap);
      wrap.onclick = () => this.toggle();
      const B = a => root.querySelector(`[data-a="${a}"]`);
      B('play').onclick = () => this.toggle(); B('prev').onclick = () => this.go(this.idx - 1); B('next').onclick = () => this.go(this.idx + 1);
      B('rate').onchange = e => { this.rate = +e.target.value; if (this.playing && this.voice) this.speak(this.sentIdx); };
      if (!synth) B('voice').classList.remove('on');
      B('voice').onclick = () => { if (!synth) return alertNoVoice(); this.voice = !this.voice; B('voice').classList.toggle('on', this.voice); B('voice').textContent = this.voice ? '🔊' : '🔇'; if (this.voice && this.playing) this.speak(this.sentIdx); else this.stopSpeech(); };
      B('cc').onclick = () => { root.classList.toggle('nosub'); B('cc').classList.toggle('on'); };
      B('fs').onclick = () => document.fullscreenElement ? document.exitFullscreen() : root.requestFullscreen?.();
      this.bar.onclick = e => { const r = this.bar.getBoundingClientRect(); this.seek((e.clientX - r.left) / r.width * this.total); };
      this.bar.onmousemove = e => { const r = this.bar.getBoundingClientRect(); const T = (e.clientX - r.left) / r.width * this.total; const i = this.idxAt(T); const tip = this.bar.querySelector('.tip'); tip.style.left = (e.clientX - r.left) + 'px'; tip.textContent = fmt(T) + ' · ' + (this.chapOf(i) || ''); };
      document.addEventListener('keydown', e => {
        if (/INPUT|TEXTAREA|SELECT/.test(e.target.tagName) || !this.v) return;
        if (e.code === 'Space') { e.preventDefault(); this.toggle(); }
        else if (e.key === 'ArrowRight') this.go(this.idx + 1); else if (e.key === 'ArrowLeft') this.go(this.idx - 1);
        else if (e.key === 'f') B('fs').click(); else if (e.key === 'c') B('cc').click(); else if (e.key === 'm') B('voice').click();
      });
      let prev = performance.now();
      const loop = now => { const dt = Math.min(.1, (now - prev) / 1000); prev = now; this.tick(dt); requestAnimationFrame(loop); };
      requestAnimationFrame(loop);
    }
    load(v) {
      this.stopSpeech(); this.v = v; this.sc = v.scenes; this.durs = this.sc.map(durOf);
      this.starts = []; let a = 0; this.durs.forEach(d => { this.starts.push(a); a += d; }); this.total = a;
      this.root.querySelector('.cp-wm').textContent = (v.tool || 'BLUE TEAM ACADEMY').toUpperCase();
      this.bar.querySelectorAll('.tick').forEach(t => t.remove());
      this.sc.forEach((s, i) => { if (s.ch && i) { const t = document.createElement('div'); t.className = 'tick'; t.style.left = (this.starts[i] / this.total * 100) + '%'; this.bar.appendChild(t); } });
      this.playing = false; this.big.classList.remove('hide'); this.btnPlay();
      this.renderSide(); this.enter(0, 0);
    }
    chapOf(i) { for (let k = i; k >= 0; k--) if (this.sc[k].ch) return this.sc[k].ch; return ''; }
    idxAt(T) { let i = 0; while (i < this.sc.length - 1 && this.starts[i + 1] <= T) i++; return i; }
    seek(T) { const i = this.idxAt(T); this.enter(i, T - this.starts[i]); }
    go(i) { if (i < 0 || i >= this.sc.length) return; this.enter(i, 0); }
    enter(i, t) {
      this.idx = i; this.t = t || 0; this.held = 0;
      const s = this.sc[i]; const r = (R[s.t] || R.bul)(s);
      r.el.classList.add('enter'); this.host.replaceChildren(r.el); this.cur = r;
      this.sents = sentences(s.say);
      const tot = this.sents.reduce((a, x) => a + x.length, 0) || 1; let acc = 0;
      this.sentAt = this.sents.map(x => { const st = acc / tot; acc += x.length; return st; });
      this.sentIdx = this.sentFor(this.t / this.durs[i]);
      this.root.querySelector('.cp-chap').textContent = this.chapOf(i);
      r.up(Math.min(1, this.t / this.durs[i]));
      this.setSub(this.sentIdx);
      if (this.playing && this.voice) this.speak(this.sentIdx); else this.stopSpeech();
      this.side?.querySelectorAll('.chi').forEach(c => c.classList.toggle('cur', +c.dataset.i === i || (c.dataset.ch && +c.dataset.i <= i && +c.dataset.next > i)));
      const curT = this.side?.querySelector('.tr .chi.cur'); if (curT && this.playing) curT.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      if (i === this.sc.length - 1) markWatched(this.v.id);
    }
    sentFor(f) { let k = 0; this.sentAt.forEach((st, j) => { if (f >= st) k = j; }); return k; }
    setSub(k) { this.sentIdx = k; this.sub.textContent = this.sents[k] || ''; }
    speak(from) {
      this.stopSpeech(); if (!synth) return;
      const id = ++this.spk; const list = this.sents.slice(from || 0);
      if (!list.length) return;
      this.speaking = true;
      list.forEach((txt, j) => {
        const u = new SpeechSynthesisUtterance(txt.replace(/`/g, '').replace(/\*\*/g, ''));
        u.lang = 'es-ES'; if (esVoice) u.voice = esVoice; u.rate = Math.min(2, 1.05 * this.rate);
        u.onstart = () => { if (id === this.spk) this.setSub((from || 0) + j); };
        u.onend = u.onerror = () => { if (id === this.spk && j === list.length - 1) this.speaking = false; };
        synth.speak(u);
      });
    }
    stopSpeech() { this.spk++; this.speaking = false; if (synth && (synth.speaking || synth.pending)) synth.cancel(); }
    toggle() { this.playing ? this.pause() : this.play(); }
    play() { if (!this.v) return; if (this.idx === this.sc.length - 1 && this.t >= this.durs[this.idx]) this.enter(0, 0); this.playing = true; this.big.classList.add('hide'); this.btnPlay(); if (this.voice) this.speak(this.sentIdx); }
    pause() { this.playing = false; this.btnPlay(); this.stopSpeech(); }
    btnPlay() { this.root.querySelector('[data-a="play"]').textContent = this.playing ? '⏸' : '▶'; }
    tick(dt) {
      if (!this.v) return;
      const d = this.durs[this.idx];
      if (this.playing) {
        this.t += dt * this.rate;
        if (this.t >= d) {
          if (this.voice && this.speaking && this.held < 30) { this.t = d; this.held += dt; }
          else if (this.idx < this.sc.length - 1) { this.enter(this.idx + 1, 0); return; }
          else { this.t = d; this.pause(); markWatched(this.v.id); }
        }
        if (!(this.voice && synth)) { const k = this.sentFor(this.t / d); if (k !== this.sentIdx) this.setSub(k); }
      }
      this.cur.up(Math.min(1, this.t / d));
      const T = this.starts[this.idx] + Math.min(this.t, d);
      this.fill.style.width = (T / this.total * 100) + '%';
      this.time.textContent = fmt(T) + ' / ' + fmt(this.total);
    }
    renderSide() {
      if (!this.side) return;
      const chs = []; this.sc.forEach((s, i) => s.ch && chs.push(i));
      const chHTML = chs.map((i, k) => `<div class="chi" data-ch="1" data-i="${i}" data-next="${chs[k + 1] ?? 1e9}"><time>${fmt(this.starts[i])}</time><p><b>${esc(this.sc[i].ch)}</b></p></div>`).join('');
      const trHTML = this.sc.map((s, i) => `<div class="chi" data-i="${i}"><time>${fmt(this.starts[i])}</time><p>${md(s.say)}</p></div>`).join('');
      this.side.innerHTML = `<div class="tabs"><button class="active" data-p="ch">Capítulos (${chs.length})</button><button data-p="tr">Transcripción</button></div><div class="list ch">${chHTML}</div><div class="list tr" style="display:none">${trHTML}</div>`;
      this.side.querySelectorAll('.tabs button').forEach(b => b.onclick = () => { this.side.querySelectorAll('.tabs button').forEach(x => x.classList.toggle('active', x === b)); this.side.querySelector('.ch').style.display = b.dataset.p === 'ch' ? '' : 'none'; this.side.querySelector('.tr').style.display = b.dataset.p === 'tr' ? '' : 'none'; });
      this.side.querySelectorAll('.chi').forEach(c => c.onclick = () => { this.enter(+c.dataset.i, 0); if (!this.playing) this.play(); });
    }
  }
  function alertNoVoice() { const m = document.createElement('div'); m.className = 'callout warn'; m.textContent = 'Tu navegador no ofrece síntesis de voz. Los subtítulos siguen disponibles.'; document.querySelector('.cp')?.after(m); setTimeout(() => m.remove(), 4000); }
  function markWatched(id) { try { const w = JSON.parse(localStorage.getItem('bta-watched') || '[]'); if (!w.includes(id)) { w.push(id); localStorage.setItem('bta-watched', JSON.stringify(w)); document.dispatchEvent(new Event('bta-watched')); } } catch (e) { } }

  window.CyberCast = { Player, durOf, fmt, totalOf: v => v.scenes.reduce((a, s) => a + durOf(s), 0), watched: () => { try { return JSON.parse(localStorage.getItem('bta-watched') || '[]'); } catch (e) { return []; } } };
})();

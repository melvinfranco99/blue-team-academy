/* SOC simulado · investigación de incidentes ya ocurridos (100 % defensivo).
   Los logs se generan en el navegador con datos ficticios e IPs de documentación (RFC 5737). */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  function rng(seed) { return () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
  let R = rng(1);
  const ri = (a, b) => a + Math.floor(R() * (b - a + 1));
  const pk = a => a[Math.floor(R() * a.length)];
  const hms = s => `${pad(Math.floor(s / 3600) % 24)}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
  const T = (h, m, s = 0) => h * 3600 + m * 60 + s;
  const sortT = L => L.sort((a, b) => a[0] - b[0]).map(x => x[1]);

  /* ---------------- Motor de consultas (tuberías estilo Unix) ---------------- */
  function tok(s) { const o = []; let c = '', q = null, h = false; for (const ch of s) { if (q) { if (ch === q) q = null; else c += ch; } else if (ch === '"' || ch === "'") { q = ch; h = true; } else if (/\s/.test(ch)) { if (c || h) { o.push(c); c = ''; h = false; } } else if (ch === '|') { if (c || h) { o.push(c); c = ''; h = false; } o.push('|'); } else c += ch; } if (c || h) o.push(c); return o; }
  function mkRe(p, i, g) { const f = (i ? 'i' : '') + (g ? 'g' : ''); try { return new RegExp(p.replace(/\\\|/g, '|'), f); } catch (e) { return new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), f); } }
  const nArg = (a, d) => { for (let i = 0; i < a.length; i++) { if (a[i] === '-n' && a[i + 1]) return +a[i + 1] || d; const m = a[i].match(/^-n?(\d+)$/); if (m) return +m[1]; } return d; };
  const F = {
    grep(a, L) { let i = 0, v = 0, c = 0, o = 0; const p = []; a.forEach(x => /^-[A-Za-z]+$/.test(x) ? (i |= x.includes('i'), v |= x.includes('v'), c |= x.includes('c'), o |= x.includes('o')) : p.push(x)); if (!p.length) throw Error('uso: grep [-i] [-v] [-c] [-o] [-E] "patrón"'); const re = mkRe(p[0], i); let r = L.filter(l => re.test(l) !== !!v); if (o && !v) { const g = mkRe(p[0], i, 1); r = r.flatMap(l => l.match(g) || []); } return c ? [String(r.length)] : r; },
    head: (a, L) => L.slice(0, nArg(a, 10)), tail: (a, L) => L.slice(-nArg(a, 10)),
    wc: (a, L) => [String(L.length)],
    sort(a, L) { const f = a.join(''), n = f.includes('n'), r = f.includes('r'), u = f.includes('u'); let o = L.slice().sort((x, y) => n ? (parseFloat(x) || 0) - (parseFloat(y) || 0) : x < y ? -1 : x > y ? 1 : 0); if (r) o.reverse(); if (u) o = o.filter((x, k) => o.indexOf(x) === k); return o; },
    uniq(a, L) { const o = []; let p = null, n = 0; const fl = () => { if (p !== null) o.push(a.includes('-c') ? `${String(n).padStart(7)} ${p}` : p); }; L.forEach(l => { if (l === p) n++; else { fl(); p = l; n = 1; } }); fl(); return o; },
    awk(a, L) { let sep = null, prog = null; for (let k = 0; k < a.length; k++) { if (a[k].startsWith('-F')) sep = a[k].slice(2) || a[++k]; else if (prog === null) prog = a[k]; } const m = (prog || '').match(/^\s*(?:\/(.*?)\/)?\s*\{\s*print\s*(.*?)\s*;?\s*\}\s*$/); if (!m) throw Error("awk admite: awk '{print $1, $3}'  ·  awk -F'=' '{print $2}'  ·  awk '/patrón/ {print $NF}'"); const re = m[1] ? mkRe(m[1]) : null, gs = m[2] ? m[2].split(',') : ['$0']; return L.filter(l => !re || re.test(l)).map(l => { const f = sep ? l.split(sep) : l.trim().split(/\s+/); return gs.map(g => (g.match(/\$(NF|\d+)|"([^"]*)"/g) || []).map(t => t[0] === '"' ? t.slice(1, -1) : t === '$NF' ? f[f.length - 1] : t === '$0' ? l : (f[+t.slice(1) - 1] ?? '')).join('')).join(' '); }); },
    cut(a, L) { let d = '\t', fl = null; for (let k = 0; k < a.length; k++) { if (a[k].startsWith('-d')) d = a[k].slice(2) || a[++k]; else if (a[k].startsWith('-f')) fl = a[k].slice(2) || a[++k]; } if (!fl) throw Error('uso: cut -d"<sep>" -f<n>'); const ix = []; fl.split(',').forEach(x => { const [p, q] = x.split('-').map(Number); if (x.includes('-')) for (let i = p || 1; i <= (q || 30); i++) ix.push(i); else ix.push(p); }); return L.map(l => { const f = l.split(d); return ix.map(i => f[i - 1]).filter(x => x !== undefined).join(d); }); },
    cat: (a, L) => L, less: (a, L) => L
  };
  F.egrep = F.grep;
  function runQuery(q, L) {
    const segs = [[]]; tok(q).forEach(x => x === '|' ? segs.push([]) : segs[segs.length - 1].push(x));
    for (const s of segs.filter(x => x.length)) { const f = F[s[0]]; if (!f) throw Error(`«${s[0]}» no está disponible. Usa: grep, awk, cut, sort, uniq, head, tail, wc`); L = f(s.slice(1), L); }
    return L;
  }

  /* ---------------- Casos ---------------- */
  const CASES = [];

  /* 1 · Fuerza bruta SSH */
  CASES.push({
    id: 'ssh', icon: '🔑', lv: 'Inicial', name: 'Fuerza bruta contra SSH', desc: 'Un servidor Linux expuesto recibe miles de intentos de login. ¿Entró alguien?',
    brief: 'Son las 09:00. El SIEM muestra una alerta en <b>srv-web01</b> (10.0.10.20). Tienes su <b>auth.log</b> de la madrugada. Averigua de dónde viene el ataque, si tuvo éxito y qué hizo el atacante.',
    alerts: [['high', 'Wazuh 5763 · Múltiples fallos de autenticación sshd en srv-web01'], ['crit', 'SIEM · Inicio de sesión correcto tras fallos repetidos (srv-web01)']],
    gen() {
      const L = [], H = 'srv-web01', ATT = '203.0.113.66'; let fails = 0, okT = 0;
      const ln = (t, s) => L.push([t, `Nov 26 ${hms(t)} ${H} ${s}`]);
      for (let t = T(0, 0); t < T(6, 0); t += ri(200, 700)) ln(t, `CRON[${ri(3000, 9000)}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)`);
      [T(0, 12, 4), T(5, 48, 31)].forEach(t => { ln(t, `sshd[${ri(1000, 9000)}]: Accepted publickey for admin from 10.0.99.5 port ${ri(40000, 60000)} ssh2: ED25519 SHA256:q2Xh…`); ln(t + 1, `sshd[${ri(1000, 9000)}]: pam_unix(sshd:session): session opened for user admin(uid=1000) by (uid=0)`); });
      ln(T(1, 3, 9), `sshd[2290]: Failed password for jperez from 10.0.20.14 port 51811 ssh2`); ln(T(1, 3, 20), `sshd[2290]: Accepted password for jperez from 10.0.20.14 port 51811 ssh2`);
      for (let i = 0; i < 9; i++) ln(T(2, 10, i * 3), `sshd[${ri(3000, 4000)}]: Failed password for invalid user admin from 198.51.100.9 port ${ri(40000, 60000)} ssh2`);
      const users = ['root', 'admin', 'oracle', 'test', 'ubuntu', 'postgres', 'soporte'];
      let t = T(3, 14, 2);
      for (let i = 0; i < 186; i++) { const u = i < 150 ? pk(users) : 'soporte'; const inv = ['oracle', 'test', 'ubuntu', 'postgres'].includes(u); ln(t, `sshd[${ri(10000, 30000)}]: Failed password for ${inv ? 'invalid user ' : ''}${u} from ${ATT} port ${ri(30000, 65000)} ssh2`); fails++; t += ri(1, 4); }
      okT = t + 2; const pid = 31877;
      ln(okT, `sshd[${pid}]: Accepted password for soporte from ${ATT} port 50112 ssh2`);
      ln(okT + 1, `sshd[${pid}]: pam_unix(sshd:session): session opened for user soporte(uid=1002) by (uid=0)`);
      ln(okT + 1, `systemd-logind[612]: New session 77 of user soporte.`);
      ln(okT + 95, `sudo:  soporte : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/soporte ; USER=root ; COMMAND=/bin/bash`);
      ln(okT + 140, `sudo:  soporte : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`);
      ln(okT + 610, `sshd[${pid}]: pam_unix(sshd:session): session closed for user soporte`);
      this.ans = { ip: ATT, fails: String(fails), ok: hms(okT) };
      return { 'auth.log': sortT(L) };
    },
    qs: c => [
      { q: '¿Qué IP externa tiene más intentos fallidos?', a: [c.ans.ip], how: 'Cuenta los fallos por IP. Como hay líneas con «invalid user», el número de campo cambia; lo más robusto es extraer las IPs con una expresión regular:\n\ngrep "Failed password" | grep -oE "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" | sort | uniq -c | sort -rn\n\nLa IP de arriba es la atacante. Las demás (198.51.100.9, 10.0.20.14) tienen muy pocos fallos: ruido de Internet y un empleado que se equivocó.' },
      { q: '¿Cuántos intentos fallidos hizo esa IP?', a: [c.ans.fails], how: 'Filtra los fallos de esa IP y cuéntalos:\n\ngrep "Failed password" | grep 203.0.113.66 | wc -l' },
      { q: '¿Con qué usuario consiguió entrar?', a: ['soporte'], how: 'Busca los inicios de sesión correctos («Accepted») de la IP atacante:\n\ngrep Accepted | grep 203.0.113.66\n\nEl usuario aparece justo después de «for».' },
      { q: '¿A qué hora (HH:MM:SS) entró?', a: [c.ans.ok], how: 'Es el tercer campo de esa misma línea:\n\ngrep Accepted | grep 203.0.113.66 | awk \'{print $3}\'' },
      { q: '¿Consiguió privilegios de root con sudo? (sí/no)', a: ['no', 'no.'], how: 'Mira qué hizo el usuario después de entrar:\n\ngrep soporte | grep -v Failed\n\nLas líneas de sudo dicen «user NOT in sudoers»: lo intentó (incluso leer /etc/shadow) pero se le denegó.' }
    ],
    acts: [
      ['Bloquear 203.0.113.66 en el firewall perimetral', 1, 'Corta nuevos intentos desde esa IP. Es rápido y de bajo riesgo.'],
      ['Bloquear la cuenta «soporte», cambiar su contraseña y cerrar sus sesiones', 1, 'La contraseña está comprometida: es imprescindible.'],
      ['Buscar en el SIEM la misma IP en el resto de servidores', 1, 'Define el alcance: ¿hay más víctimas?'],
      ['Desactivar el login SSH por contraseña (solo claves) y configurar fail2ban', 1, 'Corrige la causa raíz para que no se repita.'],
      ['Borrar auth.log para limpiar el rastro del atacante', 0, '¡Nunca! Destruyes evidencias que necesitas para investigar.'],
      ['Ignorarlo: el usuario no es administrador', 0, 'Un acceso no autorizado es un incidente, tenga o no privilegios.'],
      ['Apagar el servidor web de inmediato', 0, 'Desproporcionado: corta el negocio y pierdes memoria volátil. Basta con contener la cuenta y la IP.']
    ],
    lesson: 'Patrón clásico: cientos de fallos de una sola IP probando usuarios comunes, seguidos de un «Accepted password». La raíz es doble: contraseña débil y SSH con contraseña expuesto a Internet. MITRE: T1110.001 (adivinar contraseñas) → T1078 (cuentas válidas).'
  });

  /* 2 · Phishing con macro */
  CASES.push({
    id: 'macro', icon: '📎', lv: 'Intermedio', name: 'Phishing con macro (Sysmon)', desc: 'Una empleada abrió una «factura». Reconstruye la cadena con la telemetría de Sysmon.',
    brief: 'El EDR marcó <b>PC-CONTA-07</b>. Tienes los eventos de <b>Sysmon</b> de esa mañana (1 = proceso, 3 = red, 11 = fichero, 13 = registro) y el log del <b>proxy</b>. Reconstruye qué pasó paso a paso.',
    alerts: [['high', 'EDR · Office lanzó un intérprete de comandos en PC-CONTA-07'], ['med', 'Proxy · Descarga de DLL desde IP sin categoría']],
    gen() {
      const S = [], P = [], H = 'PC-CONTA-07', U = 'EMPRESA\\mlopez';
      const sy = (t, id, s) => S.push([t, `2026-11-26 ${hms(t)} EventID=${id} Host=${H} User=${U} ${s}`]);
      const normal = [['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Windows\\explorer.exe'], ['C:\\Users\\mlopez\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe', 'C:\\Windows\\explorer.exe'], ['C:\\Windows\\System32\\notepad.exe', 'C:\\Windows\\explorer.exe'], ['C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE', 'C:\\Windows\\explorer.exe'], ['C:\\Windows\\System32\\svchost.exe', 'C:\\Windows\\System32\\services.exe'], ['C:\\Windows\\System32\\conhost.exe', 'C:\\Windows\\System32\\svchost.exe']];
      for (let t = T(8, 30); t < T(11, 0); t += ri(40, 260)) { const [im, pa] = pk(normal); sy(t, 1, `Image=${im} ParentImage=${pa} CommandLine="${im.split('\\').pop()}"`); }
      for (let t = T(8, 31); t < T(11, 0); t += ri(60, 300)) { const d = pk(['142.250.184.0', '52.112.0.10', '13.107.42.14', '93.184.215.14']); sy(t, 3, `Image=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe DestinationIp=${d} DestinationPort=443`); P.push([t, `${hms(t)} 10.0.10.45 mlopez GET https://${pk(['www.example.com', 'teams.example.net', 'cdn.example.org', 'intranet.empresa.local'])}/ 200 ${ri(2000, 90000)} categoria=negocios`]); }
      const t0 = T(10, 2, 11);
      sy(t0, 11, `Image=C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE TargetFilename=C:\\Users\\mlopez\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\X1Y2\\factura_noviembre.docm`);
      sy(t0 + 29, 1, `Image=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE ParentImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE CommandLine="WINWORD.EXE /n C:\\Users\\mlopez\\…\\factura_noviembre.docm"`);
      sy(t0 + 33, 1, `Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ParentImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE CommandLine="powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIA…"`);
      sy(t0 + 35, 3, `Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe DestinationIp=203.0.113.50 DestinationPort=80`);
      P.push([t0 + 35, `${hms(t0 + 35)} 10.0.10.45 mlopez GET http://203.0.113.50/s/a.dll 200 184320 categoria=sin-categorizar ua="WindowsPowerShell/5.1"`]);
      sy(t0 + 38, 11, `Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe TargetFilename=C:\\Users\\Public\\a.dll`);
      sy(t0 + 40, 1, `Image=C:\\Windows\\System32\\rundll32.exe ParentImage=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine="rundll32.exe C:\\Users\\Public\\a.dll,Start"`);
      sy(t0 + 59, 13, `Image=C:\\Windows\\System32\\rundll32.exe TargetObject=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater Details="rundll32.exe C:\\Users\\Public\\a.dll,Start"`);
      for (let k = 0; k < 14; k++) { const t = t0 + 70 + k * 60 + ri(-2, 2); sy(t, 3, `Image=C:\\Windows\\System32\\rundll32.exe DestinationIp=203.0.113.50 DestinationPort=443`); P.push([t, `${hms(t)} 10.0.10.45 mlopez CONNECT 203.0.113.50:443 200 ${ri(300, 900)} categoria=sin-categorizar ua="-"`]); }
      return { 'sysmon.log': sortT(S), 'proxy.log': sortT(P) };
    },
    qs: () => [
      { q: '¿Qué documento abrió la usuaria? (nombre del fichero)', a: ['factura_noviembre.docm'], how: 'Los adjuntos de Outlook se guardan en INetCache\\Content.Outlook. Busca ficheros creados (EventID 11) por Outlook:\n\ngrep EventID=11 | grep OUTLOOK\n\nLa extensión .docm indica un documento de Word con macros.' },
      { q: '¿Qué proceso padre lanzó PowerShell? (nombre del .exe)', a: ['winword.exe', 'winword'], how: 'Filtra creaciones de proceso de PowerShell y mira el campo ParentImage:\n\ngrep EventID=1 | grep powershell.exe | grep -o "ParentImage=.*CommandLine"\n\nAl final de la ruta verás el ejecutable padre.' },
      { q: '¿A qué IP se conectó PowerShell?', a: ['203.0.113.50'], how: 'Las conexiones son EventID 3:\n\ngrep EventID=3 | grep powershell\n\nConfírmalo en el proxy: verás la descarga de a.dll con el User-Agent de PowerShell.' },
      { q: '¿Qué fichero descargó y ejecutó? (ruta completa)', a: ['c:\\users\\public\\a.dll'], how: 'Busca qué ficheros creó PowerShell (EventID 11) y qué ejecutó después rundll32:\n\ngrep EventID=11 | grep powershell\ngrep rundll32 | grep EventID=1' },
      { q: '¿Cómo se llama el valor de registro usado para persistir?', a: ['updater'], how: 'Los cambios de registro son EventID 13. Busca claves Run:\n\ngrep EventID=13\n\nLa última parte de TargetObject (…\\Run\\Updater) es el nombre del valor.' },
      { q: '¿Cada cuántos segundos contacta el malware con su servidor (aprox.)?', a: ['60', '60s', '1 minuto'], how: 'Mira las horas de las conexiones de rundll32:\n\ngrep EventID=3 | grep rundll32 | awk \'{print $2}\'\n\nSon casi exactamente cada 60 s: es un «beacon» (latido) de malware.' }
    ],
    acts: [
      ['Aislar PC-CONTA-07 desde el EDR (sin apagarlo)', 1, 'Corta el C2 y conserva la memoria para el análisis.'],
      ['Bloquear 203.0.113.50 en firewall y proxy', 1, 'Impide que otros equipos infectados contacten con el C2.'],
      ['Buscar el hash de a.dll y la IP en toda la organización', 1, 'Determina si hay más víctimas del mismo correo.'],
      ['Eliminar el correo de todos los buzones que lo recibieron', 1, 'Evita que otros empleados lo abran.'],
      ['Restablecer la contraseña de mlopez y revocar sesiones', 1, 'El malware pudo robar credenciales o tokens.'],
      ['Borrar a.dll y el valor Updater y dar el caso por cerrado', 0, 'Insuficiente: sin investigar el alcance ni recoger evidencias podrías dejar al atacante dentro.'],
      ['Formatear el equipo antes de investigar', 0, 'Destruye las evidencias. Primero aislar y recoger, luego reimagen.']
    ],
    lesson: 'Cadena: Outlook guarda .docm → Word → PowerShell oculto → descarga DLL → rundll32 → persistencia en Run → beacon cada 60 s. La relación Word → PowerShell es la detección clave (T1204.002 → T1059.001 → T1547.001 → T1071).'
  });

  /* 3 · Ataque web */
  CASES.push({
    id: 'web', icon: '💉', lv: 'Intermedio', name: 'Inyección SQL en la tienda online', desc: 'La web devolvió respuestas enormes a una IP extraña. ¿Se llevaron la base de datos?',
    brief: 'El WAF estaba en modo solo-detección. Tienes el <b>access.log</b> de Apache de <b>tienda.example</b>. Identifica al atacante, la herramienta, el punto vulnerable y si hubo fuga de datos.',
    alerts: [['high', 'WAF (detección) · Posible SQL Injection en /products.php'], ['crit', 'SIEM · Respuestas de gran tamaño a una sola IP en /products.php']],
    gen() {
      const L = [], ATT = '198.51.100.23';
      const w = (t, ip, path, st, sz, ua) => L.push([t, `${ip} - - [26/Nov/2026:${hms(t)} +0100] "GET ${path} HTTP/1.1" ${st} ${sz} "-" "${ua}"`]);
      const UAS = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1) Mobile/15E148', 'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Firefox/132.0'];
      const pages = ['/', '/index.php', '/products.php?id=3', '/products.php?id=7', '/products.php?id=12', '/css/style.css', '/img/banner.jpg', '/contacto.php', '/carrito.php'];
      for (let t = T(9, 0); t < T(12, 0); t += ri(3, 25)) w(t, `192.0.2.${ri(10, 90)}`, pk(pages), 200, ri(1800, 9000), pk(UAS));
      let t = T(10, 41, 7); this.first = hms(t);
      ['/robots.txt', '/admin/', '/backup.zip', '/.git/HEAD', '/phpmyadmin/', '/.env', '/config.php.bak', '/server-status'].forEach(p => { w(t, ATT, p, p === '/server-status' ? 403 : 404, 274, 'Mozilla/5.0 (compatible; scanner)'); t += 2; });
      w(t, ATT, "/products.php?id=1%27", 500, 612, 'sqlmap/1.8.11#stable (https://sqlmap.org)'); t += 3;
      for (let i = 0; i < 60; i++) { const n = i % 6 + 1; w(t, ATT, `/products.php?id=1%20AND%20${ri(1000, 9999)}=${ri(1000, 9999)}`, 200, pk([3120, 120]), 'sqlmap/1.8.11#stable (https://sqlmap.org)'); t += ri(1, 2); if (i > 40) { w(t, ATT, `/products.php?id=-1%20UNION%20ALL%20SELECT%20${Array(n).fill('NULL').join(',')}--`, 200, n === 6 ? 3480 : 612, 'sqlmap/1.8.11#stable (https://sqlmap.org)'); t++; } }
      for (let i = 0; i < 12; i++) { w(t, ATT, `/products.php?id=-1%20UNION%20ALL%20SELECT%20NULL,CONCAT(email,0x3a,password_hash),NULL,NULL,NULL,NULL%20FROM%20tienda.users%20LIMIT%20${i * 50},50--`, 200, ri(46000, 52000), 'sqlmap/1.8.11#stable (https://sqlmap.org)'); t += ri(2, 4); }
      return { 'access.log': sortT(L) };
    },
    qs: c => [
      { q: '¿Qué IP es la atacante?', a: ['198.51.100.23'], how: 'Agrupa las peticiones por IP (campo 1) y busca la que tiene un comportamiento distinto. Más directo: busca User-Agents de herramientas.\n\nawk \'{print $1}\' | sort | uniq -c | sort -rn | head\ngrep -i sqlmap | awk \'{print $1}\' | sort -u' },
      { q: '¿Qué herramienta automatizada usó? (según el User-Agent)', a: ['sqlmap'], how: 'El User-Agent es la última parte de la línea, entre comillas:\n\ngrep 198.51.100.23 | awk -F\'"\' \'{print $6}\' | sort | uniq -c' },
      { q: '¿Qué script PHP era vulnerable?', a: ['products.php', '/products.php'], how: 'Mira qué rutas recibieron las peticiones con UNION:\n\ngrep UNION | awk \'{print $7}\' | cut -d"?" -f1 | sort | uniq -c' },
      { q: '¿Qué tabla de la base de datos se extrajo?', a: ['users', 'tienda.users'], how: 'Busca la palabra FROM en las URLs:\n\ngrep -o "FROM%20[a-z._]*" | sort | uniq -c' },
      { q: '¿Hubo fuga de datos? (sí/no)', a: ['si', 'sí', 'si.', 'sí.'], how: 'Compara el tamaño de respuesta (campo 10) de las peticiones UNION con las normales (~3 KB):\n\ngrep "FROM%20tienda" | awk \'{print $9, $10}\'\n\nCódigo 200 y unos 50 KB por petición: el servidor devolvió los datos.' },
      { q: '¿A qué hora (HH:MM:SS) empezó la actividad de esa IP?', a: [c.first], how: 'La primera línea de la IP:\n\ngrep 198.51.100.23 | head -1 | awk \'{print $4}\'\n\n(quita el corchete y la fecha: la hora va tras «2026:»).' }
    ],
    acts: [
      ['Poner el WAF en modo bloqueo con las reglas SQLi (CRS 942xxx)', 1, 'Contención inmediata frente a nuevos intentos.'],
      ['Bloquear 198.51.100.23', 1, 'Rápido, aunque el atacante puede cambiar de IP: no basta por sí solo.'],
      ['Corregir products.php con consultas preparadas', 1, 'Es la causa raíz. Sin esto, el siguiente atacante repetirá el ataque.'],
      ['Forzar el cambio de contraseña de los usuarios de la tienda', 1, 'Se filtraron hashes de contraseñas.'],
      ['Valorar con el DPO la notificación a la AEPD (72 h) y a los clientes', 1, 'Fuga de datos personales: obligación del RGPD si hay riesgo.'],
      ['Cambiar solo el nombre de products.php', 0, 'Seguridad por oscuridad: no corrige la vulnerabilidad.'],
      ['Restaurar la base de datos desde backup', 0, 'No soluciona nada: los datos ya salieron y la vulnerabilidad sigue ahí.']
    ],
    lesson: 'Secuencia: enumeración de rutas → error SQL provocado (500) → pruebas booleanas → UNION con 6 columnas → volcado de tienda.users en bloques de 50. La señal de éxito es el tamaño de respuesta. MITRE: T1595 → T1190 → T1005/T1041.'
  });

  /* 4 · Túnel DNS */
  CASES.push({
    id: 'dns', icon: '📤', lv: 'Avanzado', name: 'Exfiltración por túnel DNS', desc: 'Volumen anómalo de consultas DNS TXT. ¿Quién está sacando datos y hacia dónde?',
    brief: 'El resolver interno <b>10.0.10.53</b> registra todas las consultas. El SIEM detectó un volumen anómalo. Analiza el <b>dns.log</b> y encuentra el equipo, el dominio y el método.',
    alerts: [['med', 'SIEM · Volumen anómalo de consultas DNS TXT'], ['high', 'Suricata · Subdominio de alta entropía (posible túnel DNS)']],
    gen() {
      const L = [], H = '0123456789abcdef', hex = n => Array.from({ length: n }, () => H[ri(0, 15)]).join('');
      const legit = ['www.example.com', 'login.microsoftonline.com', 'intranet.empresa.local', 'time.example.net', 'update.example.org', 'teams.example.net', 'cdn.example.org'];
      for (let t = T(10, 0); t < T(11, 0); t += ri(1, 4)) L.push([t, `26-Nov-2026 ${hms(t)} client 10.0.10.${pk([31, 32, 45, 52, 60, 61])}#${ri(40000, 65000)} query: ${pk(legit)} IN ${pk(['A', 'A', 'AAAA', 'A'])} +`]);
      let n = 0; for (let t = T(10, 12, 30); t < T(10, 58); t += ri(2, 4)) { L.push([t, `26-Nov-2026 ${hms(t)} client 10.0.10.45#${ri(40000, 65000)} query: ${hex(48)}.d.cdn-sync.example IN TXT +`]); n++; }
      this.n = n; return { 'dns.log': sortT(L) };
    },
    qs: c => [
      { q: '¿Qué tipo de registro DNS se usa de forma anómala?', a: ['txt'], how: 'Cuenta los tipos de registro (campo 8):\n\nawk \'{print $8}\' | sort | uniq -c | sort -rn\n\nLas consultas TXT son raras en un equipo de usuario; aquí son cientos.' },
      { q: '¿Qué dominio (de segundo nivel) recibe esas consultas?', a: ['cdn-sync.example'], how: 'Mira las consultas TXT:\n\ngrep TXT | head -5\n\nQuédate con las dos últimas partes del nombre:\n\ngrep TXT | awk \'{print $6}\' | cut -d. -f3-4 | sort | uniq -c', a: ['10.0.10.45'], how: 'Campo 4 de las consultas TXT, quitando el puerto:\n\ngrep TXT | awk \'{print $4}\' | cut -d"#" -f1 | sort | uniq -c' },
      { q: '¿Cuántas consultas TXT hizo en total?', a: [String(c.n)], how: 'grep TXT | wc -l' },
      { q: '¿Qué longitud tiene el subdominio codificado? (caracteres)', a: ['48'], how: 'Extrae el primer trozo del nombre:\n\ngrep TXT | awk \'{print $6}\' | cut -d. -f1 | head -3\n\nCuenta los caracteres (son hexadecimales: datos codificados). Una consulta normal tiene subdominios cortos y legibles.' }
    ],
    acts: [
      ['Sinkhole del dominio cdn-sync.example en el DNS corporativo', 1, 'Corta el canal de exfiltración para cualquier equipo.'],
      ['Aislar el equipo 10.0.10.45 con el EDR', 1, 'Detiene el proceso y conserva evidencias.'],
      ['Identificar el proceso que hace las consultas (Sysmon EventID 22)', 1, 'Necesario para erradicar y entender el alcance.'],
      ['Estimar el volumen exfiltrado (nº consultas × bytes por consulta)', 1, 'Clave para valorar el impacto y la notificación.'],
      ['Obligar a todos los equipos a usar solo el DNS corporativo (bloquear 53 saliente)', 1, 'Evita túneles que salgan directamente a DNS externos.'],
      ['Bloquear todo el tráfico DNS de la empresa', 0, 'Rompe todos los servicios. Desproporcionado.'],
      ['Considerarlo falso positivo: DNS siempre es tráfico legítimo', 0, 'DNS es justo el canal que los atacantes aprovechan porque casi nunca se vigila.']
    ],
    lesson: 'Un túnel DNS codifica datos en subdominios (aquí hex de 48 caracteres) y los envía como consultas TXT a un dominio controlado por el atacante. Señales: volumen, tipo TXT, alta entropía, un solo origen. MITRE: T1048.003 / T1071.004.'
  });

  /* 5 · Clave AWS filtrada */
  CASES.push({
    id: 'aws', icon: '🟧', lv: 'Avanzado', name: 'Clave de AWS filtrada', desc: 'GuardDuty alerta de uso de credenciales fuera de AWS. Sigue la clave en CloudTrail.',
    brief: 'Un desarrollador subió por error un fichero .env a un repositorio público. GuardDuty ha alertado. Tienes <b>CloudTrail</b> simplificado (una línea por llamada). Averigua qué hizo el atacante con la clave.',
    alerts: [['crit', 'GuardDuty · UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS'], ['high', 'GuardDuty · CryptoCurrency:EC2/BitcoinTool.B!DNS']],
    gen() {
      const L = [], K = 'AKIAEXAMPLEKEY000001', ATT = '203.0.113.66';
      const c = (t, user, key, ip, region, ev, res, extra = '') => L.push([t, `2026-11-26T${hms(t)}Z user=${user} key=${key} ip=${ip} region=${region} event=${ev} result=${res}${extra ? ' ' + extra : ''}`]);
      for (let t = T(0, 0); t < T(6, 0); t += ri(60, 400)) c(t, 'ci-deploy', K, '192.0.2.200', 'eu-west-1', pk(['s3:PutObject', 's3:GetObject', 'ecr:GetAuthorizationToken', 'ecs:UpdateService']), 'OK');
      for (let t = T(0, 5); t < T(6, 0); t += ri(300, 900)) c(t, 'ana.admin', 'ASIAEXAMPLESSO00009', '192.0.2.15', 'eu-west-1', pk(['ec2:DescribeInstances', 'cloudwatch:GetMetricData']), 'OK');
      let t = T(3, 9, 12); this.first = 'sts:GetCallerIdentity';
      c(t, 'ci-deploy', K, ATT, 'us-east-1', 'sts:GetCallerIdentity', 'OK'); t += 40;
      ['iam:ListUsers', 'iam:ListAttachedUserPolicies', 'iam:ListAccessKeys', 'ec2:DescribeRegions'].forEach(e => { c(t, 'ci-deploy', K, ATT, 'us-east-1', e, 'OK'); t += ri(5, 20); });
      c(t, 'ci-deploy', K, ATT, 'us-east-1', 'iam:CreateAccessKey', 'OK', 'target=backup-admin newkey=AKIAEXAMPLEKEY000002'); t += 60;
      for (let i = 0; i < 12; i++) { c(t, 'ci-deploy', K, ATT, 'ap-southeast-2', 'ec2:RunInstances', 'AccessDenied', 'type=c5.4xlarge reason=SCP'); t += 3; }
      for (let i = 0; i < 40; i++) { c(t, 'ci-deploy', K, ATT, 'eu-north-1', 'ec2:RunInstances', 'OK', `type=c5.4xlarge id=i-0${(1000 + i).toString(16)}aa`); t += ri(2, 5); }
      c(t + 30, 'ci-deploy', K, ATT, 'eu-north-1', 'cloudtrail:StopLogging', 'AccessDenied', 'reason=SCP');
      return { 'cloudtrail.log': sortT(L) };
    },
    qs: () => [
      { q: '¿Desde qué IP se usó la clave de forma anómala?', a: ['203.0.113.66'], how: 'La clave del pipeline siempre se usa desde 192.0.2.200. Cuenta IPs por usuario:\n\ngrep ci-deploy | awk \'{print $4}\' | sort | uniq -c' },
      { q: '¿Cuál fue la primera API que llamó el atacante?', a: ['sts:getcalleridentity', 'getcalleridentity'], how: 'grep 203.0.113.66 | head -1\n\n«¿Quién soy?»: lo primero que hace quien encuentra unas credenciales.' },
      { q: '¿Para qué usuario creó una clave nueva (persistencia)?', a: ['backup-admin'], how: 'grep CreateAccessKey\n\nEl campo target= indica el usuario.' },
      { q: '¿En qué región consiguió lanzar instancias?', a: ['eu-north-1'], how: 'grep RunInstances | grep result=OK | awk \'{print $5}\' | sort | uniq -c' },
      { q: '¿Cuántas instancias lanzó con éxito?', a: ['40'], how: 'grep RunInstances | grep result=OK | wc -l' },
      { q: '¿Qué intentó desactivar al final para ocultarse?', a: ['cloudtrail', 'cloudtrail:stoplogging', 'stoplogging'], how: 'Mira las últimas líneas del atacante:\n\ngrep 203.0.113.66 | tail -3\n\nIntentó parar CloudTrail, pero una SCP lo impidió.' }
    ],
    acts: [
      ['Desactivar la clave AKIAEXAMPLEKEY000001', 1, 'Primer paso: corta el acceso del atacante.'],
      ['Desactivar también la clave creada para backup-admin', 1, 'Es la persistencia del atacante: si no, sigue dentro.'],
      ['Snapshot de una instancia como evidencia y detener las 40', 1, 'Conserva pruebas y corta el gasto de minería.'],
      ['Sustituir la clave del pipeline por federación OIDC y activar secret scanning', 1, 'Corrige la causa raíz: claves fijas en ficheros.'],
      ['Borrar el repositorio de GitHub y dar el tema por resuelto', 0, 'Los bots copian las claves en segundos: el daño ya está hecho.'],
      ['Eliminar la cuenta de AWS entera', 0, 'Desproporcionado y destruye todas las evidencias.']
    ],
    lesson: 'Patrón típico de credenciales filtradas: GetCallerIdentity → reconocimiento IAM → persistencia (nueva clave) → minería en regiones no usadas → intento de apagar logs. Las SCP frenaron parte del ataque. MITRE (Cloud): T1078.004 → T1098.001 → T1496 → T1562.008.'
  });

  /* 6 · OAuth en Microsoft 365 */
  CASES.push({
    id: 'oauth', icon: '🔷', lv: 'Avanzado', name: 'App OAuth maliciosa en Microsoft 365', desc: 'Una usuaria aceptó permisos a una app. Investiga en AuditLogs y en el buzón.',
    brief: 'Microsoft Defender avisa de una aplicación sospechosa. Tienes los <b>AuditLogs</b> de Entra ID y la actividad del <b>buzón</b> (MailItemsAccessed / Send) simplificados.',
    alerts: [['high', 'Defender for Cloud Apps · Aplicación OAuth con permisos de correo poco común'], ['med', 'Entra ID · Consentimiento de usuario a aplicación no verificada']],
    gen() {
      const A = [], M = [];
      const users = ['ana.ruiz', 'jgarcia', 'mlopez', 'pfernandez', 'lsanchez'];
      for (let t = T(8, 0); t < T(12, 0); t += ri(300, 900)) A.push([t, `2026-11-26T${hms(t)}Z op="${pk(['Update user', 'Add member to group', 'Reset password (by admin)', 'Update device'])}" by=helpdesk@empresa.example target=${pk(users)}@empresa.example`]);
      A.push([T(9, 10), `2026-11-26T09:10:02Z op="Consent to application" by=jgarcia@empresa.example app="Microsoft Teams Meeting Add-in" verified=true perms="User.Read Calendars.Read"`]);
      A.push([T(9, 44, 18), `2026-11-26T09:44:18Z op="Consent to application" by=ana.ruiz@empresa.example app="DocViewer Pro" verified=false perms="User.Read Mail.Read Mail.Send offline_access"`]);
      A.push([T(9, 44, 19), `2026-11-26T09:44:19Z op="Add service principal" by=ana.ruiz@empresa.example app="DocViewer Pro" appId=5f1c0e2a-0000-4b7e-9d3a-example`]);
      for (let t = T(8, 0); t < T(12, 0); t += ri(60, 400)) M.push([t, `2026-11-26T${hms(t)}Z mailbox=${pk(users)}@empresa.example op=MailItemsAccessed client="Outlook" ip=192.0.2.${ri(10, 40)} items=${ri(1, 6)}`]);
      for (let t = T(9, 50); t < T(11, 30); t += ri(120, 300)) M.push([t, `2026-11-26T${hms(t)}Z mailbox=ana.ruiz@empresa.example op=MailItemsAccessed client="DocViewer Pro" ip=198.51.100.140 items=${ri(40, 200)}`]);
      [T(10, 31), T(10, 32, 5), T(10, 33, 40)].forEach((t, i) => M.push([t, `2026-11-26T${hms(t)}Z mailbox=ana.ruiz@empresa.example op=Send client="DocViewer Pro" ip=198.51.100.140 to=${['finanzas', 'proveedores', 'direccion'][i]}@empresa.example subject="Cambio de cuenta bancaria urgente"`]));
      return { 'auditlogs.log': sortT(A), 'mailbox.log': sortT(M) };
    },
    qs: () => [
      { q: '¿Cómo se llama la aplicación sospechosa?', a: ['docviewer pro'], how: 'grep "Consent to application"\n\nCompara: una app verificada con permisos de calendario frente a otra NO verificada que pide correo.' },
      { q: '¿Qué usuaria concedió el consentimiento? (sin @dominio)', a: ['ana.ruiz', 'ana.ruiz@empresa.example'], how: 'Campo by= de esa línea de consentimiento.' },
      { q: '¿Qué permiso le permite enviar correo en nombre de la usuaria?', a: ['mail.send'], how: 'Lee el campo perms=. offline_access además le da acceso continuado sin que la usuaria esté conectada.' },
      { q: '¿Desde qué IP accede la app al buzón?', a: ['198.51.100.140'], how: 'grep "DocViewer" | grep MailItemsAccessed | grep -o "ip=[0-9.]*" | sort | uniq -c' },
      { q: '¿Cuántos correos envió la app?', a: ['3'], how: 'grep op=Send | grep DocViewer | wc -l\n\nEl asunto revela el objetivo: fraude del CEO / cambio de cuenta bancaria (BEC).' }
    ],
    acts: [
      ['Revocar el consentimiento y eliminar el service principal de DocViewer Pro', 1, 'Corta el acceso de la app (cambiar la contraseña NO basta).'],
      ['Avisar urgentemente a finanzas, proveedores y dirección de que los correos son fraudulentos', 1, 'Evita una transferencia fraudulenta: el impacto económico es lo más urgente.'],
      ['Revocar sesiones y tokens de ana.ruiz y revisar reglas de su buzón', 1, 'Elimina cualquier acceso o regla de reenvío residual.'],
      ['Restringir el consentimiento de usuarios a apps verificadas / con aprobación de admin', 1, 'Corrige la causa raíz.'],
      ['Solo cambiar la contraseña de ana.ruiz', 0, 'Los tokens OAuth de la app siguen siendo válidos.'],
      ['Desactivar el correo de toda la empresa', 0, 'Desproporcionado: basta con contener la app y la cuenta.']
    ],
    lesson: 'El consentimiento ilícito no roba la contraseña: obtiene tokens OAuth con permisos (Mail.Read/Send, offline_access) que sobreviven a un cambio de contraseña. Aquí se usó para un fraude BEC desde el propio buzón. MITRE: T1528 → T1114.002 → T1534.'
  });

  /* ---------------- UI ---------------- */
  let C = null, LOGS = null, SRC = null, QS = [], st = null;
  const best = () => { try { return JSON.parse(localStorage.getItem('bta-soc-best') || '{}'); } catch (e) { return {}; } };
  function renderCases() {
    const b = best();
    $('cases').innerHTML = CASES.map(c => `<div class="case ${C && C.id === c.id ? 'on' : ''}" data-id="${c.id}"><span class="lv">${c.lv}</span><div class="i">${c.icon}</div><h4>${esc(c.name)}</h4><p>${esc(c.desc)}</p>${b[c.id] != null ? `<div class="best">★ mejor: ${b[c.id]} pts</div>` : ''}</div>`).join('');
    document.querySelectorAll('.case').forEach(e => e.onclick = () => load(e.dataset.id));
  }
  function load(id) {
    C = CASES.find(c => c.id === id); R = rng(id.length * 7919 + 13);
    LOGS = C.gen(); SRC = Object.keys(LOGS)[0]; QS = C.qs(C);
    st = { ok: new Set(), hints: new Set(), wrong: 0, done: false };
    renderCases(); $('work').hidden = false;
    $('c-title').textContent = `${C.icon} ${C.name}`; $('c-brief').innerHTML = C.brief;
    $('c-alerts').innerHTML = C.alerts.map(a => `<div class="${a[0]}"><span class="sv">${a[0].toUpperCase()}</span><span>${esc(a[1])}</span></div>`).join('');
    $('c-qs').innerHTML = QS.map((q, i) => `<div class="q" id="q${i}"><label>${i + 1}. ${esc(q.q)}</label><div class="row"><input data-i="${i}" spellcheck="false" autocomplete="off"><button data-c="${i}">Comprobar</button><button data-h="${i}" title="Ver cómo se hace (−20 pts)">💡 Cómo</button></div><div class="fb"></div><div class="hint">${esc(q.how).replace(/\n/g, '<br>')}</div></div>`).join('');
    $('c-qs').querySelectorAll('[data-c]').forEach(b => b.onclick = () => check(+b.dataset.c));
    $('c-qs').querySelectorAll('input').forEach(i => i.onkeydown = e => { if (e.key === 'Enter') check(+i.dataset.i); });
    $('c-qs').querySelectorAll('[data-h]').forEach(b => b.onclick = () => { const i = +b.dataset.h; st.hints.add(i); $('q' + i).querySelector('.hint').classList.add('on'); score(); });
    $('c-acts').innerHTML = C.acts.map((a, i) => `<label data-i="${i}"><input type="checkbox" value="${i}"><span>${esc(a[0])}<span class="why" hidden>${a[1] ? '✔' : '✘'} ${esc(a[2])}</span></span></label>`).join('');
    $('c-report').hidden = true; $('finish').disabled = false;
    renderSrcs(); $('qin').value = ''; run(''); score();
    $('work').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function renderSrcs() {
    $('srcs').innerHTML = Object.keys(LOGS).map(k => `<button class="${k === SRC ? 'on' : ''}" data-s="${k}">📄 ${k} <small>(${LOGS[k].length})</small></button>`).join('');
    $('srcs').querySelectorAll('button').forEach(b => b.onclick = () => { SRC = b.dataset.s; renderSrcs(); $('qp').textContent = `cat ${SRC} |`; run($('qin').value); });
    $('qp').textContent = `cat ${SRC} |`;
    const ex = ['head -20', 'wc -l', 'grep -i "error\\|fail"', "awk '{print $1}' | sort | uniq -c | sort -rn | head", 'tail -15'];
    $('ex').innerHTML = ex.map(e => `<button>${esc(e)}</button>`).join('');
    $('ex').querySelectorAll('button').forEach(b => b.onclick = () => { $('qin').value = b.textContent; run(b.textContent); });
  }
  function run(q) {
    const out = $('out'); let L;
    try { L = q.trim() ? runQuery(q, LOGS[SRC]) : LOGS[SRC].slice(0, 400); }
    catch (e) { out.innerHTML = `<span class="e">${esc(e.message)}</span>`; return; }
    const total = L.length, shown = L.slice(0, 1500);
    let pat = null; const m = q.match(/grep\s+(?:-[A-Za-z]+\s+)*(?:"([^"]+)"|'([^']+)'|(\S+))/); if (m && !/-v/.test(q.split('|')[0])) pat = m[1] || m[2] || m[3];
    let html = shown.map(l => esc(l)).join('\n');
    if (pat) { try { const re = mkRe(esc(pat), /-\w*i/.test(q), 1); html = html.replace(re, x => x ? `<mark>${x}</mark>` : x); } catch (e) { } }
    out.innerHTML = `<span class="c">$ cat ${esc(SRC)}${q.trim() ? ' | ' + esc(q.trim()) : ' | head -400'}</span>\n${html || '<span class="m">(sin resultados)</span>'}${total > shown.length ? `\n<span class="m">… ${total - shown.length} líneas más (usa head, tail o filtra con grep)</span>` : ''}\n<span class="m">— ${total} línea(s)</span>`;
    out.scrollTop = 0;
  }
  const norm = s => s.trim().toLowerCase().replace(/\s+/g, ' ').replace(/^"|"$/g, '');
  function check(i) {
    if (st.done) return; const box = $('q' + i), v = norm(box.querySelector('input').value); if (!v) return;
    const good = QS[i].a.map(norm).includes(v);
    box.classList.toggle('ok', good); box.classList.toggle('bad', !good);
    box.querySelector('.fb').textContent = good ? '✔ Correcto' : '✘ No es correcto. Revisa los logs (o pulsa «💡 Cómo»).';
    if (good) st.ok.add(i); else st.wrong++;
    score();
  }
  function pts() {
    let p = 0; st.ok.forEach(() => p += 100); p -= st.hints.size * 20; p -= st.wrong * 5;
    if (st.done) document.querySelectorAll('#c-acts input').forEach(x => { p += C.acts[+x.value][1] ? (x.checked ? 50 : -25) : (x.checked ? -50 : 0); });
    return Math.max(0, p);
  }
  const maxPts = () => QS.length * 100 + C.acts.filter(a => a[1]).length * 50;
  function score() { $('pts').textContent = `${pts()} / ${maxPts()}`; $('prog').textContent = `${st.ok.size}/${QS.length} preguntas · ${st.hints.size} pistas`; }
  function finish() {
    if (st.done) return; st.done = true; $('finish').disabled = true;
    document.querySelectorAll('#c-acts label').forEach(l => { const a = C.acts[+l.dataset.i], ch = l.querySelector('input').checked; const cl = a[1] ? 'good' : (ch ? 'badc' : ''); if (cl) l.classList.add(cl); l.querySelector('.why').hidden = false; l.querySelector('input').disabled = true; });
    QS.forEach((q, i) => { if (!st.ok.has(i)) { const b = $('q' + i); b.querySelector('.fb').textContent = `Respuesta: ${q.a[0]}`; b.querySelector('.hint').classList.add('on'); } });
    const p = pts(), mx = maxPts(), pct = p / mx, g = pct >= .9 ? 'S' : pct >= .75 ? 'A' : pct >= .6 ? 'B' : pct >= .4 ? 'C' : 'D';
    const b = best(); if (b[C.id] == null || p > b[C.id]) { b[C.id] = p; localStorage.setItem('bta-soc-best', JSON.stringify(b)); }
    const chosen = [...document.querySelectorAll('#c-acts input:checked')].map(x => '  - ' + C.acts[+x.value][0]).join('\n') || '  (ninguna)';
    const rep = `INFORME DE INCIDENTE — ${C.name}\nFecha: ${new Date().toLocaleString('es-ES')}   Analista: tú   Nota: ${g} (${p}/${mx})\n\nHallazgos:\n${QS.map((q, i) => `  ${st.ok.has(i) ? '✔' : '✘'} ${q.q} → ${q.a[0]}`).join('\n')}\n\nAcciones de respuesta propuestas:\n${chosen}\n\nResumen técnico:\n  ${C.lesson}`;
    $('c-report').hidden = false;
    $('rep-grade').textContent = g; $('rep-pts').textContent = `${p} / ${mx} puntos`;
    $('rep-text').textContent = rep; renderCases(); score();
    $('c-report').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  document.addEventListener('DOMContentLoaded', () => {
    renderCases();
    $('qin').addEventListener('keydown', e => { if (e.key === 'Enter') run($('qin').value); });
    $('qrun').onclick = () => run($('qin').value);
    $('qclr').onclick = () => { $('qin').value = ''; run(''); };
    $('finish').onclick = finish;
    $('copyrep').onclick = () => { navigator.clipboard.writeText($('rep-text').textContent); $('copyrep').textContent = '✓ Copiado'; setTimeout(() => $('copyrep').textContent = '📋 Copiar informe', 1500); };
    $('again').onclick = () => load(C.id);
    const h = location.hash.slice(1); if (CASES.some(c => c.id === h)) load(h);
  });
})();

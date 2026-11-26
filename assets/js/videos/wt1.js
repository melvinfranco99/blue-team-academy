/* Laboratorios guiados paso a paso (lecciones 1–8). Se insertan antes del repaso final. */
window.WT = window.WT || {};
Object.assign(WT, {
  intro: [
    { t: 'splunk', title: 'Triaje de una alerta real en el SIEM', note: 'Primero, ver los datos crudos de la alerta', q: 'index=windows host=PC-CONTA-07 earliest=-30m | table _time EventCode User Image ParentImage', count: '5 events', range: 'Últimos 30 min', head: ['_time', 'EventCode', 'User', 'Image', 'ParentImage'], rows: [['10:02:40', '4688', 'mlopez', 'WINWORD.EXE', 'OUTLOOK.EXE'], ['10:02:44', '4688', 'mlopez', 'powershell.exe', 'WINWORD.EXE'], ['10:02:51', '4688', 'mlopez', 'rundll32.exe', 'powershell.exe'], ['10:03:00', '4624', 'mlopez', '-', '-'], ['10:05:12', '4688', 'mlopez', 'chrome.exe', 'explorer.exe']], hl: [1, 2], say: 'Vamos a hacer juntos el triaje de una alerta, paso a paso. La alerta dice: PowerShell sospechoso en el equipo PC CONTA cero siete. Paso uno: nunca te quedes con el título de la alerta, mira los datos crudos. Escribo en el buscador del SIEM: index igual a windows, host igual al nombre del equipo, y earliest igual a menos treinta minutos, para ver solo la última media hora. Después, con table, elijo cinco columnas: hora, código de evento, usuario, proceso y proceso padre. Pulso buscar. Ahora leo de arriba abajo: Outlook abre Word, Word abre PowerShell, y PowerShell abre rundll treinta y dos. Las dos filas resaltadas son la anomalía: Word nunca debería lanzar PowerShell.', step: [1, 4] },
    { t: 'splunk', title: 'Pivotar: ¿con quién habló el equipo?', note: 'Cambiar de fuente: del endpoint a la red', q: 'index=proxy src_ip=10.0.10.45 earliest=-30m | stats count sum(bytes_out) as enviados by dest_ip url_category | sort -count', count: '4 results', range: 'Últimos 30 min', head: ['dest_ip', 'url_category', 'count', 'enviados'], rows: [['203.0.113.50', 'sin-categorizar', '27', '1.4 MB'], ['142.250.184.0', 'buscadores', '19', '88 KB'], ['52.112.0.10', 'colaboración', '11', '41 KB'], ['93.184.215.14', 'negocios', '6', '12 KB']], hl: [0], say: 'Paso dos: pivotar. Ya sé qué pasó en el equipo; ahora quiero saber con quién habló. Cambio de índice al del proxy y filtro por la IP del equipo, diez punto cero punto diez punto cuarenta y cinco. Con stats cuento conexiones y sumo los bytes enviados, agrupando por IP de destino y categoría web. Ordeno con sort menos count, de más a menos. El resultado: casi todo es normal, buscadores y herramientas de colaboración, pero hay una IP sin categorizar con veintisiete conexiones y uno coma cuatro megas enviados. Esa IP la copio, porque es mi primer indicador.', step: [2, 4] },
    { t: 'chat', title: 'Enriquecer la IP con inteligencia', note: 'Comprobar reputación antes de decidir', app: 'Consola de Threat Intelligence', bot: 'TI', msgs: [['u', 'lookup 203.0.113.50'], ['a', 'Reputación: MALICIOSA (3 de 3 fuentes)\nPrimera vez vista: hace 6 días\nAsociada a: servidor C2 · campaña de facturas falsas (sector servicios)\nOtros clientes que la han visto: 14\nRecomendación: bloquear y buscar en logs de los últimos 7 días']], say: 'Paso tres: enriquecer. Pego la IP en la consola de inteligencia de amenazas. En el mundo real usarías VirusTotal, AbuseIPDB o la plataforma de tu empresa. La respuesta confirma la sospecha: tres de tres fuentes la marcan como maliciosa, es un servidor de mando y control de una campaña de facturas falsas, y la han visto otros catorce clientes. Ahora ya no es una sospecha: es un incidente confirmado. Fíjate que hemos tardado unos minutos, porque seguimos un orden.', step: [3, 4] },
    { t: 'code', title: 'Escribir la nota de escalado', note: 'Lo que el L2 necesita para actuar sin preguntarte nada', file: 'Caso INC-2026-112 · nota del L1', code: `RESUMEN: Ejecución de malware vía macro en PC-CONTA-07 (usuaria mlopez). CONFIRMADO.
EVIDENCIAS:
  10:02:40 OUTLOOK → WINWORD (factura_noviembre.docm)
  10:02:44 WINWORD → powershell.exe -nop -w hidden -enc …
  10:02:51 powershell → rundll32 C:\\Users\\Public\\a.dll
  Proxy: 27 conexiones / 1,4 MB a 203.0.113.50 (TI: C2 malicioso, 3/3 fuentes)
ACCIONES HECHAS: equipo aislado desde EDR a las 10:09 (sin apagar).
PENDIENTE L2: alcance (¿más equipos con 203.0.113.50?), purga del correo, credenciales.
SEVERIDAD: Alta · MITRE T1566.001 → T1059.001 → T1218.011`, hl: [1, 7, 8], say: 'Paso cuatro: escalar con una nota que el nivel dos pueda usar sin hacerte ni una pregunta. Primera línea: resumen y si está confirmado. Después, las evidencias con hora exacta: la cadena de procesos y la conexión al servidor malicioso. Luego, qué has hecho ya: aislar el equipo sin apagarlo, para conservar la memoria. Después, qué queda pendiente. Y por último, severidad y técnicas de MITRE. Esta es exactamente la nota que diferencia a un buen analista junior. Practícala con el caso de phishing del SOC simulado de la academia.', step: [4, 4] }
  ],
  redes: [
    { t: 'term', title: 'Ver tu propia configuración de red', note: 'Dónde estoy: IP, máscara, puerta de enlace, DNS', prompt: 'alumno@lab:~$', lines: `
$ ip -br addr
lo       UNKNOWN  127.0.0.1/8
eth0     UP       192.168.56.10/24
$ ip route
default via 192.168.56.1 dev eth0
192.168.56.0/24 dev eth0 proto kernel scope link src 192.168.56.10
$ resolvectl status | grep "DNS Servers"
       DNS Servers: 192.168.56.1`, say: 'Laboratorio guiado de redes. Paso uno: saber dónde estás. Escribo ip, espacio, guion br, espacio, addr. La opción br significa breve. La salida tiene tres columnas: interfaz, estado y dirección. Mi interfaz eth cero está levantada, UP, con la IP ciento noventa y dos punto ciento sesenta y ocho punto cincuenta y seis punto diez, barra veinticuatro. Esa barra veinticuatro es la máscara: los tres primeros números son la red, el último el equipo. Ahora ip route: la línea default via indica la puerta de enlace, el router por el que sale todo lo que no es de mi red. Y resolvectl me dice qué servidor DNS uso.', step: [1, 4] },
    { t: 'term', title: 'Comprobar conectividad capa a capa', note: 'Si algo falla, probar de abajo arriba', prompt: 'alumno@lab:~$', lines: `
$ ping -c 2 192.168.56.1
64 bytes from 192.168.56.1: icmp_seq=1 ttl=64 time=0.41 ms
+2 packets transmitted, 2 received, 0% packet loss
$ dig +short web01.lab.local
192.168.56.20
$ nc -zv 192.168.56.20 80
+Connection to 192.168.56.20 80 port [tcp/http] succeeded!
$ curl -sI http://192.168.56.20 | head -2
HTTP/1.1 200 OK
Server: Apache/2.4.57 (Debian)`, say: 'Paso dos: comprobar la conectividad de abajo arriba, como un médico que explora por orden. Primero ping a la puerta de enlace con guion c dos, solo dos paquetes: cero por ciento de pérdida, la red local funciona. Segundo, dig con más short para resolver el nombre del servidor web: el DNS funciona y nos da su IP. Tercero, nc guion zv a la IP y al puerto ochenta: z significa solo comprobar, sin enviar datos, y v que nos lo cuente. Conexión correcta, el puerto está abierto. Cuarto, curl guion sI pide solo las cabeceras HTTP: la aplicación responde doscientos OK. Si algo fallara, sabrías exactamente en qué capa.', step: [2, 4] },
    { t: 'term', title: 'Ver el handshake con tus propios ojos', note: 'Capturar en una terminal y generar tráfico en otra', prompt: 'alumno@lab:~$', lines: `
$ sudo tcpdump -i eth0 -n 'host 192.168.56.20 and port 80' -c 6
10:21:05.114 IP 192.168.56.10.41822 > 192.168.56.20.80: Flags [S], seq 1830041
10:21:05.115 IP 192.168.56.20.80 > 192.168.56.10.41822: Flags [S.], seq 99120, ack 1830042
10:21:05.115 IP 192.168.56.10.41822 > 192.168.56.20.80: Flags [.], ack 99121
10:21:05.116 IP 192.168.56.10.41822 > 192.168.56.20.80: Flags [P.], length 78: HTTP: GET / HTTP/1.1
10:21:05.118 IP 192.168.56.20.80 > 192.168.56.10.41822: Flags [P.], length 312: HTTP: HTTP/1.1 200 OK
10:21:05.119 IP 192.168.56.10.41822 > 192.168.56.20.80: Flags [F.], seq 79`, say: 'Paso tres: ver el handshake con tus propios ojos. En una terminal lanzo tcpdump en la interfaz eth cero, con guion n para no resolver nombres, un filtro para el servidor web y el puerto ochenta, y guion c seis para parar tras seis paquetes. En otra terminal ejecuto el curl del paso anterior. Ahora leemos: la bandera S es el SYN del cliente. S punto es SYN ACK del servidor. El punto solo es el ACK final: conexión establecida. P punto son datos: la petición GET y la respuesta doscientos OK. Y F es el cierre. Acabas de ver el modelo TCP en un tráfico real.', step: [3, 4] },
    { t: 'term', title: '¿Qué está escuchando mi equipo?', note: 'Cada puerto abierto es una puerta: ¿debería estar ahí?', prompt: 'alumno@lab:~$', lines: `
$ sudo ss -tulpn
Netid State  Local Address:Port  Process
tcp   LISTEN 0.0.0.0:22          users:(("sshd",pid=612))
tcp   LISTEN 127.0.0.1:5432      users:(("postgres",pid=801))
!tcp   LISTEN 0.0.0.0:8888        users:(("python3",pid=4410))
$ ps -o user,pid,cmd -p 4410
USER   PID   CMD
alumno 4410  python3 -m http.server 8888
# Servidor de pruebas olvidado y abierto a toda la red → cerrarlo
$ kill 4410`, say: 'Paso cuatro: qué escucha mi propio equipo. sudo ss guion tulpn: t de TCP, u de UDP, l de escuchando, p de proceso, n numérico. Leo cada fila: SSH en el veintidós para todas las interfaces, es lo esperado. PostgreSQL en el cinco mil cuatrocientos treinta y dos, pero solo en ciento veintisiete punto cero punto cero punto uno, es decir, solo accesible desde el propio equipo: bien configurado. Y un python tres en el ocho mil ochocientos ochenta y ocho abierto a toda la red. Con ps miro qué es: un servidor web de pruebas que alguien olvidó. Lo cierro. Este ejercicio de revisar puertos es la base del hardening.', step: [4, 4] }
  ],
  nmap: [
    { t: 'term', title: 'Descubrir qué hosts hay en tu red de laboratorio', note: 'Inventario: no puedes proteger lo que no conoces', prompt: 'alumno@lab:~$', lines: `
$ sudo nmap -sn 192.168.56.0/24
Nmap scan report for 192.168.56.1    Host is up (0.00031s latency).
Nmap scan report for 192.168.56.10   Host is up.
Nmap scan report for 192.168.56.20   Host is up (0.00052s latency).
Nmap scan report for 192.168.56.30   Host is up (0.00061s latency).
!Nmap scan report for 192.168.56.77   Host is up (0.00090s latency).   ← no está en el inventario
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.10 seconds`, say: 'Laboratorio guiado de Nmap, siempre en tu red de laboratorio. Paso uno: descubrir qué hosts existen. Escribo sudo nmap guion sn y la red en notación CIDR, barra veinticuatro, que son doscientas cincuenta y seis direcciones. La opción sn significa: no escanees puertos, solo dime quién está vivo. En dos segundos tengo cinco hosts. Los comparo con mi inventario: el uno es el router, el diez soy yo, el veinte el servidor web, el treinta el Windows. Pero el setenta y siete no está en el inventario. Lo anoto: es lo primero que investigaremos.', step: [1, 4] },
    { t: 'term', title: 'Identificar servicios y versiones', note: '-sV pregunta a cada puerto qué software es', prompt: 'alumno@lab:~$', lines: `
$ sudo nmap -sS -sV -p- --min-rate 2000 192.168.56.77 -oA host77
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
!23/tcp   open  telnet  BusyBox telnetd
80/tcp   open  http    lighttpd 1.4.35
!8080/tcp open  http    Hikvision IP camera httpd
Service Info: Device: webcam
Nmap done: 1 IP address (1 host up) scanned in 41.3 seconds`, say: 'Paso dos: averiguar qué es ese host. sudo nmap guion sS hace un escaneo SYN, el más habitual. Guion sV interroga a cada puerto abierto para identificar software y versión. Guion p guion, es decir p menos, escanea los sesenta y cinco mil quinientos treinta y cinco puertos, no solo los mil más comunes. min rate acelera el escaneo, y guion oA guarda el resultado en tres formatos con el nombre host setenta y siete. Resultado: es una cámara IP con Telnet abierto y un SSH muy antiguo. Alguien la conectó a la red sin avisar. Dos hallazgos: Telnet envía contraseñas en claro, y el software está desactualizado.', step: [2, 4] },
    { t: 'term', title: 'Comprobar configuraciones con scripts NSE seguros', note: 'Categoría "safe": comprobaciones que no rompen nada', prompt: 'alumno@lab:~$', lines: `
$ sudo nmap -sV --script "safe and (ssl-* or http-headers or ssh2-enum-algos)" -p 22,443 192.168.56.20
443/tcp open  https
| ssl-enum-ciphers:
!|   TLSv1.0: ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA (weak) - C
|   TLSv1.3: ciphers: TLS_AES_256_GCM_SHA384 - A
|_  least strength: C
| ssl-cert: Subject: commonName=web01.lab.local
!|_Not valid after:  2026-12-01T00:00:00   ← caduca en 5 días
22/tcp open  ssh
| ssh2-enum-algos:
!|_  kex_algorithms: diffie-hellman-group1-sha1 (débil)`, say: 'Paso tres: comprobar configuraciones con scripts NSE. Uso la opción script con una expresión: solo scripts de la categoría safe, seguros, y además que sean de SSL, cabeceras HTTP o algoritmos de SSH. En el puerto cuatrocientos cuarenta y tres, ssl enum ciphers puntúa cada cifrado: todavía acepta TLS uno punto cero con un cifrado débil, nota C. El certificado caduca en cinco días: si no se renueva, la web dará error. Y SSH acepta un intercambio de claves obsoleto. Tres tareas de hardening concretas, sacadas de un solo comando.', step: [3, 4] },
    { t: 'code', title: 'Convertir el escaneo en un informe accionable', note: 'Un hallazgo sin responsable ni fecha no se corrige', file: 'informe_inventario_lab.md', code: `| Host           | Hallazgo                          | Riesgo | Acción                       | Responsable | Fecha  |
|----------------|-----------------------------------|--------|------------------------------|-------------|--------|
| 192.168.56.77  | Cámara no inventariada            | Alto   | Mover a VLAN IoT / retirar   | Redes       | 28/11  |
| 192.168.56.77  | Telnet abierto (credenciales claro)| Alto   | Deshabilitar Telnet          | Redes       | 28/11  |
| 192.168.56.20  | TLS 1.0 + 3DES                    | Medio  | Solo TLS 1.2/1.3             | Sistemas    | 05/12  |
| 192.168.56.20  | Certificado caduca 01/12          | Alto   | Renovar (automatizar ACME)   | Sistemas    | 29/11  |
| 192.168.56.20  | SSH kex group1-sha1               | Bajo   | Endurecer sshd_config        | Sistemas    | 12/12  |
Evidencia: host77.xml / web01_nse.xml (adjuntos)`, hl: [3, 4, 6], say: 'Paso cuatro: el escaneo no sirve de nada si no se convierte en acciones. Escribo una tabla con cada hallazgo, su riesgo, la acción concreta, el responsable y una fecha. Los altos primero: la cámara no inventariada con Telnet y el certificado a punto de caducar. Adjunto los ficheros XML como evidencia. Y la semana siguiente repito el escaneo con ndiff para verificar que se corrigió. Así trabaja un equipo defensivo con Nmap.', step: [4, 4] }
  ],
  nessus: [
    { t: 'bul', title: 'Crear un escaneo autenticado', note: 'Con credenciales, Nessus ve 10 veces más', items: ['**New Scan → Advanced Scan**', 'Targets: `192.168.56.20, 192.168.56.30`', 'Credentials → **SSH** (usuario `nessus-scan` con clave, sudo sin contraseña solo para comandos de lectura)', 'Credentials → **Windows** (cuenta de dominio de escaneo, no Domain Admin)', 'Schedule: semanal, de madrugada · Notificar al SOC', 'Plugins: dejar por defecto; desactivar **DoS** en producción'], say: 'Laboratorio guiado de Nessus. Paso uno: crear un escaneo autenticado, que es el que ven los profesionales. En la consola pulso New Scan y elijo Advanced Scan. En Targets escribo las IPs del servidor Linux y del Windows del laboratorio. En la pestaña Credentials añado SSH con un usuario dedicado al escaneo y autenticación por clave, y para Windows una cuenta de escaneo del dominio, nunca un administrador del dominio. Programo el escaneo semanal de madrugada. Y en producción desactivo los plugins de denegación de servicio. Con credenciales, Nessus mira dentro del sistema: paquetes instalados, configuración y parches.', step: [1, 4] },
    { t: 'dash', title: 'Leer los resultados sin agobiarse', note: 'Ordenar por severidad y por "Exploitable"', app: 'Nessus · Scan results · web01', widgets: [{ k: 'stat', t: 'Critical', v: '3', c: '#ef4444' }, { k: 'stat', t: 'High', v: '11', c: '#f97316' }, { k: 'stat', t: 'Medium', v: '24', c: '#f59e0b' }, { k: 'stat', t: 'Info', v: '87', c: '#64748b' }, { k: 'list', t: 'Vulnerabilities (filtro: Exploit Available = true)', w: 4, h: 2, items: [['crit', 'Apache HTTP Server 2.4.x < 2.4.60 — Multiple Vulnerabilities (VPR 8.4)'], ['crit', 'OpenSSL 3.0.x < 3.0.15 (VPR 7.9)'], ['high', 'PHP 8.1.x < 8.1.29 — Multiple Vulnerabilities'], ['high', 'SSH Weak Key Exchange Algorithms Enabled']] }], say: 'Paso dos: leer los resultados sin agobiarse. Ves tres críticas, once altas, veinticuatro medias y ochenta y siete informativas. No empieces por arriba sin más: aplica el filtro Exploit Available igual a true, es decir, solo las que tienen un exploit público. Y ordena por VPR, la puntuación de Tenable que tiene en cuenta la explotación real. Así la lista queda en cuatro elementos claros: Apache, OpenSSL, PHP y los algoritmos débiles de SSH.', step: [2, 4] },
    { t: 'term', title: 'Verificar el hallazgo en el propio servidor', note: 'Nunca te fíes ciegamente del escáner', prompt: 'admin@web01:~$', lines: `
$ apache2 -v
Server version: Apache/2.4.57 (Debian)
$ apt list --upgradable 2>/dev/null | grep -E "apache2|openssl|php8"
!apache2/stable-security 2.4.62-1~deb12u2 amd64 [upgradable from: 2.4.57-2]
!openssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.11-1]
$ sudo apt install --only-upgrade apache2 openssl && sudo systemctl restart apache2
+Setting up apache2 (2.4.62-1~deb12u2) ...`, say: 'Paso tres: verificar en el propio servidor. Me conecto y compruebo la versión de Apache: dos punto cuatro punto cincuenta y siete, confirmado. Con apt list upgradable veo qué paquetes tienen actualización de seguridad disponible, y filtro con grep por los afectados. Ojo a un detalle importante: las distribuciones a veces aplican el parche sin cambiar el número de versión principal, lo que genera falsos positivos en los escáneres; por eso siempre se verifica. Aquí sí hay actualización: la instalamos con only upgrade y reiniciamos Apache, en una ventana de mantenimiento acordada.', step: [3, 4] },
    { t: 'term', title: 'Re-escanear y cerrar el ticket', note: 'Lo que no se verifica, no está corregido', prompt: 'analista@nessus:~$', lines: `
# En la consola: Scan "web01-semanal" → Launch (o "Rescan" sobre los plugins afectados)
Scan finished · web01 · 14 min
+Apache HTTP Server < 2.4.60      → Fixed
+OpenSSL 3.0.x < 3.0.15           → Fixed
!PHP 8.1.x < 8.1.29               → Still open (el equipo de desarrollo pide 1 semana)
# Ticket VULN-381: cerrar Apache y OpenSSL; PHP → excepción temporal aprobada hasta 05/12
#                   con mitigación: WAF en modo bloqueo para la aplicación`, say: 'Paso cuatro: re escanear y cerrar. Lanzamos de nuevo el escaneo, o solo los plugins afectados. Apache y OpenSSL aparecen como corregidos. PHP sigue abierto, porque el equipo de desarrollo necesita una semana para probar la nueva versión. Eso se gestiona con una excepción temporal, aprobada por el responsable de riesgos, con fecha de caducidad y una mitigación compensatoria: el WAF en modo bloqueo. Así se cierra el ciclo de gestión de vulnerabilidades.', step: [4, 4] }
  ],
  snort: [
    { t: 'code', title: 'Escribir una regla para detectar una herramienta de escaneo web', note: 'Detectar el User-Agent de un escáner contra tu web', file: '/etc/snort/rules/local.rules', code: `alert http $EXTERNAL_NET any -> $HOME_NET 80 (
    msg:"LAB Escáner web por User-Agent";
    flow:established,to_server;
    http_header; content:"User-Agent|3a| ";
    pcre:"/User-Agent\\x3a\\s[^\\r\\n]*(nikto|sqlmap|nuclei|dirbuster|wpscan)/i";
    classtype:web-application-attack;
    sid:1000010; rev:1;
)`, hl: [3, 4, 5], say: 'Laboratorio guiado de Snort. Paso uno: escribir una regla que detecte herramientas de escaneo web por su User Agent. Abro local punto rules. La cabecera dice: alertar sobre HTTP desde redes externas hacia mi red, puerto ochenta. flow established to server garantiza que solo miramos conexiones ya establecidas y en dirección al servidor, lo que evita falsos positivos. http header restringe la búsqueda a las cabeceras. content busca el texto User Agent seguido de dos puntos, escritos en hexadecimal como barra tres a barra. Y la expresión pcre comprueba si el agente contiene nikto, sqlmap, nuclei, dirbuster o wpscan, sin distinguir mayúsculas. Le doy un sid propio y rev uno.', step: [1, 4] },
    { t: 'term', title: 'Validar la sintaxis antes de cargar', note: '-T: probar configuración sin arrancar', prompt: 'analista@ids:~$', lines: `
$ sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -T 2>&1 | tail -4
rule counts
       total rules loaded: 11
               text rules: 11
+Snort successfully validated the configuration (with 0 warnings).`, say: 'Paso dos: validar antes de cargar. Ejecuto snort con la configuración, mi fichero de reglas con guion R, y guion T, que significa test: comprueba todo y termina sin ponerse a escuchar. Con tail miro solo las últimas líneas. Once reglas cargadas y validación correcta sin avisos. Si hubiera un error de sintaxis, aquí me diría la línea exacta. Nunca cargues una regla en producción sin este paso: una regla mal escrita puede impedir que Snort arranque y dejarte sin detección.', step: [2, 4] },
    { t: 'term', title: 'Probar con tráfico de laboratorio', note: 'Generar el caso positivo desde tu propia máquina', prompt: 'analista@ids:~$', lines: `
# Terminal 1: Snort escuchando
$ sudo snort -c /etc/snort/snort.lua -R local.rules -i eth0 -A alert_fast -k none -q
# Terminal 2 (tu propia máquina de laboratorio): simular el User-Agent
$ curl -s -A "Mozilla/5.00 (Nikto/2.5.0)" http://192.168.56.20/ -o /dev/null
# Terminal 1:
!11/26-10:21:05 [**] [1:1000010:1] "LAB Escáner web por User-Agent" [**] [Classification: Web Application Attack] {TCP} 192.168.56.40:51022 -> 192.168.56.20:80
# Caso negativo: navegador normal → sin alerta
$ curl -s -A "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0" http://192.168.56.20/ -o /dev/null`, say: 'Paso tres: probar con tráfico real de laboratorio. En una terminal arranco Snort escuchando en eth cero con alertas rápidas. guion k none evita que descarte paquetes por checksums incorrectos, algo frecuente en máquinas virtuales. En otra terminal, desde mi propia máquina, uso curl con guion A para enviar un User Agent igual al de Nikto, sin ejecutar ningún escáner. La alerta aparece al instante con mi sid. Después hago la prueba negativa: un User Agent de navegador normal no debe generar alerta. Las dos pruebas son obligatorias.', step: [3, 4] },
    { t: 'term', title: 'Medir el ruido durante 24 horas', note: 'Antes de pasar a producción, ¿cuántas alertas genera?', prompt: 'analista@ids:~$', lines: `
$ grep -c "1:1000010" /var/log/snort/alert_fast.txt
37
$ grep "1:1000010" /var/log/snort/alert_fast.txt | awk '{print $NF}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -3
     29 203.0.113.66
      6 198.51.100.9
      2 192.168.56.40
# 2 alertas son de nuestra propia prueba → documentar como esperadas
# Decisión: mantener en modo alerta; enviar al SIEM con severidad media`, say: 'Paso cuatro: medir el ruido. Tras un día, cuento con grep guion c cuántas veces saltó: treinta y siete. Luego saco la IP de origen: con awk tomo el último campo, con cut me quedo con la IP sin el puerto, y con sort, uniq guion c y sort guion rn cuento y ordeno. Veintinueve alertas son de una IP externa, seis de otra, y dos de nuestras propias pruebas, que documentamos. Treinta y siete alertas al día y todas relevantes: la regla está lista para el SIEM con severidad media.', step: [4, 4] }
  ],
  suricata: [
    { t: 'term', title: 'Instalar reglas gestionadas y comprobar que cargan', note: 'suricata-update descarga ET Open y combina tus reglas', prompt: 'analista@ids:~$', lines: `
$ sudo suricata-update list-sources | grep -E "et/open|oisf/trafficid"
Name: et/open      Vendor: Proofpoint   License: MIT
$ sudo suricata-update
+-- Loaded 61873 rules.  -- Disabled 14 rules.  -- Enabled 43021 rules.
+-- Writing rules to /var/lib/suricata/rules/suricata.rules
$ sudo suricata -T -c /etc/suricata/suricata.yaml -v | tail -2
+Configuration provided was successfully loaded. Exiting.
$ sudo systemctl reload suricata`, say: 'Laboratorio guiado de Suricata. Paso uno: reglas gestionadas. suricata update list sources lista las fuentes disponibles; ET Open, de Proofpoint, es la gratuita más usada. Ejecuto suricata update: descarga, combina y escribe más de cuarenta mil reglas activas en un único fichero. Después valido la configuración con guion T y, si todo es correcto, recargo el servicio sin pararlo. Programa este update a diario con cron o un temporizador de systemd.', step: [1, 4] },
    { t: 'term', title: 'Generar tráfico de prueba controlado', note: 'Hay URLs de prueba diseñadas para disparar reglas sin riesgo', prompt: 'alumno@lab:~$', lines: `
# La regla 2100498 (GPL ATTACK_RESPONSE id check returned root) se activa con este texto inofensivo:
$ curl -s http://testmynids.org/uid/index.html
uid=0(root) gid=0(root) groups=0(root)
# En el sensor:
$ sudo tail -1 /var/log/suricata/fast.log
!11/26/2026-10:21:05 [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] {TCP} 18.155.x.x:80 -> 192.168.56.10:41822`, say: 'Paso dos: comprobar que todo funciona con tráfico de prueba controlado. La web testmynids punto org existe precisamente para esto: devuelve un texto inofensivo que imita la salida del comando id de un usuario root. Desde una máquina monitorizada hago un curl a esa URL. En el sensor, miro la última línea de fast punto log con tail guion uno: aparece la alerta dos millones cien mil cuatrocientos noventa y ocho. La cadena completa funciona: captura, motor de reglas y salida.', step: [2, 4] },
    { t: 'term', title: 'Investigar la alerta en eve.json con jq', note: 'Toda la información de contexto está en el JSON', prompt: 'analista@ids:~$', lines: `
$ jq 'select(.alert.signature_id==2100498) | {ts:.timestamp, src:.src_ip, dst:.dest_ip, flow:.flow_id, host:.http.hostname, url:.http.url, status:.http.status}' /var/log/suricata/eve.json | tail -9
{
  "ts": "2026-11-26T10:21:05.114+0100",
  "src": "18.155.x.x", "dst": "192.168.56.10",
  "flow": 1284019380112233,
  "host": "testmynids.org", "url": "/uid/index.html", "status": 200
}
$ jq -c 'select(.flow_id==1284019380112233) | .event_type' /var/log/suricata/eve.json | sort | uniq -c
      1 "alert"
      1 "flow"
      1 "http"`, say: 'Paso tres: investigar en eve punto json. Con jq selecciono los eventos cuyo signature id sea el de la alerta, y construyo un objeto con solo los campos que me interesan: hora, origen, destino, el identificador de flujo, y del bloque http el host, la URL y el código. Ahora pivoto por flow id: con un segundo jq listo todos los eventos de ese mismo flujo. Veo que además de la alerta hay un evento http y un evento flow con los bytes transferidos. El flow id es la llave que une todo lo que Suricata sabe de una conexión.', step: [3, 4] },
    { t: 'code', title: 'Suprimir un falso positivo de forma quirúrgica', note: 'Nunca desactivar la regla entera si puedes acotar', file: '/etc/suricata/threshold.config', code: `# El escáner de vulnerabilidades interno dispara ET SCAN cada lunes:
suppress gen_id 1, sig_id 2002910, track by_src, ip 192.168.56.5
suppress gen_id 1, sig_id 2002911, track by_src, ip 192.168.56.5

# Regla ruidosa: limitar a 1 alerta por origen cada 10 min
threshold gen_id 1, sig_id 2210045, type limit, track by_src, count 1, seconds 600
# Documentado en: wiki/SOC/excepciones#2026-11-26 (aprobado por L2)`, hl: [2, 6], say: 'Paso cuatro: tratar un falso positivo con precisión. El escáner interno de vulnerabilidades dispara reglas de escaneo cada lunes. En lugar de desactivar esas reglas para todos, las suprimo solo cuando el origen es la IP del escáner, con suppress, track by src e ip. Para una regla que genera demasiadas alertas repetidas, uso threshold de tipo limit: como máximo una alerta por origen cada diez minutos. Y documento cada excepción con la fecha y quién la aprobó, porque una supresión mal hecha puede ocultar un ataque real.', step: [4, 4] }
  ],
  splunk: [
    { t: 'splunk', title: 'Paso 1: conocer los datos antes de buscar', note: 'Qué índices y sourcetypes hay, y qué campos trae cada uno', q: '| tstats count where index=* by index sourcetype | sort -count', count: '6 results', range: 'Últimas 24 horas', head: ['index', 'sourcetype', 'count'], rows: [['wineventlog', 'XmlWinEventLog:Security', '2.481.220'], ['sysmon', 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', '1.902.331'], ['proxy', 'squid:access', '611.873'], ['linux', 'linux_secure', '88.102'], ['fw', 'pan:traffic', '3.004.112'], ['cloud', 'aws:cloudtrail', '41.230']], say: 'Laboratorio guiado de Splunk. Paso uno: conocer los datos. Mucha gente empieza a buscar sin saber qué hay. Escribo una barra vertical y tstats, que consulta los índices de forma ultrarrápida, contando eventos por índice y sourcetype. Ordeno de más a menos. Ahora sé que tengo seguridad de Windows, Sysmon, proxy, Linux, firewall y CloudTrail. Después, en cada uno, abriría unos eventos y miraría la barra lateral de campos para saber cómo se llama cada dato.' , step: [1, 4] },
    { t: 'splunk', title: 'Paso 2: password spraying en Windows', note: 'stats + dc() para contar usuarios distintos', q: 'index=wineventlog EventCode=4625 | stats count dc(TargetUserName) as usuarios values(TargetUserName) as lista by IpAddress | where usuarios > 15 | sort -usuarios', count: '1 result', range: 'Últimas 4 horas', head: ['IpAddress', 'count', 'usuarios', 'lista'], rows: [['10.0.10.77', '212', '205', 'a.perez, b.lopez, c.ruiz, …']], hl: [0], say: 'Paso dos: detectar password spraying en Windows. Busco el evento cuatro mil seiscientos veinticinco, inicio de sesión fallido. Con stats cuento fallos, y con dc, distinct count, cuento usuarios distintos, por IP de origen. values me muestra la lista. Con where me quedo con las IPs que han probado más de quince usuarios. Resultado: un equipo interno ha probado doscientos cinco usuarios distintos con apenas un intento cada uno. Ese patrón, muchos usuarios y pocos intentos por usuario, es el spraying desde un equipo ya comprometido.', step: [2, 4] },
    { t: 'splunk', title: 'Paso 3: ¿acertó alguno? (subsearch)', note: 'Buscar éxitos (4624) desde la IP sospechosa', q: 'index=wineventlog EventCode=4624 Logon_Type=3 [ search index=wineventlog EventCode=4625 | stats dc(TargetUserName) as u by IpAddress | where u>15 | fields IpAddress ] | table _time TargetUserName IpAddress host', count: '1 event', range: 'Últimas 4 horas', head: ['_time', 'TargetUserName', 'IpAddress', 'host'], rows: [['10:48:12', 'svc_backup', '10.0.10.77', 'SRV-FICHEROS']], hl: [0], say: 'Paso tres: comprobar si alguna contraseña acertó. Uso una subbúsqueda, entre corchetes: primero se ejecuta la búsqueda interna, que devuelve la IP del spraying, y su resultado se convierte en filtro de la búsqueda externa. Fuera busco el cuatro mil seiscientos veinticuatro, inicio correcto, de tipo tres, que es acceso por red. Aparece la cuenta de servicio de copias entrando en el servidor de ficheros. Las cuentas de servicio suelen tener contraseñas antiguas y no tienen MFA: es la que cayó.', step: [3, 4] },
    { t: 'code', title: 'Paso 4: guardarlo como alerta programada', note: 'Search → Save As → Alert', file: 'savedsearches.conf (resultado de la interfaz)', code: `[SOC - Password spraying interno con éxito]
search = index=wineventlog EventCode=4624 Logon_Type=3 [search index=wineventlog EventCode=4625 earliest=-30m | stats dc(TargetUserName) as u by IpAddress | where u>15 | fields IpAddress]
cron_schedule = */15 * * * *
dispatch.earliest_time = -30m
alert.severity = 5
alert.suppress = 1
alert.suppress.fields = IpAddress
alert.suppress.period = 4h
action.notable = 1          # crea un notable en Enterprise Security
action.webhook.param.url = https://soar.empresa.local/hooks/spraying`, hl: [3, 6, 9], say: 'Paso cuatro: no repitas la búsqueda a mano; conviértela en alerta. En la interfaz: Save As, Alert. Programo la ejecución cada quince minutos sobre los últimos treinta. Severidad cinco, la máxima. La supresión por IP durante cuatro horas evita recibir la misma alerta veinte veces. Y como acciones, crear un notable en Enterprise Security y llamar a un webhook del SOAR para que enriquezca automáticamente. Así una búsqueda manual se convierte en detección permanente.', step: [4, 4] }
  ],
  zabbix: [
    { t: 'term', title: 'Instalar y registrar el agente', note: 'Agente 2 en el servidor a monitorizar', prompt: 'admin@web01:~$', lines: `
$ sudo apt install zabbix-agent2
$ sudo sed -i 's/^Server=.*/Server=192.168.56.50/; s/^ServerActive=.*/ServerActive=192.168.56.50/; s/^Hostname=.*/Hostname=web01/' /etc/zabbix/zabbix_agent2.conf
$ sudo systemctl enable --now zabbix-agent2
# Desde el servidor Zabbix, comprobar que responde:
$ zabbix_get -s 192.168.56.20 -k agent.ping
+1
$ zabbix_get -s 192.168.56.20 -k system.cpu.util
3.418`, say: 'Laboratorio guiado de Zabbix. Paso uno: instalar el agente en el servidor web. Instalo zabbix agent dos. Con sed edito tres líneas del fichero de configuración: Server, la IP del servidor Zabbix que puede consultarle; ServerActive, a quién envía datos por iniciativa propia; y Hostname, que debe coincidir exactamente con el nombre del host en la interfaz web. Activo el servicio. Desde el servidor Zabbix, compruebo con zabbix get: agent ping devuelve uno, está vivo, y el uso de CPU es del tres por ciento.', step: [1, 4] },
    { t: 'bul', title: 'Dar de alta el host y aplicar plantillas', note: 'Data collection → Hosts → Create host', items: ['Host name: **web01** (igual que en el agente)', 'Templates: **Linux by Zabbix agent** + **Apache by HTTP**', 'Host groups: `Servidores web`, `Producción`', 'Interfaces: Agent `192.168.56.20:10050`', 'Tags: `service=tienda`, `owner=sistemas`', 'Comprobar en **Latest data** que llegan valores en 1–2 minutos'], say: 'Paso dos: en la interfaz web voy a Data collection, Hosts, Create host. El nombre debe ser exactamente web cero uno, como en el agente. Añado dos plantillas: Linux by Zabbix agent, que trae cientos de métricas del sistema, y Apache by HTTP. Lo meto en los grupos de servidores web y producción, configuro la interfaz del agente con su IP y el puerto diez mil cincuenta, y pongo etiquetas de servicio y responsable, que luego sirven para enrutar las alertas. Guardo, y en Latest data compruebo que empiezan a llegar valores.', step: [2, 4] },
    { t: 'code', title: 'Crear un trigger con histéresis', note: 'Evitar que la alerta "parpadee"', file: 'Trigger · web01', code: `Name:      Tráfico de salida anómalo en {HOST.NAME} ({ITEM.LASTVALUE1})
Severity:  High
Problem:   avg(/web01/net.if.out["eth0"],10m) > 50M
Recovery:  avg(/web01/net.if.out["eth0"],10m) < 20M     ← histéresis
Tags:      scope=security · mitre=T1048
Manual close: allowed
Description: Posible exfiltración. Comprobar en el SIEM conexiones salientes de web01.`, hl: [3, 4], say: 'Paso tres: crear un trigger útil para seguridad. La expresión de problema calcula la media del tráfico de salida en los últimos diez minutos y salta si supera cincuenta megabits. El truco profesional es la expresión de recuperación: el problema no se cierra hasta que baja de veinte megabits. Eso se llama histéresis y evita que la alerta se abra y se cierre continuamente cuando el valor oscila alrededor del umbral. Le pongo etiquetas de seguridad y una descripción con el primer paso a seguir.', step: [3, 4] },
    { t: 'dash', title: 'Ver el problema y reconocerlo', note: 'Monitoring → Problems → Update (Acknowledge)', app: 'Zabbix · Monitoring → Problems', widgets: [{ k: 'list', t: 'Problems', w: 2, h: 2, items: [['high', '03:14 · Tráfico de salida anómalo en web01 (87 Mbps)'], ['med', '03:15 · web01: CPU > 90 % durante 5 min']] }, { k: 'line', t: 'web01 · net.if.out[eth0] (Mbps)', w: 2, h: 2, data: [4, 5, 4, 6, 5, 61, 85, 87, 86, 22, 5], c: '#ef4444', thr: 50 }, { k: 'list', t: 'Acknowledge', w: 4, h: 1, items: [['low', '03:21 · analista: reconocido, investigando en SIEM (INC-2026-120). Severidad mantenida.']] }], say: 'Paso cuatro: gestionar el problema. En Monitoring, Problems, aparece el tráfico anómalo junto a un pico de CPU a la misma hora: dos señales que se refuerzan. Abro la gráfica: el tráfico subió de cinco a ochenta y siete megabits durante media hora. Pulso Update y lo reconozco con un mensaje: quién lo investiga y el número de caso. Así el resto del equipo sabe que alguien se está encargando, y el historial queda documentado.', step: [4, 4] }
  ]
});

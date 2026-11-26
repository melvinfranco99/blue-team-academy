VIDEOS.push({
  id: 'nmap', n: 3, tool: 'Nmap', icon: '🔦', color: '#10b981', level: 'Principiante',
  title: 'Nmap: escaneo y descubrimiento de red (práctica completa)',
  desc: 'Descubrimiento de hosts, tipos de escaneo, detección de versiones y SO, scripts NSE, salida a ficheros y ndiff para vigilar cambios.',
  scenes: [
    { t: 'title', ch: 'Introducción', icon: '🔦', kick: 'Módulo 3 · Descubrimiento', title: 'Nmap para defensores', sub: 'Inventario de activos, superficie de exposición y detección de cambios.', say: 'Bienvenido al módulo de Nmap. Nmap es el escáner de red más usado del mundo. Los atacantes lo usan para reconocer objetivos, pero para un defensor es igual de valioso: nos permite inventariar qué equipos hay en la red, qué servicios exponen y, sobre todo, detectar cambios que nadie ha autorizado. Antes de empezar, una regla de oro: escanea solo redes propias o con autorización por escrito.' },
    { t: 'ana', icon: '🏢', lab: 'ANALOGÍA', title: 'Nmap es el inventario del conserje', text: 'Recorre el edificio, apunta qué puertas existen, cuáles están abiertas y quién vive detrás. Si mañana aparece una puerta nueva, lo sabrá.', say: 'Piensa en Nmap como un conserje meticuloso que cada noche recorre el edificio y anota qué puertas existen, cuáles están abiertas y quién vive detrás de cada una. Si mañana aparece una puerta nueva que nadie ha autorizado, el conserje lo sabrá al comparar su lista. Esa comparación diaria es uno de los usos defensivos más potentes de Nmap.' },
    { t: 'flow', title: 'Nuestro laboratorio', zones: [{ x: 40, y: 40, w: 1060, h: 450, label: 'Red de laboratorio 192.168.56.0/24', c: '#22d3ee' }], nodes: [{ id: 'k', x: 210, y: 270, label: 'Analista', sub: '.10 · Kali / Ubuntu', icon: '👩‍💻', w: 230, c: '#10b981' }, { id: 'w', x: 820, y: 130, label: 'web01', sub: '.20 · Ubuntu + Apache', icon: '🌐', w: 250 }, { id: 'd', x: 820, y: 270, label: 'dc01', sub: '.30 · Windows Server', icon: '🪟', w: 250, c: '#3b82f6' }, { id: 'm', x: 820, y: 410, label: 'meta2', sub: '.40 · Metasploitable 2', icon: '💀', w: 250, c: '#ef4444' }], edges: [['k', 'w', 'escaneo'], ['k', 'd', 'escaneo'], ['k', 'm', 'escaneo']], say: 'Este es nuestro laboratorio, todo en máquinas virtuales aisladas en la red ciento noventa y dos punto ciento sesenta y ocho punto cincuenta y seis. El analista, desde la punto diez, escaneará tres objetivos: un servidor web Ubuntu con Apache, un controlador de dominio Windows y una máquina Metasploitable, que es deliberadamente vulnerable y perfecta para practicar. Al final de la página de laboratorios tienes la guía para montarlo tú mismo.' },
    { t: 'term', ch: '1. Descubrir hosts', title: 'Paso 1: ¿qué equipos están vivos?', lines: `
$ sudo nmap -sn 192.168.56.0/24
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for 192.168.56.1
Host is up (0.00021s latency).
Nmap scan report for web01 (192.168.56.20)
+Host is up (0.00045s latency).
MAC Address: 08:00:27:3A:11:B2 (Oracle VirtualBox)
Nmap scan report for dc01 (192.168.56.30)
+Host is up (0.00051s latency).
Nmap scan report for meta2 (192.168.56.40)
+Host is up (0.00038s latency).
Nmap scan report for 192.168.56.77
!Host is up (0.00090s latency).   <-- ¿equipo desconocido?
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.11 seconds`, say: 'Paso uno: descubrir qué equipos están encendidos. Usamos nmap guion s n, que hace un barrido de ping sin escanear puertos, sobre toda la red barra veinticuatro. En dos segundos tenemos cinco hosts vivos. Reconocemos web cero uno, dc cero uno y meta dos. Pero hay uno que no está en nuestro inventario: la punto setenta y siete. Un equipo desconocido en la red es siempre una pregunta que responder: ¿es el portátil de un invitado, un dispositivo IoT o algo malicioso?' },
    { t: 'table', ch: '2. Tipos de escaneo', title: 'Tipos de escaneo principales', mono: true, head: ['Opción', 'Nombre', 'Cómo funciona', 'Cuándo usarlo'], rows: [['-sS', 'SYN (half-open)', 'Envía SYN, no completa', 'Por defecto con root, rápido'], ['-sT', 'TCP connect', 'Handshake completo', 'Sin privilegios root'], ['-sU', 'UDP', 'Paquetes UDP', 'DNS, SNMP, NTP'], ['-sV', 'Versiones', 'Habla con el servicio', 'Inventario de software'], ['-O', 'Sistema operativo', 'Huella TCP/IP', 'Identificar SO'], ['-A', 'Agresivo', '-sV -O -sC --traceroute', 'Laboratorio / auditoría'], ['-p- / --top-ports', 'Puertos', 'Todos / los más comunes', 'Cobertura vs velocidad']], say: 'Nmap tiene muchos tipos de escaneo. El más común es guion s S, el escaneo SYN o medio abierto: envía el SYN y, si recibe SYN-ACK, sabe que el puerto está abierto, pero no completa la conexión. Guion s T completa el saludo y no requiere privilegios. Guion s U escanea UDP, más lento pero necesario para DNS o SNMP. Guion s V detecta la versión exacta del software, clave para saber si es vulnerable. Guion O intenta adivinar el sistema operativo. Y guion A lo combina todo. Por defecto Nmap escanea los mil puertos más comunes; con guion p guion escanea los sesenta y cinco mil quinientos treinta y cinco.' },
    { t: 'term', ch: '3. Puertos y versiones', title: 'Paso 2: servicios y versiones de web01', lines: `
$ sudo nmap -sS -sV -p- -T4 192.168.56.20
PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp   open   http     Apache httpd 2.4.52 ((Ubuntu))
443/tcp  open   ssl/http Apache httpd 2.4.52
!3306/tcp open   mysql    MySQL 8.0.36   <-- ¿expuesto?
!8080/tcp open   http     Apache Tomcat 9.0.58 (admin)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 14.62 seconds`, say: 'Paso dos: vamos a fondo con web cero uno. Combinamos escaneo SYN, detección de versiones, todos los puertos con guion p guion y una plantilla de velocidad guion T cuatro. Resultado: SSH, HTTP y HTTPS, que esperábamos. Pero aparecen dos sorpresas. MySQL escuchando en el tres tres cero seis, cuando la base de datos solo debería aceptar conexiones locales. Y un Tomcat en el ocho mil ochenta con su panel de administración. Ambos son hallazgos defensivos reales: amplían la superficie de ataque y hay que cerrarlos o protegerlos.' },
    { t: 'flow', title: 'Los estados de un puerto', nodes: [{ id: 'n', x: 570, y: 70, label: 'Nmap envía SYN', icon: '📤', w: 260 }, { id: 'o', x: 200, y: 300, label: 'open', sub: 'responde SYN-ACK', icon: '🟢', w: 240, c: '#10b981' }, { id: 'c', x: 570, y: 300, label: 'closed', sub: 'responde RST', icon: '🔴', w: 240, c: '#ef4444' }, { id: 'f', x: 940, y: 300, label: 'filtered', sub: 'sin respuesta (firewall)', icon: '🧱', w: 280, c: '#f59e0b' }], edges: [['n', 'o'], ['n', 'c'], ['n', 'f']], say: 'Es importante entender los estados que reporta Nmap. Open significa que el puerto respondió con SYN-ACK: hay un servicio escuchando. Closed significa que respondió con un paquete RST: el equipo existe, pero no hay nada en ese puerto. Y filtered significa que no hubo respuesta, normalmente porque un firewall descarta el paquete. Para un defensor, filtered es buena señal: el firewall está haciendo su trabajo.' },
    { t: 'term', ch: '4. Sistema operativo', title: 'Paso 3: identificar el sistema operativo de dc01', lines: `
$ sudo nmap -O -sV --top-ports 100 192.168.56.30
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: lab.local)
445/tcp  open  microsoft-ds?
!3389/tcp open  ms-wbt-server Microsoft Terminal Services
OS details: Microsoft Windows Server 2019 - 2022
+Network Distance: 1 hop`, say: 'Paso tres: el controlador de dominio. Con guion O, Nmap analiza detalles sutiles de cómo el sistema responde a paquetes TCP e IP para deducir el sistema operativo: en este caso, Windows Server dos mil diecinueve o dos mil veintidós. Los puertos confirman que es un controlador de dominio: DNS en el cincuenta y tres, Kerberos en el ochenta y ocho, LDAP en el trescientos ochenta y nueve. Y ojo con el RDP en el tres tres ocho nueve: en un controlador de dominio debería estar restringido solo a equipos de administración.' },
    { t: 'code', ch: '5. Scripts NSE', title: 'NSE: el motor de scripts de Nmap', file: 'categorías NSE más útiles para defensa', code: `# Más de 600 scripts en /usr/share/nmap/scripts/
# Categorías: auth, default, discovery, safe, vuln, brute, intrusive...

# Scripts por defecto (seguros): equivalen a -sC
nmap -sC 192.168.56.20

# Auditar cifrados TLS débiles
nmap --script ssl-enum-ciphers -p 443 192.168.56.20

# Algoritmos SSH aceptados (¿hay alguno obsoleto?)
nmap --script ssh2-enum-algos -p 22 192.168.56.20

# ¿SMB exige firma? (mitiga ataques relay)
nmap --script smb2-security-mode -p 445 192.168.56.30

# Buscar vulnerabilidades conocidas (solo laboratorio/autorizado)
nmap -sV --script vuln 192.168.56.40`, hl: [8, 14, 17], say: 'Nmap incluye un motor de scripts, el NSE, con más de seiscientos scripts escritos en Lua. Para defensa son oro. El script ssl guion enum guion ciphers revisa si tu servidor web acepta cifrados TLS débiles. El script ssh dos guion enum guion algos revisa si SSH admite algoritmos obsoletos. El smb dos guion security guion mode comprueba si la firma SMB es obligatoria, lo que mitiga los ataques de retransmisión. Y la categoría vuln busca vulnerabilidades conocidas; úsala solo en laboratorio o con autorización, porque algunos scripts son intrusivos.' },
    { t: 'term', title: 'NSE en acción contra Metasploitable', lines: `
$ sudo nmap -sV --script vuln -p 21,445 192.168.56.40
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-vsftpd-backdoor:
!|   VULNERABLE:
!|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2011-2523
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian
| smb-vuln-cve2009-3103: NOT VULNERABLE
+# Acción defensiva: retirar vsftpd 2.3.4, actualizar Samba`, say: 'Veamos NSE en acción contra Metasploitable. El script detecta que el servidor FTP vsftpd dos punto tres punto cuatro contiene una puerta trasera conocida, con el identificador CVE dos mil once guion dos cinco dos tres. Es una versión que fue troyanizada en su día. Como defensores, la acción es clara: retirar inmediatamente ese software y actualizar los servicios antiguos como Samba. En el video de Nessus veremos cómo automatizar este tipo de hallazgos a gran escala.' },
    { t: 'term', ch: '6. Guardar y comparar', title: 'Guardar resultados y detectar cambios con ndiff', lines: `
# -oA guarda en 3 formatos: .nmap (texto), .xml y .gnmap (grep)
$ sudo nmap -sS -sV -oA baseline_2026-11-25 192.168.56.0/24
# Al día siguiente, el mismo escaneo
$ sudo nmap -sS -sV -oA scan_2026-11-26 192.168.56.0/24
$ ndiff baseline_2026-11-25.xml scan_2026-11-26.xml
-Nmap 7.95 scan initiated ...
 web01 (192.168.56.20):
 PORT     STATE  SERVICE VERSION
!+4444/tcp open   krb524?
 dc01 (192.168.56.30):
!+5985/tcp open   http    Microsoft HTTPAPI httpd 2.0 (WinRM)
!+192.168.56.77: Host is up.`, say: 'Este es el uso defensivo estrella. Con guion o A guardamos los resultados en tres formatos, incluido XML. Hoy guardamos una línea base. Mañana repetimos el mismo escaneo. Y con la herramienta ndiff comparamos ambos ficheros. El resultado muestra solo las diferencias, marcadas con un signo más: web cero uno tiene un puerto nuevo, el cuatro cuatro cuatro cuatro, típico de shells inversas de Metasploit. El controlador de dominio ha abierto WinRM. Y hay un host nuevo. Tres alertas que merecen un ticket inmediato.' },
    { t: 'code', title: 'Automatizarlo: escaneo diario con cron', file: '/opt/scans/diario.sh', code: `#!/bin/bash
# Escaneo diario y aviso si hay cambios
RED="192.168.56.0/24"
DIR=/opt/scans; HOY=$(date +%F)
nmap -sS -sV -oX $DIR/scan_$HOY.xml $RED > /dev/null
ULTIMO=$(ls -t $DIR/scan_*.xml | sed -n 2p)
CAMBIOS=$(ndiff $ULTIMO $DIR/scan_$HOY.xml | grep '^[+-]' | grep -v Nmap)
if [ -n "$CAMBIOS" ]; then
  echo "$CAMBIOS" | mail -s "[SOC] Cambios en la red $HOY" soc@empresa.local
fi
# crontab -e  ->  0 6 * * * /opt/scans/diario.sh`, hl: [7, 8, 9], say: 'Y para que esto no dependa de la memoria de nadie, lo automatizamos con un pequeño script de bash. Cada día escanea la red, guarda el XML con la fecha, lo compara con el escaneo anterior usando ndiff y, si hay cambios, envía un correo al SOC. Lo programamos con cron a las seis de la mañana. Con veinte líneas has creado un sistema de detección de cambios en la superficie de exposición. Esto, en una entrevista para un puesto junior, causa muy buena impresión.' },
    { t: 'bul', ch: '7. Detectar a quien te escanea', icon: '🛡️', title: 'El otro lado: ¿cómo detectar un escaneo Nmap?', items: ['IDS (Suricata/Snort): reglas tipo **ET SCAN Nmap**.', 'Firewall: muchas conexiones **bloqueadas** desde una IP a muchos puertos.', 'SIEM: `stats dc(dest_port) by src_ip` → umbral > 100 en 1 min.', 'User-Agent **Nmap Scripting Engine** en logs web.', 'Honeypots/puertos trampa: nadie legítimo los toca.'], say: 'Ahora cambiemos de lado: ¿cómo detecta un defensor que alguien le escanea con Nmap? Primero, los sistemas de detección de intrusos como Suricata traen reglas específicas para escaneos. Segundo, el firewall registra muchas conexiones bloqueadas desde una misma IP a muchos puertos distintos. Tercero, en el SIEM contamos puertos de destino distintos por IP de origen y alertamos si superan, por ejemplo, cien en un minuto. Cuarto, los scripts NSE dejan el User-Agent Nmap Scripting Engine en los logs web. Y por último, los honeypots: puertos trampa que nadie legítimo debería tocar.' },
    { t: 'quiz', ch: 'Repaso', q: 'En un escaneo, un puerto aparece como "filtered". ¿Qué significa?', o: ['Hay un servicio escuchando', 'El puerto responde con RST', 'No hubo respuesta: probablemente un firewall lo bloquea', 'El host está apagado'], a: 2, say: 'Pregunta de repaso. En un escaneo, un puerto aparece como filtered. ¿Qué significa? La respuesta correcta es que no hubo respuesta, probablemente porque un firewall descarta los paquetes. Recuerda: open responde SYN-ACK, closed responde RST y filtered no responde.' },
    { t: 'title', icon: '🎓', kick: 'Siguiente video', title: 'Nessus: gestión de vulnerabilidades', sub: 'De “qué puertos hay” a “qué vulnerabilidades hay y cuál parcheo primero”.', say: 'Fantástico. Ya sabes inventariar una red y vigilar sus cambios. En el próximo video subimos un nivel con Nessus: no solo veremos qué servicios hay, sino qué vulnerabilidades tienen y, lo más importante, cómo priorizar cuál parchear primero.' }
  ]
});

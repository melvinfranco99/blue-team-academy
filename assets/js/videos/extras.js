/* Prácticas adicionales para las lecciones 1–13.
   Se insertan antes de la pregunta de repaso final de cada video. */
(function () {
  const EXTRA = {
    intro: [
      { t: 'dash', ch: 'Práctica: un turno en el SOC', app: 'SIEM · Cola de alertas del turno de mañana', title: 'Práctica: priorizar la cola de alertas', widgets: [{ k: 'stat', t: 'Alertas en cola', v: '47', c: '#f59e0b' }, { k: 'stat', t: 'Críticas', v: '2', c: '#ef4444' }, { k: 'stat', t: 'SLA crítica', v: '15', u: 'min' }, { k: 'stat', t: 'Analistas de turno', v: '3' }, { k: 'list', t: 'Cola (ordenada por severidad × criticidad del activo)', w: 4, h: 2, items: [['crit', 'Ransomware: renombrado masivo en SRV-FICHEROS (activo crítico)'], ['crit', 'Login correcto tras 300 fallos: cuenta de administrador'], ['high', 'PowerShell codificado en PC-CONTA-07'], ['med', 'Escaneo de puertos desde Internet contra la web (bloqueado)'], ['low', 'Usuario bloqueado por 5 fallos de contraseña']] }], say: 'Práctica: un turno en el SOC. Empiezas el turno con cuarenta y siete alertas en cola. No se atienden por orden de llegada, sino por severidad multiplicada por la criticidad del activo. Primero, el posible ransomware en el servidor de ficheros, que es crítico para el negocio. Después, el acceso correcto a una cuenta de administrador tras cientos de fallos. Luego el PowerShell codificado. Un escaneo bloqueado por el firewall es informativo, y un usuario que olvidó su contraseña puede esperar. Saber priorizar es la primera habilidad de un analista.' },
      { t: 'table', title: 'Plantilla de triaje: las 5 preguntas', head: ['Pregunta', 'Ejemplo de respuesta'], rows: [['¿Qué ha pasado?', 'Word lanzó PowerShell codificado en PC-CONTA-07'], ['¿Quién y dónde?', 'Usuaria mlopez, Contabilidad, 10:02'], ['¿Es real?', 'Sí: conexión a IP con mala reputación tras la ejecución'], ['¿Cuál es el impacto?', 'Un equipo; posible robo de credenciales'], ['¿Qué hago ahora?', 'Aislar con EDR, escalar a L2 con evidencias, abrir caso']], hl: [2], say: 'Para cada alerta, responde cinco preguntas. Qué ha pasado, quién y dónde, si es real o un falso positivo, cuál es el impacto y qué haces ahora. Esta plantilla convierte una alerta en una nota clara que cualquier compañero o tu responsable puede entender, y evita que te olvides de pasos. Úsala desde el primer día.' }
    ],
    redes: [
      { t: 'term', ch: 'Práctica: diagnóstico', title: 'Práctica: comandos de red que usarás cada día', prompt: 'analista@soc:~$', lines: `
$ ip -br addr
eth0   UP   10.0.99.5/24
$ ip route
default via 10.0.99.1 dev eth0
$ dig +short tienda.example A
192.0.2.80
$ ss -tunap | grep ESTAB | head -3
tcp ESTAB 0 0 10.0.99.5:52144 10.0.10.20:22   users:(("ssh",pid=2211))
tcp ESTAB 0 0 10.0.99.5:41012 10.0.99.10:9200 users:(("filebeat",pid=901))
$ traceroute -n 192.0.2.80
 1  10.0.99.1  0.4 ms   2  192.0.2.1  3.1 ms   3  192.0.2.80  4.0 ms`, say: 'Práctica: los comandos de red que usarás cada día. ip guion br addr muestra tus interfaces y direcciones de forma breve. ip route, la puerta de enlace. dig resuelve un nombre de dominio. ss muestra las conexiones establecidas y qué proceso las abrió: muy útil para detectar conexiones sospechosas. Y traceroute muestra el camino que siguen los paquetes salto a salto. Practícalos en tu máquina hasta que salgan solos.' },
      { t: 'table', title: 'Puertos que debes reconocer de memoria', mono: true, head: ['Puerto', 'Servicio', '¿Expuesto a Internet?'], rows: [['22', 'SSH', 'Solo vía VPN/bastión'], ['53', 'DNS', 'Solo servidores DNS públicos'], ['80 / 443', 'HTTP / HTTPS', 'Sí, servicios web'], ['445', 'SMB', '❌ Nunca'], ['3389', 'RDP', '❌ Nunca (vía VPN)'], ['3306 / 1433 / 5432', 'MySQL / MSSQL / PostgreSQL', '❌ Nunca'], ['9200', 'Elasticsearch', '❌ Nunca'], ['161', 'SNMP', '❌ Nunca']], hl: [3, 4], say: 'Estos puertos debes reconocerlos de memoria. SSH en el veintidós, DNS en el cincuenta y tres, web en el ochenta y cuatrocientos cuarenta y tres. Y una lista negra: SMB en el cuatrocientos cuarenta y cinco, escritorio remoto en el tres mil trescientos ochenta y nueve, bases de datos y Elasticsearch nunca deben estar expuestos directamente a Internet. Cuando veas uno de ellos abierto al exterior en un escaneo o en Shodan, es un hallazgo prioritario.' }
    ],
    nmap: [
      { t: 'term', ch: 'Práctica: línea base', title: 'Práctica: inventario semanal y detección de cambios', prompt: 'analista@lab:~$', lines: `
# Línea base de tu laboratorio (red propia)
$ sudo nmap -sS -sV -T4 -oX base_lunes.xml 192.168.56.0/24
# Una semana después, mismo escaneo
$ sudo nmap -sS -sV -T4 -oX base_lunes2.xml 192.168.56.0/24
$ ndiff base_lunes.xml base_lunes2.xml
 192.168.56.20 (web01):
 PORT     STATE SERVICE VERSION
!+8888/tcp open  http    SimpleHTTPServer 0.6 (Python 3.12)
!-80/tcp   open  http    Apache httpd 2.4.57
!+80/tcp   open  http    Apache httpd 2.4.52   ← ¿versión anterior?`, say: 'Práctica de defensa con Nmap: la línea base. Escaneas tu propia red y guardas el resultado en XML. Una semana después repites el escaneo y comparas con ndiff. Aparecen dos cambios: un servidor web de Python en el puerto ocho mil ochocientos ochenta y ocho que nadie había autorizado, y Apache con una versión anterior a la que había, lo que sugiere que alguien restauró una copia antigua sin parches. Ambos merecen un ticket. Este inventario periódico es una tarea habitual de los equipos defensivos.' },
      { t: 'code', ch: 'Automatizar', title: 'Automatizar el inventario con cron y avisos', file: '/etc/cron.d/inventario-red', code: `# Cada lunes a las 06:00, escaneo y comparación con la semana anterior
0 6 * * 1  root  /opt/inventario/escaneo.sh

# /opt/inventario/escaneo.sh
#!/bin/bash
HOY=/opt/inventario/$(date +%F).xml
nmap -sS -sV -T4 -oX "$HOY" 192.168.56.0/24 >/dev/null
ANT=$(ls -1 /opt/inventario/*.xml | tail -2 | head -1)
ndiff "$ANT" "$HOY" > /tmp/cambios.txt && exit 0   # sin cambios
mail -s "[Inventario] cambios en la red" soc@empresa.local < /tmp/cambios.txt`, hl: [2, 10], say: 'Lo automatizamos. Una tarea programada ejecuta cada lunes a las seis un script que escanea la red, compara con el escaneo anterior y, solo si hay cambios, envía un correo al equipo del SOC. Recuerda coordinar estos escaneos con el equipo de sistemas y documentarlos, para que no se confundan con un ataque real en el IDS.' }
    ],
    nessus: [
      { t: 'table', ch: 'Práctica: priorizar', title: 'Práctica: prioriza estos hallazgos', head: ['Hallazgo', 'CVSS', 'EPSS', 'KEV', 'Exposición', 'Prioridad'], rows: [['VPN SSL — RCE sin autenticación', '9.8', '0.94', 'Sí', 'Internet', '🔴 P1 (horas)'], ['Exchange on-prem — ProxyShell', '9.8', '0.97', 'Sí', 'Internet', '🔴 P1 (horas)'], ['Impresora — firmware antiguo', '7.5', '0.02', 'No', 'Interna', '🟡 P3'], ['Servidor interno — OpenSSL DoS', '7.5', '0.01', 'No', 'Interna', '🟡 P3'], ['Portátiles — Chrome desactualizado', '8.8', '0.40', 'Sí', 'Usuarios', '🟠 P2 (días)']], hl: [0, 1], say: 'Práctica de priorización. Combinamos cuatro datos: la gravedad CVSS, la probabilidad de explotación EPSS, si está en el catálogo KEV de vulnerabilidades explotadas activamente, y la exposición. La VPN y Exchange expuestos a Internet, en KEV y con EPSS altísimo, son prioridad uno: se corrigen en horas. El navegador desactualizado está en KEV y lo usan todos los usuarios, prioridad dos. La impresora y el servidor interno, con baja probabilidad de explotación, pueden ir al ciclo normal de parches.' },
      { t: 'dash', ch: 'Seguimiento', app: 'Gestión de vulnerabilidades · KPIs', title: 'Medir el programa de vulnerabilidades', widgets: [{ k: 'stat', t: 'Críticas abiertas', v: '12', c: '#ef4444' }, { k: 'stat', t: 'Tiempo medio de corrección', v: '9', u: 'días', c: '#f59e0b' }, { k: 'stat', t: 'Dentro de SLA', v: '86', u: '%', c: '#10b981' }, { k: 'stat', t: 'Cobertura de escaneo', v: '97', u: '%' }, { k: 'line', t: 'Críticas abiertas (últimas 10 semanas)', w: 4, h: 2, data: [48, 44, 41, 39, 30, 26, 22, 18, 15, 12], c: '#10b981' }], say: 'Un programa de vulnerabilidades se mide con pocos indicadores: críticas abiertas, tiempo medio de corrección, porcentaje dentro del acuerdo de servicio y cobertura, es decir, qué porcentaje de activos se escanea. La tendencia descendente de las críticas es lo que querrá ver la dirección. Si la cobertura baja, significa que hay activos que no conoces, y eso es un riesgo en sí mismo.' }
    ],
    snort: [
      { t: 'code', ch: 'Práctica: tuning', title: 'Práctica: afinar una regla ruidosa', file: 'local.rules', code: `# Antes: 4.000 alertas/día por la monitorización interna
alert icmp any any -> $HOME_NET any (msg:"LAB ICMP Ping"; itype:8; sid:1000001; rev:1;)

# Después: excluir el servidor de monitorización y limitar el ritmo
alert icmp !$MONITOR_SERVERS any -> $HOME_NET any (msg:"LAB ICMP Ping (no monitorización)";
    itype:8; detection_filter:track by_src, count 20, seconds 10;
    sid:1000001; rev:2;)`, hl: [5, 6, 7], say: 'Práctica de ajuste. Nuestra regla de ping generaba cuatro mil alertas al día por culpa del servidor de monitorización, que hace ping constantemente. La afinamos: excluimos las IPs de monitorización con una variable negada y añadimos un filtro de detección que solo alerta cuando una misma IP envía más de veinte pings en diez segundos, un patrón de barrido. Incrementamos rev a dos. Así pasamos de miles de alertas inútiles a unas pocas que realmente importan.' },
      { t: 'term', title: 'Probar reglas con un PCAP sin tocar la red', prompt: 'analista@ids:~$', lines: `
$ snort -c /etc/snort/snort.lua -R local.rules -r pruebas/barrido_icmp.pcap -A alert_fast -q
![1:1000001:2] "LAB ICMP Ping (no monitorización)" {ICMP} 192.168.56.40 -> 192.168.56.10
$ snort -c /etc/snort/snort.lua -R local.rules -r pruebas/monitorizacion_normal.pcap -A alert_fast -q
+(sin alertas: la excepción funciona)`, say: 'Siempre probamos los cambios con capturas guardadas, usando guion r en lugar de una interfaz. Con la captura de un barrido, la regla salta. Con la captura del tráfico normal de monitorización, no salta. Tener una pequeña colección de capturas de prueba, positivas y negativas, es la base para mantener reglas de calidad sin romper nada en producción.' }
    ],
    suricata: [
      { t: 'term', ch: 'Práctica: jq', title: 'Práctica: analizar eve.json con jq', prompt: 'analista@ids:~$', lines: `
# Top 5 firmas del día
$ jq -r 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -5
    412 ET SCAN Suspicious inbound to mySQL port 3306
     88 ET POLICY curl User-Agent Outbound
     17 ET DNS Query for .onion proxy domain
      3 ET MALWARE Possible Cobalt Strike beacon
# Detalle de las alertas de malware
$ jq -c 'select(.alert.signature|test("MALWARE")) | {ts:.timestamp, src:.src_ip, dst:.dest_ip, sni:.tls.sni}' eve.json
!{"ts":"2026-11-26T10:21:05","src":"10.0.10.45","dst":"203.0.113.50","sni":"cdn.example"}`, say: 'Práctica con jq sobre el fichero eve punto json. Primero, las cinco firmas más frecuentes del día: el escaneo al puerto de MySQL es ruido de Internet que el firewall ya bloquea, pero las tres alertas de posible baliza de malware son lo importante, aunque sean pocas. Las extraemos en formato compacto con la hora, el origen, el destino y el SNI. El volumen no indica importancia: a menudo lo grave está en las alertas menos frecuentes.' },
      { t: 'code', title: 'Regla Suricata con buffers y umbral', file: 'local.rules', code: `alert dns $HOME_NET any -> any any (msg:"LAB DNS subdominio largo (posible túnel)";
    dns.query; pcre:"/^[a-z0-9]{40,}\\./i";
    threshold:type both, track by_src, count 30, seconds 60;
    classtype:policy-violation; sid:1000301; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LAB PowerShell descargando desde Internet";
    flow:established,to_server; http.user_agent; content:"WindowsPowerShell"; nocase;
    sid:1000302; rev:1; metadata:mitre_technique T1105;)`, hl: [2, 3, 8], say: 'Dos reglas más de defensa. La primera usa el buffer dns punto query de Suricata y una expresión regular para detectar subdominios de cuarenta caracteres o más, y solo alerta si un mismo equipo hace más de treinta en un minuto: el patrón de un túnel DNS. La segunda detecta peticiones HTTP salientes con el agente de usuario de PowerShell, algo poco habitual en usuarios normales y típico de descargas de malware. Los buffers específicos de protocolo hacen las reglas más precisas y rápidas.' }
    ],
    splunk: [
      { t: 'splunk', ch: 'Práctica: Windows', title: 'Práctica: cuentas creadas y añadidas a administradores', q: 'index=wineventlog (EventCode=4720 OR EventCode=4732) | eval accion=if(EventCode=4720,"Cuenta creada","Añadida a grupo") | table _time host SubjectUserName TargetUserName accion | sort _time', count: '3 events', range: 'Últimos 7 días', head: ['_time', 'host', 'SubjectUserName', 'TargetUserName', 'accion'], rows: [['03:14:02', 'DC01', 'svc_backup', 'soporte_tmp', 'Cuenta creada'], ['03:14:09', 'DC01', 'svc_backup', 'soporte_tmp', 'Añadida a grupo'], ['09:30:11', 'DC01', 'jgarcia', 'nuevo.empleado', 'Cuenta creada']], hl: [0, 1], say: 'Práctica con eventos de Windows. El cuatro mil setecientos veinte indica la creación de una cuenta y el cuatro mil setecientos treinta y dos que se añadió un miembro a un grupo local de seguridad, como Administradores. Con eval creamos una columna legible. El resultado destaca un patrón sospechoso: una cuenta de servicio de copias creó una cuenta a las tres de la madrugada y la añadió a un grupo de administradores siete segundos después. Las cuentas de servicio no deberían crear usuarios: es una señal clara de persistencia.' },
      { t: 'splunk', title: 'Práctica: detectar beaconing con estadística', q: 'index=proxy | bin _time span=1m | stats count by _time src dest | stats count as minutos stdev(count) as desv by src dest | where minutos > 50 AND desv < 1 | sort -minutos', count: '2 results', range: 'Últimas 2 horas', head: ['src', 'dest', 'minutos', 'desv'], rows: [['10.0.10.45', '198.51.100.77', '118', '0.12'], ['10.0.10.20', 'update.example.com', '61', '0.48']], hl: [0], say: 'Segunda práctica: beaconing. El malware suele conectar con su servidor a intervalos muy regulares. Agrupamos el tráfico del proxy por minuto, contamos conexiones por origen y destino, y después calculamos en cuántos minutos hubo conexión y la desviación típica. Una conexión presente en casi todos los minutos con desviación casi cero es una máquina, no una persona. El segundo resultado es un actualizador legítimo que se valida y se añade a una lista de excepciones; el primero se investiga.' }
    ],
    zabbix: [
      { t: 'code', ch: 'Práctica: seguridad', title: 'Práctica: Zabbix como sensor de seguridad', file: 'Plantilla "Linux seguridad" · items y triggers', code: `Item:    vfs.file.cksum[/etc/passwd,sha256]       cada 5 min
Trigger: last(/web01/vfs.file.cksum[/etc/passwd,sha256],#1)<>last(...,#2)
         → ALTA: "/etc/passwd ha cambiado en {HOST.NAME}"

Item:    log[/var/log/auth.log,"Failed password",,,skip]
Trigger: count(/web01/log[...],5m)>20  → MEDIA: "Posible fuerza bruta SSH"

Item:    net.if.out[eth0]
Trigger: avg(/web01/net.if.out[eth0],10m)>50M and time()<070000
         → ALTA: "Tráfico de salida anómalo de madrugada"`, hl: [2, 6, 9], say: 'Zabbix también puede actuar como sensor de seguridad. Un item calcula el hash de passwd cada cinco minutos y un trigger alerta si cambia. Otro item lee el log de autenticación y alerta si hay más de veinte fallos en cinco minutos. Y un tercero vigila el tráfico de salida: más de cincuenta megabits de media durante diez minutos de madrugada es un indicio de exfiltración. No sustituye a un SIEM, pero en entornos pequeños aporta detección valiosa con la herramienta que ya tienes.' },
      { t: 'term', title: 'Enviar las alertas de Zabbix al SOC', prompt: 'admin@zabbix:~$', lines: `
# Media type "Webhook" → SIEM / TheHive / Teams
$ zabbix_get -s 10.0.10.20 -k 'vfs.file.cksum[/etc/passwd,sha256]'
9b74c9897bac770ffc029102a200c5de…
# Acción: severidad >= Alta  →  webhook al SOC + correo al responsable del host
+Action "Seguridad → SOC" enabled (conditions: Trigger severity >= High, Tag scope = security)`, say: 'Para que estas alertas lleguen al SOC, configuramos un tipo de medio webhook que envía los problemas al SIEM, a TheHive o a un canal del equipo, y una acción que se dispara con severidad alta o superior y una etiqueta de seguridad. Con zabbix get comprobamos desde el servidor que el item devuelve el valor esperado antes de confiar en el trigger.' }
    ],
    shodan: [
      { t: 'shodan', ch: 'Práctica: tu superficie', title: 'Práctica: vigilar tus certificados y productos', q: 'ssl.cert.subject.cn:"empresa.example" -net:203.0.113.0/24', total: '2', side: [['Top orgs', [['Cloud provider A', '1'], ['Cloud provider B', '1']]]], results: [{ ip: '198.51.100.140', org: 'Cloud provider A', loc: 'Fráncfort, DE', port: '443', banner: 'HTTP/1.1 200 OK\nTitle: Staging - Portal empleados\nSSL: CN=staging.empresa.example', vulns: 'Entorno de pruebas olvidado' }, { ip: '198.51.100.201', org: 'Cloud provider B', loc: 'Dublín, IE', port: '9200', banner: 'HTTP/1.1 200 OK\n{"cluster_name":"logs-marketing"}', vulns: 'Elasticsearch sin autenticación' }], say: 'Práctica de superficie de ataque. Buscamos certificados con el nombre de nuestra empresa, excluyendo nuestros rangos conocidos. Aparecen dos activos fuera de nuestro inventario: un entorno de pruebas olvidado en un proveedor cloud y un Elasticsearch de marketing sin autenticación. Esto es lo que se llama TI en la sombra: servicios creados fuera del control de seguridad. El paso siguiente es identificar al responsable, cerrarlos o protegerlos y añadirlos al inventario.' },
      { t: 'code', title: 'Monitorización continua con alertas de Shodan', file: 'Shodan Monitor · configuración', code: `Red monitorizada:  203.0.113.0/24  (rangos propios)
Disparadores:
  ✔ new_service           Servicio nuevo expuesto
  ✔ open_database         Base de datos expuesta
  ✔ vulnerable            Software con CVE conocido
  ✔ ssl_expired           Certificado caducado
  ✔ iot / industrial_control_system
Notificación: webhook → SIEM  ·  correo → soc@empresa.example`, hl: [3, 4], say: 'En lugar de buscar a mano, configuramos la monitorización de Shodan sobre nuestros rangos propios. Nos avisa cuando aparece un servicio nuevo, una base de datos expuesta, software con vulnerabilidades conocidas o un certificado caducado. Enviamos los avisos al SIEM mediante un webhook. Así nos enteramos de un cambio en nuestra exposición a la vez que los atacantes, y no semanas después.' }
    ],
    maltego: [
      { t: 'flow', ch: 'Práctica: phishing', title: 'Práctica: investigar un dominio de phishing', nodes: [{ id: 'd', x: 570, y: 90, label: 'empresa-pagos.example', sub: 'dominio del correo', icon: '🌐', c: '#ef4444', w: 260 }, { id: 'w', x: 220, y: 240, label: 'WHOIS', sub: 'creado hace 2 días', icon: '📅', s: 1 }, { id: 'ip', x: 570, y: 240, label: '203.0.113.88', sub: 'resolución DNS', icon: '🖥️', s: 1 }, { id: 'mx', x: 920, y: 240, label: 'Certificado TLS', sub: 'Let’s Encrypt, 2 días', icon: '🔒', s: 1 }, { id: 'o1', x: 380, y: 400, label: 'empresa-nominas.example', sub: 'misma IP', icon: '🎣', c: '#ef4444', s: 2 }, { id: 'o2', x: 760, y: 400, label: 'empresa-vpn.example', sub: 'misma IP', icon: '🎣', c: '#ef4444', s: 2 }], edges: [['d', 'w'], ['d', 'ip'], ['d', 'mx'], ['ip', 'o1', 'resolución inversa'], ['ip', 'o2']], say: 'Práctica defensiva con Maltego: investigar un dominio de phishing recibido por un empleado. A partir del dominio, las transformaciones muestran que se registró hace dos días, que tiene un certificado igual de reciente y a qué IP resuelve. Al pivotar sobre esa IP, aparecen dos dominios más que imitan a nuestra empresa: uno de nóminas y otro de VPN. Es una campaña preparada contra nosotros. Bloqueamos los tres dominios antes de que lleguen los siguientes correos y avisamos a la plantilla.' },
      { t: 'table', title: 'Del grafo a la acción', head: ['Hallazgo', 'Acción defensiva'], rows: [['3 dominios de typosquatting', 'Bloqueo en DNS, proxy y pasarela de correo'], ['IP 203.0.113.88', 'Bloqueo en firewall + búsqueda en logs de 30 días'], ['Dominio “empresa-vpn”', 'Alerta específica: posible robo de credenciales VPN'], ['Registrador y patrón de nombres', 'Monitorización de nuevos dominios similares'], ['Campaña dirigida', 'Aviso a la plantilla y reporte al CERT/INCIBE']], say: 'Del grafo pasamos a la acción. Bloqueamos los tres dominios en DNS, proxy y correo. Bloqueamos la IP y la buscamos en los logs de los últimos treinta días para saber si alguien ya visitó esas páginas. Creamos una alerta específica para la falsa VPN. Configuramos la monitorización de nuevos dominios parecidos al nuestro. Y avisamos a la plantilla y al CERT, en España INCIBE CERT, para que la información ayude a otras organizaciones.' }
    ],
    ir: [
      { t: 'dash', ch: 'Simulacro', app: 'Ejercicio de mesa (tabletop) · Ransomware', title: 'Práctica: ejercicio de mesa (tabletop)', widgets: [{ k: 'list', t: 'Inyecciones del ejercicio (cada 10 min)', w: 2, h: 3, items: [['med', '09:00 · El EDR alerta de cifrado en SRV-FICHEROS'], ['high', '09:10 · Varios usuarios no pueden abrir documentos'], ['high', '09:20 · Aparece nota de rescate; un periodista llama'], ['crit', '09:30 · El atacante afirma haber robado datos de clientes'], ['crit', '09:40 · Las copias de seguridad también están cifradas']] }, { k: 'list', t: 'Preguntas para el equipo', w: 2, h: 3, items: [['low', '¿Quién declara el incidente y activa el plan?'], ['low', '¿Qué aislamos primero y quién lo autoriza?'], ['med', '¿Quién habla con la prensa?'], ['high', '¿Hay que notificar a la AEPD en 72 h?'], ['crit', '¿Tenemos copias inmutables u offline?']] }], say: 'Práctica de respuesta: el ejercicio de mesa, o tabletop. El equipo se reúne y un moderador va introduciendo novedades cada diez minutos: alertas, usuarios afectados, una llamada de la prensa, la amenaza de publicar datos, copias cifradas. Ante cada una, el equipo debe responder: quién decide, qué se aísla, quién comunica, si hay que notificar a la autoridad de protección de datos en setenta y dos horas, y si existen copias inmutables. Estos ejercicios revelan los huecos del plan antes de un incidente real.' },
      { t: 'code', title: 'Plantilla de informe post-incidente', file: 'INC-2026-112_postmortem.md', code: `# Resumen ejecutivo (5 líneas, sin jerga)
# Cronología (UTC): detección → contención → erradicación → recuperación
# Causa raíz: macro en adjunto + usuarios con permisos de admin local
# Impacto: 2 equipos, 380 MB enviados, sin datos personales confirmados
# Qué funcionó: EDR alertó en 2 min; aislamiento en 9 min
# Qué falló: macros permitidas desde Internet; sin regla Office→PowerShell
# Acciones (responsable · fecha):
#   1. Bloquear macros de Internet por GPO      · Sistemas · 05/12
#   2. Regla Sigma Office→shell en el SIEM       · Detección · 01/12
#   3. Retirar admin local a usuarios            · Sistemas · 15/12`, hl: [3, 6, 8], say: 'Todo incidente termina con un informe de lecciones aprendidas, sin buscar culpables. Un resumen ejecutivo sin jerga, la cronología, la causa raíz, el impacto, qué funcionó, qué falló y, lo más importante, acciones concretas con responsable y fecha. Si las acciones no se cumplen, el mismo incidente volverá a ocurrir. Este informe es también lo que más valoran los responsables cuando evalúan a un analista senior.' }
    ],
    hunting: [
      { t: 'splunk', ch: 'Práctica: stacking', title: 'Práctica: stacking de procesos raros', q: 'index=sysmon EventCode=1 | stats count dc(host) as equipos by Image | where equipos <= 2 | sort count', count: '4 results', range: 'Últimos 30 días', head: ['Image', 'count', 'equipos'], rows: [['C:\\Users\\Public\\svch0st.exe', '3', '1'], ['C:\\ProgramData\\upd\\rclone.exe', '5', '1'], ['C:\\Tools\\procexp64.exe', '7', '2'], ['C:\\Program Files\\Herramienta\\x.exe', '9', '2']], hl: [0, 1], say: 'Práctica de hunting por stacking, o apilamiento. La idea: lo malicioso suele ser raro. Contamos cada ejecutable y en cuántos equipos aparece, y nos quedamos con los que solo aparecen en uno o dos. Arriba de la lista salta un svch zero st, con un cero en lugar de la o, imitando a un proceso de Windows, en una carpeta pública. Y rclone, una herramienta legítima de sincronización muy usada para exfiltrar datos a la nube. Ambos se investigan; las herramientas administrativas conocidas se documentan y se descartan.' },
      { t: 'code', title: 'Documentar la caza: hipótesis → resultado', file: 'hunt-2026-11-rclone.md', code: `Hipótesis:  Un atacante usa herramientas de sincronización (rclone, MEGAsync)
            para exfiltrar datos antes de cifrar (T1567.002).
Datos:      Sysmon 1 y 3, proxy, 30 días.
Consultas:  stacking de Image; conexiones a *.mega.nz, *.dropboxapi.com
Resultado:  1 equipo (PC-ADMIN-03) ejecutó rclone con config cifrada.
            Escalado a IR: INC-2026-118.
Detección nueva: Sigma "rclone con parámetros de copia a remoto" (rev 1)
Lecciones:  falta log de proxy en sede Valencia → ticket a Redes.`, hl: [1, 5, 7], say: 'Toda caza se documenta: la hipótesis, los datos usados, las consultas, el resultado, la detección nueva que nace de ella y las lecciones, como una fuente de logs que faltaba. Aunque una caza no encuentre nada, aporta valor: confirma que no hay actividad, revela huecos de visibilidad y deja una regla automática para el futuro. Así el hunting mejora el SOC de forma continua.' }
    ],
    ia: [
      { t: 'chat', ch: 'Práctica: regla con IA', app: 'Claude · Ingeniería de detección', bot: 'CLAUDE', title: 'Práctica: pedir una regla Sigma y validarla', msgs: [['u', 'Escribe una regla Sigma que detecte rclone ejecutado con "copy" o "sync" hacia un remoto, para process_creation en Windows. Incluye falsos positivos y nivel.'], ['a', 'title: Rclone copiando datos a un remoto\nlogsource: {product: windows, category: process_creation}\ndetection:\n  sel_img: {Image|endswith: \\rclone.exe}\n  sel_ren: {OriginalFileName: rclone.exe}\n  sel_cmd: {CommandLine|contains: [" copy ", " sync "]}\n  condition: (sel_img or sel_ren) and sel_cmd\nfalsepositives: [Copias legítimas del equipo de sistemas]\nlevel: high\n\nNota: incluyo OriginalFileName para detectarlo aunque lo renombren. Valídala con sigma check y pruébala con datos de tu laboratorio antes de desplegar.']], say: 'Práctica de IA aplicada a la detección. Pedimos a Claude una regla Sigma para detectar rclone copiando datos a un remoto, con falsos positivos y nivel. La respuesta incluye un detalle profesional: comprobar también el nombre original del fichero en sus metadatos, para detectar la herramienta aunque el atacante la renombre. Y nos recuerda lo esencial: la IA propone, pero tú validas con sigma check y pruebas con datos reales antes de desplegar.' },
      { t: 'bul', title: 'Checklist para usar IA en el SOC con seguridad', items: ['No pegues **secretos ni datos personales** innecesarios: anonimiza', 'Usa herramientas **aprobadas** por tu empresa (contrato y retención de datos)', 'Trata los logs como **datos**, nunca como instrucciones (prompt injection)', '**Verifica** cada comando, consulta o regla antes de ejecutarla', 'Registra qué ayudó la IA en el caso: trazabilidad', 'La decisión final y la responsabilidad son **humanas**'], say: 'Cierra esta práctica con un checklist. No pegues secretos ni datos personales innecesarios, anonimiza. Usa solo herramientas aprobadas por tu organización. Trata los logs como datos, nunca como instrucciones, para evitar la inyección de prompts. Verifica cada comando o regla antes de ejecutarla. Registra en el caso cómo ayudó la IA. Y recuerda que la decisión final y la responsabilidad siempre son humanas.' }
    ]
  };
  (window.VIDEOS || []).forEach(v => {
    const add = EXTRA[v.id]; if (!add) return;
    let i = -1; v.scenes.forEach((s, k) => { if (s.t === 'quiz') i = k; });
    if (i < 0) i = v.scenes.length - 1;
    v.scenes.splice(i, 0, ...add);
  });
})();

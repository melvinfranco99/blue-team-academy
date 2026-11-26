VIDEOS.push({
  id: 'suricata', n: 6, tool: 'Suricata', icon: '🦦', color: '#f97316', level: 'Intermedio',
  title: 'Suricata: IDS/IPS moderno, eve.json y análisis con jq',
  desc: 'Instalación, suricata.yaml, suricata-update con ET Open, prueba con testmynids.org, eve.json, jq, reglas propias y modo IPS.',
  scenes: [
    { t: 'title', ch: 'Introducción', icon: '🦦', kick: 'Módulo 6 · Detección en red', title: 'Suricata: IDS/IPS de nueva generación', sub: 'Multihilo, protocolos de aplicación y logs JSON listos para tu SIEM.', say: 'Bienvenido al módulo de Suricata. Suricata es un motor de detección y prevención de intrusiones de código abierto, desarrollado por la fundación OISF. Es compatible con la mayoría de reglas de Snort, pero aporta tres ventajas: es multihilo, por lo que aprovecha todos los núcleos del procesador; entiende muchos protocolos de aplicación de forma nativa; y genera logs en formato JSON que cualquier SIEM puede ingerir directamente.' },
    { t: 'table', title: 'Snort vs Suricata', head: ['Aspecto', 'Snort 3', 'Suricata'], rows: [['Hilos', 'Multihilo (desde v3)', 'Multihilo nativo'], ['Configuración', 'Lua (snort.lua)', 'YAML (suricata.yaml)'], ['Salida principal', 'alert_fast, JSON, unified2', 'eve.json (alertas + metadatos)'], ['Metadatos', 'Mediante plugins', 'HTTP, DNS, TLS, flujos, ficheros…'], ['Extracción de ficheros', 'Sí (file inspector)', 'Sí, con hash'], ['Reglas', 'Talos, ET', 'ET Open/Pro, mayoría de Snort'], ['Plataformas', 'Cisco, pfSense…', 'Security Onion, pfSense, OPNsense']], say: 'Comparémoslos rápidamente. Ambos son hoy multihilo, aunque Suricata lo es desde su origen. Snort tres se configura en Lua y Suricata en YAML. La gran diferencia práctica está en la salida: el fichero eve punto json de Suricata no solo contiene alertas, sino metadatos de todo el tráfico: peticiones HTTP, consultas DNS, certificados TLS, flujos y ficheros. Esto convierte a Suricata en una fuente de visibilidad de red enorme. Por eso es el motor que integran plataformas como Security Onion u OPNsense.' },
    { t: 'term', ch: 'Instalación', title: 'Instalación en Ubuntu', prompt: 'analista@ids:~$', lines: `
$ sudo add-apt-repository ppa:oisf/suricata-stable -y
$ sudo apt update && sudo apt install suricata jq -y
$ suricata --build-info | head -2
This is Suricata version 7.0.x RELEASE
# Ver la interfaz y su red
$ ip -br addr show eth0
eth0  UP  192.168.56.10/24
$ sudo systemctl enable suricata`, say: 'Instalamos Suricata en Ubuntu desde el repositorio oficial de la OISF, junto con jq, una herramienta para procesar JSON que usaremos mucho. Comprobamos la versión con suricata guion guion build guion info. Y anotamos el nombre de nuestra interfaz y nuestra red, porque los necesitamos para la configuración.' },
    { t: 'code', ch: 'Configuración', title: 'Lo esencial de /etc/suricata/suricata.yaml', file: '/etc/suricata/suricata.yaml', code: `vars:
  address-groups:
    HOME_NET: "[192.168.56.0/24,10.0.0.0/8]"   # tus redes
    EXTERNAL_NET: "!$HOME_NET"

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules          # generado por suricata-update
  - /etc/suricata/rules/local.rules

af-packet:
  - interface: eth0         # interfaz de captura
    cluster-id: 99
    cluster-type: cluster_flow

community-id: true          # ID común para correlar con Zeek/SIEM`, hl: [3, 12, 16], say: 'Estas son las partes esenciales del fichero suricata punto yaml. En vars definimos HOME NET con nuestras redes internas, y EXTERNAL NET como todo lo demás. En rule files indicamos los ficheros de reglas: suricata punto rules, que generará la herramienta de actualización, y nuestro fichero local. En af packet indicamos la interfaz de captura. Y activamos community id, un identificador estándar de flujo que permite correlacionar los eventos de Suricata con otras herramientas como Zeek en el SIEM.' },
    { t: 'term', title: 'Descargar reglas ET Open y validar', prompt: 'analista@ids:~$', lines: `
$ sudo suricata-update
-- Fetching https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz
+-- Loaded 48912 rules.
+-- Enabled 36230 rules.
-- Writing rules to /var/lib/suricata/rules/suricata.rules
# Validar la configuración antes de arrancar
$ sudo suricata -T -c /etc/suricata/suricata.yaml -v
+Notice: suricata: Configuration provided was successfully loaded. Exiting.
$ sudo systemctl restart suricata
$ sudo tail -f /var/log/suricata/suricata.log
Info: unix-manager: unix socket '/var/run/suricata/suricata-command.socket'
+Notice: threads: Threads created -> W: 4 FM: 1 FR: 1   Engine started.`, say: 'Ahora descargamos las reglas. El comando suricata guion update descarga por defecto el conjunto Emerging Threats Open, en este caso casi cuarenta y nueve mil reglas, de las cuales unas treinta y seis mil quedan activadas. Antes de arrancar, siempre validamos con suricata guion T: si hay un error en el YAML o en una regla, lo veremos aquí y no en producción. Reiniciamos el servicio y en el log vemos que el motor ha arrancado con cuatro hilos de trabajo.' },
    { t: 'term', ch: 'Primera alerta', title: 'La prueba clásica: testmynids.org', prompt: 'analista@ids:~$', lines: `
$ curl http://testmynids.org/uid/index.html
uid=0(root) gid=0(root) groups=0(root)
$ sudo tail -n 1 /var/log/suricata/fast.log
!11/26/2026-10:45:12.338 [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 18.155.x.x:80 -> 192.168.56.10:53212`, say: 'Hagamos la prueba clásica para verificar que todo funciona. La web testmynids punto org devuelve un texto que imita la salida del comando id de Linux ejecutado como root. Es lo que vería un atacante tras explotar un servidor. Hacemos curl a esa URL y, en el fichero fast punto log, aparece inmediatamente la alerta GPL ATTACK RESPONSE id check returned root, con el sid dos millones cien mil cuatrocientos noventa y ocho. Nuestro IDS está vivo.' },
    { t: 'code', ch: 'eve.json', title: 'El mismo evento en eve.json', file: '/var/log/suricata/eve.json (formateado)', code: `{
  "timestamp": "2026-11-26T10:45:12.338+0100",
  "event_type": "alert",
  "src_ip": "18.155.x.x",  "src_port": 80,
  "dest_ip": "192.168.56.10", "dest_port": 53212,
  "proto": "TCP",
  "community_id": "1:3rYp0mTqk2...=",
  "alert": {
    "action": "allowed",
    "signature_id": 2100498,
    "signature": "GPL ATTACK_RESPONSE id check returned root",
    "category": "Potentially Bad Traffic",
    "severity": 2
  },
  "http": { "hostname": "testmynids.org", "url": "/uid/index.html",
            "http_user_agent": "curl/8.5.0", "status": 200 }
}`, hl: [3, 10, 11, 16], say: 'Y aquí está la magia de Suricata. El mismo evento en eve punto json contiene muchísima más información: el tipo de evento, las IPs y puertos, el community id, los detalles de la alerta con su firma y severidad y, además, el contexto HTTP completo: el dominio, la URL, el User-Agent y el código de respuesta. Todo en un formato estructurado que el SIEM puede indexar campo a campo sin necesidad de expresiones regulares.' },
    { t: 'term', ch: 'Análisis con jq', title: 'Analizar eve.json con jq', prompt: 'analista@ids:~$', lines: `
# Tipos de eventos registrados
$ jq -r '.event_type' /var/log/suricata/eve.json | sort | uniq -c | sort -rn
  48211 flow
  12034 dns
   6120 tls
   2210 http
!    37 alert
# Top firmas de alerta
$ jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn | head -4
!    14 ET SCAN Possible Nmap User-Agent Observed
!     9 ET POLICY SSH session in progress on Unusual Port
!     6 ET INFO Observed DNS Query to .top TLD
      1 GPL ATTACK_RESPONSE id check returned root
# Dominios TLS (SNI) visitados por un host sospechoso
$ jq -r 'select(.event_type=="tls" and .src_ip=="192.168.56.23") | .tls.sni' eve.json | sort -u
update.microsoft.com
!xk2p9-cdn.top`, say: 'Con jq podemos hacer análisis potentes desde la terminal. Primero contamos los tipos de evento: casi cincuenta mil flujos, doce mil consultas DNS, seis mil sesiones TLS y treinta y siete alertas. Después seleccionamos solo las alertas y contamos por firma: catorce detecciones del User-Agent de Nmap, sesiones SSH en puertos inusuales y consultas DNS a dominios punto top, muy usados en campañas maliciosas. Por último, listamos los dominios TLS visitados por un equipo sospechoso, y aparece uno con nombre aleatorio en punto top. Tenemos un hilo del que tirar.' },
    { t: 'alerts', ch: 'Triaje de alertas', win: 'EveBox / Kibana · Alertas Suricata (últimas 24h)', title: 'Triaje: ¿qué alerta miro primero?', items: [{ sv: 'crit', ts: '10:52:03', msg: 'ET MALWARE Possible Cobalt Strike Beacon Observed', ip: '192.168.56.23 → 203.0.113.50' }, { sv: 'high', ts: '10:47:19', msg: 'ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)', ip: '198.51.100.7 → 192.168.56.20' }, { sv: 'high', ts: '10:45:12', msg: 'GPL ATTACK_RESPONSE id check returned root', ip: '18.155.x.x → 192.168.56.10' }, { sv: 'med', ts: '10:31:40', msg: 'ET SCAN Possible Nmap User-Agent Observed', ip: '192.168.56.66 → 192.168.56.20' }, { sv: 'low', ts: '10:02:15', msg: 'ET INFO Observed DNS Query to .top TLD', ip: '192.168.56.23 → 192.168.56.1' }], say: 'En una consola de alertas como EveBox o Kibana, el analista ve algo así. ¿Por dónde empezar? Por la crítica: un posible beacon de Cobalt Strike desde un equipo interno hacia una IP externa. Eso sugiere un equipo comprometido comunicándose con su servidor de mando y control. Fíjate en que la última alerta, de baja severidad, la consulta DNS a punto top, viene del mismo equipo, el punto veintitrés. Correlacionar alertas pequeñas con una grande es exactamente lo que diferencia a un buen analista.' },
    { t: 'code', ch: 'Reglas propias', title: 'Reglas propias con buffers de Suricata', file: '/etc/suricata/rules/local.rules', code: `# Consulta DNS a dominio de la lista negra interna
alert dns $HOME_NET any -> any any (msg:"LAB DNS a dominio malicioso conocido";
  dns.query; content:"xk2p9-cdn.top"; nocase; endswith;
  sid:1100001; rev:1;)

# Certificado TLS autofirmado hacia Internet (posible C2)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"LAB TLS con SNI en TLD sospechoso";
  tls.sni; pcre:"/\\.(top|xyz|zip|click)$/";
  sid:1100002; rev:1;)

# Petición HTTP con PowerShell como User-Agent (descarga de payload)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LAB PowerShell descargando por HTTP";
  http.user_agent; content:"WindowsPowerShell"; nocase;
  sid:1100003; rev:1; classtype:trojan-activity;)`, hl: [3, 8, 13], say: 'Las reglas propias en Suricata usan buffers con nombre, muy legibles. La primera usa dns punto query para alertar si alguien consulta el dominio sospechoso que encontramos. La segunda usa tls punto sni con una expresión regular para dominios en extensiones abusadas como punto top, punto xyz o punto zip. La tercera usa http punto user agent para detectar PowerShell descargando ficheros por HTTP, algo muy típico en la primera fase de una infección. Después de editar, ejecuta suricata guion T y recarga las reglas.' },
    { t: 'term', ch: 'Modo IPS', title: 'Pasar a modo IPS (bloqueo) con NFQUEUE', prompt: 'root@gw:~#', lines: `
# Cambiar la acción de una regla fiable de alert a drop
$ sed -i 's/^alert dns \\$HOME_NET any -> any any (msg:"LAB DNS a dominio/drop dns $HOME_NET any -> any any (msg:"LAB DNS a dominio/' /etc/suricata/rules/local.rules
# Enviar el tráfico reenviado a Suricata
$ iptables -I FORWARD -j NFQUEUE --queue-num 0
$ suricata -c /etc/suricata/suricata.yaml -q 0 -D
# Desde un cliente interno:
$ nslookup xk2p9-cdn.top
!;; connection timed out; no servers could be reached
$ jq -c 'select(.alert.action=="blocked") | {ts:.timestamp, sig:.alert.signature}' /var/log/suricata/eve.json
!{"ts":"2026-11-26T11:02:44","sig":"LAB DNS a dominio malicioso conocido"}`, say: 'Cuando una regla es muy fiable, podemos pasar a modo prevención. En un equipo que actúa como pasarela, cambiamos la acción de alert a drop, redirigimos el tráfico reenviado a una cola NFQUEUE con iptables y arrancamos Suricata leyendo de esa cola con guion q cero. Ahora, cuando un cliente intenta resolver el dominio malicioso, la consulta se descarta y en eve punto json la acción aparece como blocked. Recuerda: solo reglas muy afinadas pasan a drop.' },
    { t: 'flow', ch: 'Integración', title: 'Integrar Suricata con el SIEM', nodes: [{ id: 's', x: 150, y: 250, label: 'Suricata', sub: 'eve.json', icon: '🦦', w: 200, c: '#f97316' }, { id: 'f', x: 450, y: 130, label: 'Filebeat / Elastic Agent', icon: '🚚', w: 280 }, { id: 'u', x: 450, y: 370, label: 'Splunk UF', sub: 'TA-suricata', icon: '🚚', w: 280 }, { id: 'e', x: 830, y: 130, label: 'Elastic / Security Onion', icon: '🔎', w: 300, c: '#a78bfa' }, { id: 'sp', x: 830, y: 370, label: 'Splunk', sub: 'index=ids', icon: '🧠', w: 300, c: '#10b981' }], edges: [['s', 'f'], ['s', 'u'], ['f', 'e'], ['u', 'sp']], say: 'Por último, Suricata brilla cuando se integra con el SIEM. Con Filebeat o Elastic Agent, usando el módulo de Suricata, enviamos eve punto json a Elastic o a Security Onion, que ya trae paneles preparados. Con el Universal Forwarder de Splunk y su add-on, lo enviamos a un índice de Splunk. A partir de ahí, las alertas de red se cruzan con los logs de los equipos, del directorio activo y del firewall. Precisamente eso es lo que haremos en el siguiente video.' },
    { t: 'quiz', ch: 'Repaso', q: '¿Qué ventaja principal aporta eve.json frente a un log de alertas simple?', o: ['Ocupa menos espacio', 'Incluye metadatos estructurados (HTTP, DNS, TLS, flujos) en JSON', 'Bloquea ataques automáticamente', 'Solo funciona con Splunk'], a: 1, say: 'Repaso. ¿Qué ventaja principal aporta eve punto json? Incluye metadatos estructurados en JSON, no solo de alertas sino de HTTP, DNS, TLS y flujos, lo que permite investigar y correlacionar en el SIEM sin depender de expresiones regulares.' },
    { t: 'title', icon: '🎓', kick: 'Siguiente video', title: 'Splunk: el cerebro del SOC', sub: 'Ingesta de logs, lenguaje SPL, detección de fuerza bruta, dashboards y alertas.', say: 'Muy bien. Ya tenemos ojos en la red. En el siguiente video montamos el cerebro: Splunk, el SIEM. Aprenderemos el lenguaje SPL desde cero y construiremos detecciones, paneles y alertas reales.' }
  ]
});

VIDEOS.push({
  id: 'snort', n: 5, tool: 'Snort 3', icon: '🐷', color: '#ef4444', level: 'Intermedio',
  title: 'Snort: sistema de detección de intrusos (IDS) y escritura de reglas',
  desc: 'IDS vs IPS, arquitectura de Snort 3, anatomía de una regla, reglas propias para ICMP, escaneos, fuerza bruta SSH y web, y pruebas.',
  scenes: [
    { t: 'title', ch: 'Introducción', icon: '🐷', kick: 'Módulo 5 · Detección en red', title: 'Snort: tu primer IDS', sub: 'Inspeccionar cada paquete y alertar cuando coincide con un patrón de ataque.', say: 'Bienvenido al módulo de Snort, el sistema de detección de intrusos de código abierto más veterano y conocido, hoy mantenido por Cisco Talos. Un IDS inspecciona el tráfico de red y genera una alerta cuando un paquete coincide con un patrón de ataque. En este video entenderemos cómo funciona y, sobre todo, aprenderemos a escribir nuestras propias reglas y a probarlas.' },
    { t: 'cmp', title: 'IDS vs IPS', l: { t: '📹 IDS (detección)', c: '#3b82f6', items: ['Recibe una **copia** del tráfico (SPAN/TAP)', 'Solo alerta', 'Si falla, la red sigue funcionando', 'Ideal para empezar sin riesgo'] }, r: { t: '🚧 IPS (prevención)', c: '#ef4444', items: ['Está **en línea**: el tráfico pasa a través', 'Puede **bloquear** paquetes (acción drop)', 'Un falso positivo corta servicio', 'Requiere reglas muy afinadas'] }, say: 'Primero, una distinción fundamental. Un IDS recibe una copia del tráfico, por ejemplo desde un puerto espejo del switch, y solo alerta: es como una cámara de seguridad. Un IPS está en línea, el tráfico pasa a través de él, y puede bloquear paquetes: es como un guardia en la puerta. El IPS protege más, pero un falso positivo puede cortar un servicio legítimo. Por eso se suele empezar en modo IDS, afinar las reglas y, después, pasar las más fiables a modo bloqueo.' },
    { t: 'ana', icon: '🛂', title: 'Una regla es una orden de búsqueda', text: '“Si ves a alguien (protocolo) que viene de fuera (origen) hacia el banco (destino) con un pasamontañas (contenido), da la alarma (acción) y apunta este código (sid)”.', say: 'Una regla de Snort se parece a una orden de búsqueda que le das a un guardia. Si ves a alguien que llega por la carretera principal, que viene de fuera, que se dirige al banco y que lleva un pasamontañas, da la alarma y apunta el código de caso mil uno. El protocolo, el origen, el destino, el contenido sospechoso, la acción y un identificador único: esas son exactamente las piezas de una regla.' },
    { t: 'flow', ch: 'Arquitectura', title: 'Cómo procesa Snort cada paquete', nodes: [{ id: 'a', x: 120, y: 250, label: 'Captura', sub: 'DAQ (afpacket)', icon: '📥', w: 190 }, { id: 'b', x: 340, y: 250, label: 'Decoder', sub: 'Eth/IP/TCP', icon: '🧩', w: 180 }, { id: 'c', x: 560, y: 250, label: 'Inspectores', sub: 'http, stream, dns', icon: '🔬', w: 200, c: '#a78bfa' }, { id: 'd', x: 790, y: 250, label: 'Motor de reglas', sub: 'detección', icon: '⚙️', w: 210, c: '#f59e0b' }, { id: 'e', x: 1020, y: 140, label: 'Alerta', sub: 'alert_fast / json', icon: '🚨', w: 190, c: '#ef4444' }, { id: 'f', x: 1020, y: 360, label: 'Pasa', sub: 'sin coincidencia', icon: '➡️', w: 190, c: '#10b981' }], edges: [['a', 'b'], ['b', 'c'], ['c', 'd'], ['d', 'e', 'match'], ['d', 'f']], say: 'Así procesa Snort cada paquete. Primero, la capa de adquisición, llamada DAQ, captura el paquete de la interfaz. El decodificador entiende sus cabeceras Ethernet, IP y TCP. Después, los inspectores reconstruyen el contexto: reensamblan flujos TCP, entienden peticiones HTTP o consultas DNS. Con todo normalizado, el motor de reglas compara el tráfico con miles de firmas. Si hay coincidencia, se genera una alerta; si no, el paquete sigue su camino.' },
    { t: 'term', ch: 'Instalación', title: 'Instalar y verificar Snort 3', prompt: 'analista@ids:~$', lines: `
# Debian/Ubuntu (o compilar desde github.com/snort3/snort3)
$ sudo apt install snort3   # disponible en distros recientes
$ snort -V
   ,,_     -*> Snort++ <*-
  o"  )~   Version 3.x
   ''''    By Martin Roesch & The Snort Team
# Poner la interfaz en modo promiscuo
$ sudo ip link set eth0 promisc on
# Validar la configuración (Lua)
$ sudo snort -c /etc/snort/snort.lua -T
+Snort successfully validated the configuration (with 0 warnings).`, say: 'Para instalar Snort tres, en distribuciones recientes puedes usar el gestor de paquetes, o compilarlo desde su repositorio oficial. Comprobamos la versión con snort guion V y vemos el famoso cerdito en arte ASCII. Ponemos la interfaz en modo promiscuo, para que capture todo el tráfico y no solo el dirigido a ella. Y validamos la configuración con guion T. Snort tres usa ficheros de configuración en lenguaje Lua, lo que lo hace más flexible que la versión dos. La ruta exacta puede variar según cómo lo instales.' },
    { t: 'code', ch: 'Anatomía de una regla', title: 'Anatomía de una regla', file: 'local.rules', code: `# ACCIÓN PROTO  ORIGEN       PUERTO -> DESTINO   PUERTO  ( OPCIONES )
alert   icmp   any          any    -> $HOME_NET any     (
    msg:"LAB ICMP Ping hacia la red interna";   # texto de la alerta
    itype:8;                                    # tipo 8 = echo request
    sid:1000001;                                # ID único (>=1000000 propias)
    rev:1;                                      # versión de la regla
    classtype:misc-activity;                    # categoría
)`, hl: [2, 5], say: 'Veamos la anatomía de una regla. Tiene una cabecera y unas opciones. La cabecera dice: acción alert, protocolo icmp, origen cualquier IP y cualquier puerto, flecha hacia la variable HOME NET, que representa nuestra red interna, a cualquier puerto. Entre paréntesis, las opciones: msg es el texto de la alerta, itype ocho indica una petición de eco, es decir, un ping, sid es el identificador único, y por convención las reglas propias usan números a partir del millón. rev es la versión de la regla, y classtype su categoría.' },
    { t: 'term', ch: 'Práctica: primera alerta', title: 'Probar la regla del ping', prompt: 'analista@ids:~$', lines: `
$ sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i eth0 -A alert_fast -k none
Commencing packet processing
# (desde otra máquina: ping -c 3 192.168.56.10)
!11/26-10:21:05.114 [**] [1:1000001:1] "LAB ICMP Ping hacia la red interna" [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.56.40 -> 192.168.56.10
!11/26-10:21:06.115 [**] [1:1000001:1] "LAB ICMP Ping hacia la red interna" [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.56.40 -> 192.168.56.10
!11/26-10:21:07.117 [**] [1:1000001:1] "LAB ICMP Ping hacia la red interna" [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.56.40 -> 192.168.56.10`, say: 'Probemos la regla. Lanzamos Snort con guion c para la configuración, guion R para cargar nuestro fichero de reglas, guion i para la interfaz, guion A alert underscore fast para mostrar las alertas en consola en formato corto y guion k none para ignorar los checksums, algo útil en máquinas virtuales. Desde otra máquina hacemos tres pings y... ¡ahí están nuestras tres primeras alertas! Fíjate en el formato: fecha, el identificador uno, un millón uno, uno, que significa generador, sid y revisión, el mensaje, la prioridad y las IPs.' },
    { t: 'code', ch: 'Reglas útiles', title: 'Reglas defensivas más realistas', file: 'local.rules', code: `# 1) Fuerza bruta SSH: >5 conexiones nuevas en 60 s desde la misma IP
alert tcp any any -> $HOME_NET 22 (msg:"LAB Posible fuerza bruta SSH";
  flow:to_server; flags:S;
  detection_filter:track by_src, count 5, seconds 60;
  sid:1000002; rev:1; classtype:attempted-admin;)

# 2) Intento de path traversal en peticiones web
alert http any any -> $HOME_NET any (msg:"LAB Path traversal en URI";
  http_uri; content:"../"; content:"/etc/passwd"; nocase;
  sid:1000003; rev:1; classtype:web-application-attack;)

# 3) Escáner de vulnerabilidades por User-Agent
alert http any any -> $HOME_NET any (msg:"LAB User-Agent de escáner (sqlmap/nikto)";
  http_header:field user-agent; pcre:"/(sqlmap|nikto|nmap scripting)/i";
  sid:1000004; rev:1;)`, hl: [4, 9, 14], say: 'Ahora reglas más realistas. La primera detecta fuerza bruta SSH: paquetes SYN hacia el puerto veintidós y, gracias a detection filter, solo alerta si hay más de cinco conexiones nuevas en sesenta segundos desde la misma IP de origen. La segunda detecta intentos de path traversal: busca en la URI la secuencia punto punto barra y la cadena barra etc barra passwd. La tercera usa una expresión regular sobre la cabecera User-Agent para detectar herramientas automáticas como sqlmap, nikto o los scripts de Nmap.' },
    { t: 'term', title: 'Generar tráfico de ataque y ver las alertas', prompt: 'atacante@lab:~$', lines: `
# Simular fuerza bruta (laboratorio): 10 conexiones rápidas
$ for i in $(seq 1 10); do nc -z -w1 192.168.56.10 22; done
# Path traversal
$ curl -s "http://192.168.56.10/index.php?page=../../../../etc/passwd" -o /dev/null
# Escáner web
$ curl -s -A "sqlmap/1.8" http://192.168.56.10/ -o /dev/null
# ---- consola de Snort ----
!11/26-10:30:12 [**] [1:1000002:1] "LAB Posible fuerza bruta SSH" [**] {TCP} 192.168.56.66:51022 -> 192.168.56.10:22
!11/26-10:30:41 [**] [1:1000003:1] "LAB Path traversal en URI" [**] {TCP} 192.168.56.66:40210 -> 192.168.56.10:80
!11/26-10:30:55 [**] [1:1000004:1] "LAB User-Agent de escáner (sqlmap/nikto)" [**] {TCP} 192.168.56.66:40214 -> 192.168.56.10:80`, say: 'Generemos tráfico malicioso controlado desde la máquina atacante del laboratorio. Un bucle con netcat abre diez conexiones rápidas al puerto veintidós. Con curl pedimos una URL con path traversal. Y con otro curl nos hacemos pasar por sqlmap cambiando el User-Agent. En la consola de Snort aparecen las tres alertas, cada una con su identificador. Probar cada regla con tráfico real es imprescindible: una regla que nunca se ha probado es una regla que no sabes si funciona.' },
    { t: 'bul', ch: 'Reglas de la comunidad', icon: '📦', title: 'No empieces de cero: conjuntos de reglas', items: ['**Community Rules** (gratis, Talos).', '**Registered / Subscriber** (Talos, con registro o suscripción).', '**Emerging Threats Open** (Proofpoint) — también para Suricata.', 'Gestión automática con **PulledPork 3**.', 'Desactiva reglas ruidosas y documenta por qué (tuning).'], say: 'Por supuesto, no vas a escribir todas las reglas a mano. Existen conjuntos de reglas mantenidos por expertos. Las Community Rules de Talos son gratuitas. Las Registered y Subscriber requieren registro o suscripción y llegan antes. Emerging Threats Open, de Proofpoint, es otro conjunto muy popular, compatible también con Suricata. Para descargarlas y actualizarlas automáticamente se usa PulledPork tres. Y una parte esencial del trabajo es el tuning: desactivar reglas que generan ruido en tu entorno y documentar por qué.' },
    { t: 'flow', title: 'Dónde colocar el sensor IDS', zones: [{ x: 360, y: 40, w: 420, h: 450, label: 'DMZ', c: '#f59e0b' }, { x: 800, y: 40, w: 320, h: 450, label: 'LAN interna', c: '#10b981' }], nodes: [{ id: 'i', x: 150, y: 260, label: 'Internet', icon: '🌍', w: 180, c: '#ef4444' }, { id: 'fw', x: 470, y: 260, label: 'Firewall', icon: '🧱', w: 170, c: '#f59e0b' }, { id: 'sw', x: 680, y: 260, label: 'Switch', sub: 'SPAN', icon: '🔀', w: 160 }, { id: 'ids', x: 680, y: 430, label: 'Sensor IDS', sub: 'Snort', icon: '🐷', w: 190, c: '#a78bfa' }, { id: 'web', x: 570, y: 110, label: 'Web', icon: '🌐', w: 150 }, { id: 'lan', x: 960, y: 260, label: 'Usuarios', icon: '👥', w: 190, c: '#10b981' }], edges: [['i', 'fw'], ['fw', 'sw'], ['sw', 'web'], ['sw', 'lan'], ['sw', 'ids', 'copia', '#a78bfa']], say: 'Una cuestión de diseño: ¿dónde colocamos el sensor? Lo habitual es detrás del firewall, conectado a un puerto espejo o SPAN del switch, o a un TAP de red, de forma que reciba una copia de todo el tráfico que entra y sale de la DMZ y de la red interna. Así vemos lo que el firewall dejó pasar. En redes grandes se colocan varios sensores: en el perímetro, entre segmentos internos y en el centro de datos, para detectar también el movimiento lateral.' },
    { t: 'quiz', ch: 'Repaso', q: 'En la regla "alert tcp any any -> $HOME_NET 22 (...; sid:1000002; ...)", ¿qué indica $HOME_NET?', o: ['La IP del atacante', 'La variable con las redes internas a proteger', 'El puerto de destino', 'El fichero de log'], a: 1, say: 'Repaso. En una regla de Snort, ¿qué indica la variable HOME NET? Correcto: es la variable que contiene las redes internas que queremos proteger, y se define en el fichero de configuración. Definirla bien es crítico: si está mal, muchas reglas no dispararán.' },
    { t: 'title', icon: '🎓', kick: 'Siguiente video', title: 'Suricata: IDS/IPS moderno', sub: 'Multihilo, logs JSON (eve.json), reglas ET Open e integración con el SIEM.', say: 'Excelente. Ya sabes cómo piensa un IDS y cómo escribir reglas. En el siguiente video veremos Suricata, la alternativa moderna, multihilo y con logs en JSON que se integran de maravilla con el SIEM. Las reglas que has aprendido te servirán casi tal cual.' }
  ]
});

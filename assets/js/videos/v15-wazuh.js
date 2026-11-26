VIDEOS.push({
  id: 'wazuh', n: 15, tool: 'Wazuh · Sysmon', icon: '🦉', color: '#3b82f6', level: 'Intermedio',
  title: 'Wazuh y Sysmon: SIEM/XDR open source y telemetría de Windows',
  desc: 'Arquitectura de Wazuh, despliegue de agentes, Sysmon con configuración de comunidad, reglas y decodificadores propios, FIM, detección de vulnerabilidades y respuesta activa.',
  scenes: [
    { t: 'title', ch: 'Introducción', icon: '🦉', kick: 'Módulo 15 · SIEM open source', title: 'Wazuh + Sysmon', sub: 'Un SIEM/XDR gratuito y la mejor telemetría de Windows.', say: 'Bienvenido al módulo de Wazuh y Sysmon. Wazuh es la plataforma de seguridad open source más popular para pymes y laboratorios: combina SIEM, detección en el endpoint, integridad de ficheros, inventario de vulnerabilidades y respuesta activa. Sysmon es una herramienta gratuita de Microsoft que hace que Windows registre con detalle cada proceso, conexión y fichero. Juntos forman una pareja perfecta para aprender y para proteger entornos reales.' },
    { t: 'flow', ch: 'Arquitectura', title: 'Cómo encajan las piezas de Wazuh', nodes: [{ id: 'w', x: 150, y: 110, label: 'Agente Windows', sub: 'Sysmon + eventos', icon: '🪟' }, { id: 'l', x: 150, y: 250, label: 'Agente Linux', sub: 'auth, auditd, FIM', icon: '🐧', s: 0 }, { id: 'n', x: 150, y: 390, label: 'Syslog', sub: 'firewall, switches', icon: '🧱', s: 0 }, { id: 'm', x: 520, y: 250, label: 'Wazuh Manager', sub: 'decoders + reglas', icon: '🧠', c: '#a78bfa', w: 230, s: 1 }, { id: 'i', x: 860, y: 170, label: 'Indexer', sub: 'OpenSearch', icon: '🗄️', c: '#f59e0b', s: 2 }, { id: 'd', x: 860, y: 340, label: 'Dashboard', sub: 'web UI', icon: '📊', c: '#10b981', s: 3 }], edges: [['w', 'm', '1514/tcp'], ['l', 'm'], ['n', 'm', '514'], ['m', 'i', 'alertas'], ['i', 'd']], say: 'Así encajan las piezas. Los agentes se instalan en los equipos Windows y Linux y envían eventos cifrados al manager por el puerto mil quinientos catorce. Los dispositivos de red que no admiten agente envían syslog. El manager es el cerebro: decodifica cada evento y lo compara con miles de reglas. Las alertas se guardan en el indexer, basado en OpenSearch, y se consultan desde el dashboard web. En un laboratorio, todo cabe en una sola máquina virtual con ocho gigas de memoria.' },
    { t: 'term', ch: 'Instalación', title: 'Instalar Wazuh en una sola máquina (laboratorio)', prompt: 'admin@wazuh:~$', lines: `
# Asistente oficial "all-in-one" (indexer + manager + dashboard)
$ curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
$ sudo bash ./wazuh-install.sh -a
INFO: --- Summary ---
INFO: You can access the web interface https://<wazuh-ip>:443
    User: admin
    Password: <generada y mostrada solo una vez>
+INFO: Installation finished.
# Comprobar servicios
$ sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
+active
+active
+active`, say: 'Para un laboratorio, Wazuh ofrece un asistente que lo instala todo en una sola máquina con la opción guion a. Al terminar muestra la dirección del panel web y la contraseña del administrador, que debes guardar en un gestor de contraseñas porque solo se muestra una vez. Revisa siempre un script antes de ejecutarlo con privilegios. Comprobamos que los tres servicios están activos: manager, indexer y dashboard.' },
    { t: 'term', ch: 'Sysmon', title: 'Desplegar Sysmon y el agente en Windows', prompt: 'PS C:\\Admin>', win: 'PowerShell (Administrador) — PC-CONTA-07', lines: `
# 1) Sysmon con una configuración de comunidad (p. ej. SwiftOnSecurity u Olaf Hartong)
$ .\\Sysmon64.exe -accepteula -i .\\sysmonconfig.xml
+Sysmon64 installed. SysmonDrv installed. Configuration file validated.
# 2) Agente Wazuh apuntando al manager
$ msiexec /i wazuh-agent.msi /q WAZUH_MANAGER="10.0.99.10" WAZUH_AGENT_NAME="PC-CONTA-07"
$ NET START WazuhSvc
+The Wazuh service was started successfully.
# 3) Comprobar que Sysmon genera eventos
$ Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 | fl Id,Message
Id      : 1
Message : Process Create: Image: C:\\Windows\\System32\\notepad.exe ParentImage: C:\\Windows\\explorer.exe`, say: 'En Windows, primero instalamos Sysmon con una configuración de la comunidad, como la de SwiftOnSecurity o la modular de Olaf Hartong, que ya filtran el ruido y destacan lo relevante. Después instalamos el agente de Wazuh indicando la IP del manager y un nombre para el equipo, y arrancamos el servicio. Por último, comprobamos con Get WinEvent que el canal de Sysmon está generando eventos: aquí vemos un evento uno, creación de proceso, con la imagen y su proceso padre.' },
    { t: 'table', ch: 'Eventos clave', title: 'Los eventos de Sysmon que más usarás', mono: true, head: ['ID', 'Evento', 'Qué detecta'], rows: [['1', 'Process Create', 'Línea de comandos, padre, hash: la joya'], ['3', 'Network Connection', 'Qué proceso abre qué conexión'], ['7', 'Image Loaded', 'DLLs cargadas (side-loading)'], ['10', 'Process Access', 'Acceso a la memoria de lsass (robo de credenciales)'], ['11', 'File Create', 'Ficheros nuevos: droppers, ransomware'], ['13', 'Registry Value Set', 'Persistencia en claves Run'], ['22', 'DNS Query', 'Qué proceso resolvió qué dominio']], hl: [0, 3], say: 'Estos son los eventos de Sysmon que más usarás. El uno, creación de proceso, es la joya: incluye la línea de comandos completa, el proceso padre y el hash del ejecutable. El tres relaciona procesos con conexiones de red. El siete muestra las DLL cargadas. El diez detecta accesos a la memoria de otros procesos, como lsass, donde Windows guarda credenciales. El once registra ficheros creados. El trece cambios en el registro, típicos de persistencia. Y el veintidós qué proceso resolvió cada dominio.' },
    { t: 'dash', ch: 'Práctica: el panel', app: 'Wazuh · Threat Hunting', title: 'Primer vistazo al panel de Wazuh', widgets: [{ k: 'stat', t: 'Agentes activos', v: '42/43', c: '#10b981' }, { k: 'stat', t: 'Alertas nivel ≥ 12', v: '3', c: '#ef4444' }, { k: 'stat', t: 'Fallos de login', v: '1.284', c: '#f59e0b' }, { k: 'stat', t: 'Cambios FIM', v: '17' }, { k: 'list', t: 'Alertas recientes', w: 2, h: 2, items: [['crit', 'Nivel 15 · Sysmon: acceso a memoria de lsass.exe por rundll32.exe (PC-CONTA-07)'], ['high', 'Nivel 12 · PowerShell con -EncodedCommand lanzado por WINWORD.EXE'], ['high', 'Nivel 10 · Múltiples fallos de autenticación (sshd) desde 203.0.113.66'], ['med', 'Nivel 7 · Fichero modificado en /etc/sudoers (FIM)']] }, { k: 'line', t: 'Alertas por hora', w: 2, h: 2, data: [12, 15, 11, 14, 13, 60, 88, 40, 16, 12], c: '#f59e0b', thr: 50 }], say: 'Este es el panel. Arriba, el estado de los agentes y los contadores. Wazuh asigna a cada regla un nivel de cero a quince: a partir de doce, atención inmediata. En la lista vemos una alerta de nivel quince: un rundll treinta y dos accediendo a la memoria de lsass, un patrón clásico de volcado de credenciales. Debajo, Word lanzando PowerShell codificado, que suele indicar un documento malicioso. La gráfica muestra un pico de alertas que coincide con el inicio del incidente.' },
    { t: 'code', ch: 'Reglas propias', title: 'Escribir una regla local en Wazuh', file: '/var/ossec/etc/rules/local_rules.xml', code: `<group name="sysmon,local,">
  <!-- Office lanzando un intérprete: posible macro maliciosa -->
  <rule id="100200" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\\\(winword|excel|powerpnt)\\.exe$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\\\(powershell|cmd|wscript|mshta)\\.exe$</field>
    <description>Office ejecuta $(win.eventdata.image) (posible macro)</description>
    <mitre><id>T1204.002</id><id>T1059.001</id></mitre>
  </rule>
</group>`, hl: [5, 6, 8], say: 'Ahora escribimos una regla propia. Las reglas locales van en local rules punto xml, con identificadores a partir de cien mil. Esta regla de nivel doce se aplica a eventos uno de Sysmon y exige dos condiciones: que el proceso padre sea Word, Excel o PowerPoint, y que el proceso hijo sea PowerShell, cmd, wscript o mshta. Un documento de Office casi nunca necesita lanzar un intérprete, así que es una detección de alta calidad. Añadimos la descripción y las técnicas de MITRE para que el analista tenga contexto.' },
    { t: 'term', ch: 'Probar la regla', title: 'Validar con wazuh-logtest', prompt: 'admin@wazuh:~$', lines: `
$ sudo /var/ossec/bin/wazuh-logtest
Type one log per line
# (pegamos un evento Sysmon 1 de ejemplo con parentImage WINWORD.EXE)
**Phase 2: Completed decoding.
        name: 'windows_eventchannel'
**Phase 3: Completed filtering (rules).
        id: '100200'
        level: '12'
!       description: 'Office ejecuta C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe (posible macro)'
        mitre.id: '["T1204.002","T1059.001"]'
+**Alert to be generated.
$ sudo systemctl restart wazuh-manager`, say: 'Antes de desplegar, probamos con wazuh logtest. Pegamos un evento de ejemplo y la herramienta muestra las tres fases: decodificación, que reconoce el formato de Windows, y filtrado, donde se activa nuestra regla cien mil doscientos con nivel doce y la descripción rellenada con el nombre del proceso. Al final indica que se generaría una alerta. Solo entonces reiniciamos el manager para cargarla. Probar cada regla antes de activarla evita sorpresas en producción.' },
    { t: 'bul', ch: 'Más capacidades', title: 'Lo que Wazuh hace además de alertar', items: ['**FIM**: avisa si cambian /etc/passwd, sudoers o la web', '**Vulnerability Detection**: cruza el software instalado con CVEs', '**SCA**: comprueba configuraciones contra CIS Benchmarks', '**Active Response**: bloquea una IP o desactiva una cuenta automáticamente', '**Cumplimiento**: paneles para PCI DSS, RGPD, NIS2 o ENS'], say: 'Wazuh hace mucho más que alertar. Su monitor de integridad de ficheros avisa si cambian ficheros críticos como passwd, sudoers o el código de la web. El detector de vulnerabilidades cruza el software instalado con bases de datos de CVE. El módulo SCA compara la configuración con las guías CIS. La respuesta activa puede bloquear automáticamente una IP tras una fuerza bruta. Y trae paneles para normativas como PCI, RGPD, NIS dos o el Esquema Nacional de Seguridad.' },
    { t: 'code', ch: 'Respuesta activa', title: 'Respuesta activa: bloquear fuerza bruta SSH', file: '/var/ossec/etc/ossec.conf', code: `<active-response>
  <command>firewall-drop</command>   <!-- script incluido -->
  <location>local</location>         <!-- en el agente atacado -->
  <rules_id>5763</rules_id>          <!-- fuerza bruta sshd -->
  <timeout>3600</timeout>            <!-- desbloqueo en 1 h -->
</active-response>
<!-- Buenas prácticas: lista blanca de IPs propias,
     empezar en modo alerta y medir falsos positivos -->`, hl: [2, 4, 5], say: 'Así se configura una respuesta activa. Cuando salte la regla cinco mil setecientos sesenta y tres, que detecta fuerza bruta contra SSH, se ejecuta el script firewall drop en el propio agente atacado, bloqueando la IP de origen durante una hora. Buenas prácticas: mantén una lista blanca con tus propias IPs para no bloquearte a ti mismo, empieza solo alertando y mide los falsos positivos antes de automatizar.' },
    { t: 'quiz', ch: 'Repaso', q: '¿Qué evento de Sysmon te muestra la línea de comandos completa y el proceso padre?', o: ['Evento 3', 'Evento 1', 'Evento 11', 'Evento 22'], a: 1, say: 'Pregunta de repaso. ¿Qué evento de Sysmon muestra la línea de comandos completa y el proceso padre? El evento uno, creación de proceso. Es el más valioso para detectar ataques en Windows.' },
    { t: 'title', ch: 'Cierre', icon: '✅', kick: 'Resumen', title: 'Tu propio SIEM/XDR gratuito', sub: 'Agentes + Sysmon → manager con reglas → alertas con MITRE → respuesta activa.', say: 'Resumen. Con Wazuh y Sysmon tienes un SIEM y XDR gratuito: agentes que recogen telemetría rica, un manager que aplica reglas con contexto MITRE, y capacidades de integridad, vulnerabilidades y respuesta activa. Monta tu laboratorio, escribe una regla para cada técnica que aprendas y pruébala con wazuh logtest. Hasta el próximo módulo.' }
  ]
});

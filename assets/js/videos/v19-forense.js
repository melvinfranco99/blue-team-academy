VIDEOS.push({
  id: 'forense', n: 19, tool: 'Volatility · Autopsy · KAPE', icon: '🔬', color: '#a78bfa', level: 'Avanzado',
  title: 'Análisis forense digital (DFIR): memoria, disco y línea temporal',
  desc: 'Orden de volatilidad, cadena de custodia, adquisición, Volatility 3 para memoria RAM, artefactos de Windows, KAPE, Autopsy y construcción de una super-timeline.',
  scenes: [
    { t: 'title', ch: 'Introducción', icon: '🔬', kick: 'Módulo 19 · DFIR', title: 'Análisis forense digital', sub: 'Reconstruir qué pasó, cuándo y cómo, con pruebas que resistan un juicio.', say: 'Bienvenido al módulo de análisis forense digital, la D de DFIR. El objetivo del forense es reconstruir qué ocurrió, cuándo y cómo, con pruebas sólidas que puedan presentarse incluso ante un juez. Veremos el orden de volatilidad, la cadena de custodia, el análisis de memoria con Volatility, los artefactos clave de Windows y cómo construir una línea temporal.' },
    { t: 'ana', icon: '🕵️', title: 'Como la policía científica en la escena del crimen', text: 'Primero se acordona y se fotografía; después se recogen las pruebas más frágiles; todo se etiqueta y se firma; y el análisis se hace sobre copias, nunca sobre el original.', say: 'Piensa en la policía científica. Primero acordona la escena y la fotografía. Después recoge las pruebas más frágiles, como huellas que se pueden borrar. Todo se etiqueta, se precinta y se firma. Y el análisis se hace en el laboratorio, sobre copias, nunca sobre el original. En forense digital seguimos exactamente los mismos principios.' },
    { t: 'table', ch: 'Orden de volatilidad', title: 'Orden de volatilidad (RFC 3227)', head: ['Orden', 'Evidencia', 'Cuánto dura'], rows: [['1', 'Registros y caché de CPU', 'Nanosegundos'], ['2', 'Memoria RAM: procesos, conexiones, claves', 'Hasta apagar'], ['3', 'Estado de red, tablas ARP, sesiones', 'Segundos o minutos'], ['4', 'Disco: ficheros, logs, registro', 'Días o años'], ['5', 'Logs remotos, copias de seguridad', 'Según retención'], ['6', 'Medios de archivo', 'Años']], hl: [1], say: 'El orden de volatilidad nos dice qué recoger primero. Lo más frágil son los registros de la CPU, prácticamente inalcanzables. Después la memoria RAM, que contiene procesos, conexiones, claves de cifrado e incluso malware que nunca tocó el disco: se pierde al apagar. Luego el estado de la red. El disco dura mucho más, y los logs remotos y copias aún más. Por eso, ante un incidente, se adquiere la memoria antes de apagar o reiniciar.' },
    { t: 'term', ch: 'Adquisición', title: 'Adquirir memoria y disco con integridad', prompt: 'PS E:\\IR>', win: 'PowerShell (Administrador) — PC-CONTA-07', lines: `
# Memoria RAM a un disco externo (no al disco de la víctima)
$ .\\winpmem_mini_x64.exe E:\\IR\\PC-CONTA-07.raw
+Driver loaded. Imaging 16 GB…  done.
$ Get-FileHash E:\\IR\\PC-CONTA-07.raw -Algorithm SHA256
SHA256  9F2C…41AB   E:\\IR\\PC-CONTA-07.raw
# Disco: imagen forense con bloqueador de escritura (FTK Imager / ewfacquire)
$ ewfacquire /dev/sdb -t /evidencias/PC-CONTA-07 -f encase6 -c deflate
+Written: 256 GiB · MD5 y SHA1 verificados`, say: 'Adquisición. La memoria se vuelca con una herramienta como WinPmem directamente a un disco externo, nunca al disco del equipo analizado, para no sobrescribir evidencias. Calculamos su hash SHA doscientos cincuenta y seis y lo anotamos. El disco se copia con un bloqueador de escritura, físico o lógico, en un formato forense como E zero one, que guarda metadatos y verifica hashes. A partir de aquí, todo el análisis se hace sobre las copias.' },
    { t: 'code', ch: 'Cadena de custodia', title: 'Registro de cadena de custodia', file: 'custodia_INC-2026-112.txt', code: `Evidencia:   EV-01  PC-CONTA-07.raw (RAM, 16 GB)
SHA256:      9F2C…41AB
Recogida:    2026-11-26 10:41 UTC por A. Analista (SOC L2)
Método:      WinPmem desde USB de respuesta, equipo aislado por EDR
Custodia:    10:55 entregado a DFIR (firma)  · 11:02 almacenado en NAS cifrado
Verificación: 2026-11-27 09:00 hash coincide ✔`, hl: [2, 6], say: 'La cadena de custodia documenta quién tuvo la evidencia, cuándo, cómo se obtuvo y dónde está. Identificador, hash, fecha y hora en UTC, quién la recogió y con qué método, cada transferencia firmada, y verificaciones posteriores del hash. Sin esto, la evidencia puede no ser válida en un procedimiento judicial o disciplinario. Incluso si no hay juicio, esta disciplina hace tu trabajo reproducible.' },
    { t: 'term', ch: 'Volatility 3', title: 'Práctica: análisis de memoria con Volatility 3', prompt: 'dfir@lab:~$', lines: `
$ vol -f PC-CONTA-07.raw windows.pstree
PID   PPID  ImageFileName   CreateTime
4012  3880  OUTLOOK.EXE     10:01:55
* 5120 4012 WINWORD.EXE     10:02:40
** 5388 5120 powershell.exe 10:02:44
!*** 6020 5388 rundll32.exe  10:02:51
$ vol -f PC-CONTA-07.raw windows.cmdline --pid 5388 6020
5388 powershell.exe  powershell -nop -w hidden -enc SQBFAFgA…
!6020 rundll32.exe    rundll32.exe C:\\Users\\Public\\a.dll,Start
$ vol -f PC-CONTA-07.raw windows.netscan | grep 6020
!TCPv4 10.0.10.45:51022  203.0.113.50:443  ESTABLISHED  6020  rundll32.exe`, say: 'Analicemos la memoria con Volatility tres. El plugin pstree muestra el árbol de procesos tal como estaba en el momento del volcado: Outlook, Word, PowerShell y un rundll treinta y dos. Con cmdline vemos sus líneas de comandos: PowerShell oculto y codificado, y rundll ejecutando una DLL desde la carpeta Public. Con netscan comprobamos que ese rundll tenía una conexión establecida con una IP externa. En tres comandos confirmamos la cadena completa del ataque.' },
    { t: 'term', title: 'Buscar código inyectado y extraerlo', prompt: 'dfir@lab:~$', lines: `
$ vol -f PC-CONTA-07.raw windows.malfind --pid 6020
!Process rundll32.exe Pid 6020  Protection: PAGE_EXECUTE_READWRITE
!0x1f0000  4d 5a 90 00 03 00 00 00   MZ......   ← cabecera PE en memoria
$ vol -f PC-CONTA-07.raw -o dump/ windows.dumpfiles --pid 6020
$ sha256sum dump/*.dll
e7a1…9c02  dump/file.0x1f0000.a.dll
# Comprobar el hash en VirusTotal / sandbox y añadirlo a los IOCs`, say: 'El plugin malfind busca regiones de memoria con permisos de lectura, escritura y ejecución a la vez, algo poco habitual en código legítimo, y que además contienen una cabecera MZ, la firma de un ejecutable de Windows. Es un indicio claro de código inyectado. Extraemos los ficheros asociados al proceso, calculamos su hash y lo consultamos en servicios de inteligencia o lo analizamos en una sandbox, siempre en un entorno aislado.' },
    { t: 'table', ch: 'Artefactos de Windows', title: 'Artefactos de disco que prueban la ejecución', mono: true, head: ['Artefacto', 'Qué demuestra', 'Herramienta'], rows: [['Prefetch (C:\\Windows\\Prefetch)', 'Programa ejecutado, veces y últimas fechas', 'PECmd'], ['Amcache.hve', 'Ejecutables presentes y su SHA1', 'AmcacheParser'], ['ShimCache (SYSTEM)', 'Ficheros vistos por el sistema', 'AppCompatCacheParser'], ['UserAssist / RecentDocs (NTUSER)', 'Acciones del usuario en el escritorio', 'RECmd / Registry Explorer'], ['$MFT y $UsnJrnl', 'Creación, cambios y borrado de ficheros', 'MFTECmd'], ['EVTX (4624, 4688, 7045, 1102)', 'Logins, procesos, servicios, borrado de logs', 'EvtxECmd / Hayabusa'], ['SRUM', 'Bytes enviados por aplicación (exfiltración)', 'SrumECmd']], say: 'En el disco, estos artefactos de Windows prueban qué se ejecutó y cuándo. Prefetch registra programas ejecutados y sus últimas fechas. Amcache guarda ejecutables con su hash. ShimCache registra ficheros vistos por el sistema. UserAssist y documentos recientes muestran acciones del usuario. La tabla MFT y el diario USN revelan creación y borrado de ficheros, incluso si el atacante los eliminó. Los logs de eventos registran inicios de sesión, procesos, servicios y borrado de logs. Y SRUM muestra cuántos bytes envió cada aplicación, útil para estimar una exfiltración. Las herramientas de Eric Zimmerman los procesan todos.' },
    { t: 'term', ch: 'KAPE y timeline', title: 'De artefactos a una super-timeline', prompt: 'PS E:\\IR>', lines: `
# KAPE: recoger (targets) y procesar (modules) en un paso
$ .\\kape.exe --tsource C: --target KapeTriage --tdest E:\\triage --mdest E:\\out --module !EZParser
+Processed 1.2M entries in 4m 12s
# Hayabusa: detección Sigma sobre EVTX y timeline en CSV
$ .\\hayabusa.exe csv-timeline -d E:\\triage\\C\\Windows\\System32\\winevt\\Logs -o timeline.csv
!crit  10:03:10  PC-CONTA-07  Persistencia: valor Run sospechoso
!high  10:02:44  PC-CONTA-07  PowerShell codificado lanzado por Office
# Plaso: super-timeline de todas las fuentes
$ log2timeline.py --storage-file caso.plaso E:\\triage && psort.py -o l2tcsv caso.plaso > supertimeline.csv`, say: 'KAPE recoge los artefactos y los procesa en un solo paso con los parsers de Eric Zimmerman. Hayabusa aplica reglas Sigma a los logs de eventos y genera una línea temporal con las detecciones más graves, ideal para un primer triaje. Y Plaso, con log2timeline, crea una super timeline que combina todas las fuentes en un único listado cronológico, que después se filtra y analiza en herramientas como Timeline Explorer.' },
    { t: 'dash', ch: 'La historia completa', app: 'Timeline Explorer · supertimeline.csv (filtrado)', title: 'La reconstrucción final', widgets: [{ k: 'list', t: 'Cronología del incidente INC-2026-112', w: 4, h: 3, items: [['low', '10:01:55 · Correo con factura_noviembre.docm recibido (OfficeActivity)'], ['med', '10:02:40 · El usuario abre el documento (Prefetch WINWORD, RecentDocs)'], ['high', '10:02:44 · Macro lanza PowerShell codificado (EVTX 4688, Sysmon 1)'], ['crit', '10:02:51 · a.dll escrita en C:\\Users\\Public y ejecutada (MFT, Amcache)'], ['crit', '10:03:10 · Persistencia en HKCU\\…\\Run (NTUSER)'], ['high', '10:15–10:40 · 380 MB enviados a 203.0.113.50 (SRUM)'], ['low', '10:41 · Equipo aislado por el SOC (EDR)']] }], say: 'Esta es la reconstrucción final, donde cada línea se apoya en un artefacto concreto. El correo llega, el usuario abre el documento, la macro lanza PowerShell, se escribe y ejecuta la DLL, se crea la persistencia, se envían trescientos ochenta megas a la IP del atacante, según SRUM, y el SOC aísla el equipo. Con esta cronología respondemos a las preguntas de la dirección: qué pasó, qué datos pudieron salir y desde cuándo, algo clave para decidir si hay que notificar a la autoridad de protección de datos.' },
    { t: 'quiz', ch: 'Repaso', q: 'Llegas a un equipo comprometido que sigue encendido. ¿Qué adquieres primero?', o: ['La imagen del disco', 'La memoria RAM', 'Los logs del firewall', 'Las copias de seguridad'], a: 1, say: 'Pregunta de repaso. Llegas a un equipo comprometido que sigue encendido. ¿Qué adquieres primero? La memoria RAM, porque es lo más volátil y se pierde al apagar. El disco puede esperar.' },
    { t: 'title', ch: 'Cierre', icon: '✅', kick: 'Resumen', title: 'Forense: pruebas, no suposiciones', sub: 'Volatilidad → adquisición con hash → custodia → memoria → artefactos → timeline.', say: 'Resumen. Recoge primero lo más volátil, calcula hashes y documenta la cadena de custodia, analiza la memoria con Volatility, los artefactos de disco con las herramientas de Zimmerman, y une todo en una línea temporal. Practica con los retos gratuitos de CyberDefenders y Blue Team Labs Online. Hasta el siguiente módulo.' }
  ]
});

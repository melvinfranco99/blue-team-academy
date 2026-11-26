/* Laboratorios guiados paso a paso (lecciones 17–25). */
window.WT = window.WT || {};
Object.assign(WT, {
  sentinel: [
    { t: 'bul', title: 'Montar un laboratorio de Sentinel gratis', note: 'Cuenta de Azure de prueba + datos de ejemplo', items: ['Crear **cuenta gratuita de Azure** (crédito inicial) y una alerta de presupuesto de 5 €', 'Crear **Log Analytics workspace** `law-lab` en una región europea', '**Microsoft Sentinel → Add** sobre ese workspace (prueba gratuita de 31 días)', '**Content hub** → instalar *Microsoft Entra ID* y *Training Lab*', 'O usar el entorno de demo público de Log Analytics para practicar KQL'], say: 'Laboratorio guiado de Sentinel. Paso uno: un laboratorio gratuito. Creo una cuenta gratuita de Azure y, lo primero, una alerta de presupuesto de cinco euros para no llevarme sorpresas. Creo un área de trabajo de Log Analytics en una región europea y añado Sentinel encima, que tiene un periodo de prueba. Desde el Content hub instalo la solución de Entra ID y el laboratorio de entrenamiento, que carga datos de ejemplo. Si solo quieres practicar KQL, existe un entorno de demostración público de Log Analytics.', step: [1, 4] },
    { t: 'code', title: 'Explorar una tabla antes de consultarla', note: 'getschema · take · summarize count by', file: 'Logs · KQL', code: `SigninLogs | getschema | project ColumnName, ColumnType | take 15
// → TimeGenerated (datetime), UserPrincipalName (string), IPAddress (string),
//   ResultType (string), LocationDetails (dynamic), ConditionalAccessStatus …

SigninLogs | where TimeGenerated > ago(1d) | take 5          // ver filas reales

SigninLogs | where TimeGenerated > ago(1d)
| summarize count() by ResultType, ResultDescription | sort by count_ desc
// 0       → 18.211  (correctos)
// 50126   →  1.304  (usuario o contraseña incorrectos)
// 50074   →    412  (se requiere MFA)`, hl: [1, 5, 8], say: 'Paso dos: explorar la tabla antes de escribir consultas complicadas. getschema lista las columnas y sus tipos: fíjate en que LocationDetails es de tipo dinámico, un JSON, y por eso habrá que extraer sus campos. take cinco muestra filas reales para ver cómo son los valores. Y summarize count by ResultType y su descripción me enseña qué códigos existen: cero son correctos, cincuenta mil ciento veintiséis contraseñas incorrectas, cincuenta mil setenta y cuatro se requiere MFA. Con esto ya sé qué filtrar.', step: [2, 4] },
    { t: 'code', title: 'Construir la detección línea a línea', note: 'Ejecutar tras añadir cada línea y comprobar el resultado', file: 'Logs · KQL', code: `SigninLogs
| where TimeGenerated > ago(1h)                          // ① 21.004 filas
| where ResultType == "50126"                            // ② 1.304
| summarize Intentos=count(), Usuarios=dcount(UserPrincipalName),
            Primer=min(TimeGenerated), Ultimo=max(TimeGenerated)
            by IPAddress                                  // ③ 37 IPs
| where Usuarios >= 10                                    // ④ 2 IPs
| extend Duracion = Ultimo - Primer
| join kind=leftouter (SigninLogs | where TimeGenerated > ago(1h) and ResultType == "0"
        | summarize Exitos=dcount(UserPrincipalName) by IPAddress) on IPAddress   // ⑤`, hl: [7, 10], say: 'Paso tres: construir la detección línea a línea, ejecutando cada vez. Uno: última hora, veintiún mil filas. Dos: solo contraseñas incorrectas, mil trescientas. Tres: agrupo por IP con intentos, usuarios distintos y primera y última hora: treinta y siete IPs. Cuatro: solo las que probaron diez usuarios o más: dos. Calculo la duración. Y cinco: con un join a la izquierda traigo cuántos inicios correctos tuvo cada una de esas IPs. Si Exitos es mayor que cero, hay cuentas comprometidas. Construir así evita errores y te enseña qué hace cada operador.', step: [3, 4] },
    { t: 'dash', title: 'Crear la regla y trabajar el incidente', note: 'Analytics → Create → Scheduled query rule · Incidents', app: 'Microsoft Sentinel · Incidents', widgets: [{ k: 'stat', t: 'Incidente', v: '#4821', c: '#ef4444' }, { k: 'stat', t: 'Severidad', v: 'Alta', c: '#ef4444' }, { k: 'stat', t: 'Entidades', v: '1 IP · 3 cuentas' }, { k: 'stat', t: 'Propietario', v: 'tú', c: '#10b981' }, { k: 'list', t: 'Pasos en el incidente', w: 4, h: 2, items: [['low', 'Asignarme el incidente · estado: Active'], ['med', 'Investigate: gráfico IP → 3 cuentas → 1 con inicio correcto'], ['high', 'Ejecutar playbook "Revocar-sesiones" sobre rgarcia@'], ['low', 'Comentario con consultas usadas y evidencias'], ['low', 'Cerrar: True Positive · Suspicious activity']] }], say: 'Paso cuatro: convertirlo en regla y trabajar el incidente. En Analytics creo una regla programada con la consulta, cada quince minutos, y mapeo las entidades IP y cuenta. Cuando salta, en Incidents me asigno el incidente y lo pongo en activo. Abro Investigate: el gráfico muestra la IP conectada a tres cuentas, una con inicio correcto. Ejecuto el playbook de revocar sesiones sobre esa cuenta, documento en un comentario las consultas y evidencias, y al terminar lo cierro como verdadero positivo. Ese es el día a día de un analista en Sentinel.', step: [4, 4] }
  ],
  edr: [
    { t: 'term', title: 'Lanzar Velociraptor y conectar un cliente', note: 'Modo gui = servidor + cliente en tu equipo', prompt: 'alumno@lab:~$', lines: `
$ wget -q https://github.com/Velocidex/velociraptor/releases/download/v0.7.x/velociraptor-v0.7.x-linux-amd64 -O velociraptor
$ chmod +x velociraptor && ./velociraptor gui --datastore ./vr-data
+GUI is ready on https://127.0.0.1:8889/  (usuario admin, contraseña mostrada en consola)
# En la GUI: lupa → buscar "all" → aparece el cliente local C.1a2b3c… (online)`, say: 'Laboratorio guiado de Velociraptor. Paso uno: descargar el binario oficial desde su repositorio de GitHub, darle permisos de ejecución y lanzarlo en modo gui, indicando una carpeta para sus datos. Se abre el navegador en el puerto ocho mil ochocientos ochenta y nueve. En la interfaz, pulso la lupa y busco all: aparece el cliente local conectado. En un laboratorio con más máquinas, generarías el instalador del cliente y lo desplegarías en cada una.', step: [1, 4] },
    { t: 'bul', title: 'Recoger un artefacto en un equipo', note: 'Cliente → Collected Artifacts → + New Collection', items: ['Seleccionar el cliente → **Collected Artifacts** → **＋**', 'Buscar `Windows.System.Pslist` (o `Linux.Sys.Pslist`)', 'Parámetros: dejar por defecto → **Launch**', 'Pestaña **Results**: lista de procesos con PID, padre, usuario, ruta y hash', 'Ordenar por **CreateTime** y revisar los más recientes'], say: 'Paso dos: recoger un artefacto en un equipo concreto. Selecciono el cliente, voy a Collected Artifacts y pulso el más. Busco el artefacto de listado de procesos, dejo los parámetros por defecto y lo lanzo. En segundos, la pestaña Results muestra todos los procesos con su PID, proceso padre, usuario, ruta y hash. Ordeno por hora de creación para revisar primero lo más reciente, que es donde suele estar lo sospechoso.', step: [2, 4] },
    { t: 'code', title: 'Escribir tu propia consulta VQL en un Notebook', note: 'Notebooks → New → celda VQL', file: 'Notebook · celda VQL', code: `-- Procesos cuyo binario está en carpetas de usuario o temporales
SELECT Pid, Ppid, Name, Exe, CommandLine, Username,
       hash(path=Exe).SHA256 AS sha256
FROM pslist()
WHERE Exe =~ "(?i)(\\\\Users\\\\Public|\\\\AppData\\\\Local\\\\Temp|\\\\ProgramData)\\\\"
  AND NOT Exe =~ "(?i)(Microsoft|Google|Teams)"
-- Resultado: rundll32 → C:\\Users\\Public\\a.dll  (sha256 e7a1…9c02)`, hl: [2, 5], say: 'Paso tres: escribir mi propia consulta. En Notebooks creo una celda VQL. Selecciono PID, proceso padre, nombre, ruta, línea de comandos y usuario, y calculo el hash SHA doscientos cincuenta y seis con la función hash. FROM pslist, la lista de procesos. WHERE con el operador igual virgulilla, que aplica una expresión regular sin distinguir mayúsculas: procesos que se ejecutan desde Public, Temp o ProgramData, excluyendo software conocido. Aparece rundll ejecutando nuestra DLL sospechosa con su hash.', step: [3, 4] },
    { t: 'bul', title: 'Lanzar una caza en toda la flota', note: 'Hunt Manager → New Hunt → artefacto o VQL propio', items: ['**Hunt Manager → ＋** · Descripción: *INC-2026-112 búsqueda a.dll*', 'Artefacto: `Generic.Detection.HashHunter` · Hashes: `e7a1…9c02`', 'Incluir etiqueta `windows` · Expira en 7 días (equipos que se conecten más tarde)', '**Run Hunt** → ver progreso: 1.180/1.204 clientes respondieron', 'Resultados → **2 coincidencias** → exportar CSV → aislar con el EDR'], say: 'Paso cuatro: cazar en toda la flota. En Hunt Manager creo una caza con una descripción que incluya el número de incidente, uso el artefacto que busca hashes y pego el de la DLL. Limito a los equipos Windows y le doy siete días de validez, para que los portátiles que se conecten más tarde también respondan. La lanzo y sigo el progreso: mil ciento ochenta de mil doscientos cuatro equipos han respondido. Dos coincidencias. Exporto el CSV y aíslo esos equipos. Esto es responder a escala.', step: [4, 4] }
  ],
  forense: [
    { t: 'term', title: 'Identificar la memoria y listar procesos', note: 'windows.info primero: confirma que Volatility entiende el volcado', prompt: 'dfir@lab:~$', lines: `
$ sha256sum PC-CONTA-07.raw            # comprobar que coincide con la custodia
9f2c…41ab  PC-CONTA-07.raw
$ vol -f PC-CONTA-07.raw windows.info | grep -E "NtBuildLab|SystemTime"
NtBuildLab   19041.1.amd64fre.vb_release.191206-1406
SystemTime   2026-11-26 10:41:03 UTC
$ vol -f PC-CONTA-07.raw windows.pslist | wc -l
142`, say: 'Laboratorio guiado de forense de memoria. Paso uno: antes de nada, compruebo que el hash del volcado coincide con el anotado en la cadena de custodia. Después ejecuto el plugin windows punto info, que identifica la versión de Windows y la hora del volcado: si Volatility no reconoce el sistema, los demás plugins fallarán. Diez cuarenta y uno UTC. pslist cuenta ciento cuarenta y dos procesos. Ahora sé que trabajo con la evidencia correcta y que el análisis es posible.', step: [1, 4] },
    { t: 'term', title: 'Buscar procesos con padres anómalos', note: 'pstree + conocimiento de lo que es normal en Windows', prompt: 'dfir@lab:~$', lines: `
$ vol -f PC-CONTA-07.raw windows.pstree | grep -E -A3 "WINWORD|svchost.exe" | head -12
* 5120  4012  WINWORD.EXE
!** 5388 5120  powershell.exe          ← Office no debería tener hijos de este tipo
!*** 6020 5388 rundll32.exe
* 788   652   svchost.exe             (padre 652 = services.exe ✔ normal)
!* 7311  6020  svchost.exe             ← svchost con padre rundll32: ¡falso svchost!
$ vol -f PC-CONTA-07.raw windows.pslist --pid 7311 | awk '{print $1,$2,$3,$NF}'
7311 6020 svchost.exe 2026-11-26 10:04:12`, say: 'Paso dos: buscar relaciones padre hijo anómalas. Hay que saber qué es normal en Windows: svchost siempre tiene como padre a services punto exe. Ejecuto pstree y filtro con grep las ramas de Word y de svchost, con guion A tres para ver tres líneas después. Word tiene como hijo a PowerShell, y este a rundll. Y aparece un svchost cuyo padre es rundll treinta y dos: eso no existe en un Windows sano. Es malware disfrazado con un nombre legítimo. Su PID siete mil trescientos once pasa a la lista de investigación.', step: [2, 4] },
    { t: 'term', title: 'Red, línea de comandos y código inyectado', note: 'netscan · cmdline · malfind sobre los PIDs sospechosos', prompt: 'dfir@lab:~$', lines: `
$ vol -f PC-CONTA-07.raw windows.netscan | grep -E "6020|7311"
!TCPv4 10.0.10.45:51022 203.0.113.50:443 ESTABLISHED 6020 rundll32.exe
!TCPv4 10.0.10.45:51190 10.0.10.10:445   ESTABLISHED 7311 svchost.exe   ← movimiento lateral SMB
$ vol -f PC-CONTA-07.raw windows.cmdline --pid 7311
7311 svchost.exe  C:\\Users\\Public\\svchost.exe -k netsvcs    (ruta incorrecta)
$ vol -f PC-CONTA-07.raw windows.malfind --pid 7311 | head -3
!Process svchost.exe Pid 7311  Protection: PAGE_EXECUTE_READWRITE  (MZ header)`, say: 'Paso tres: tres preguntas sobre los sospechosos. netscan: rundll habla con el servidor externo, y el falso svchost tiene una conexión SMB con diez punto cero punto diez punto diez, el servidor de ficheros. Eso es movimiento lateral. cmdline: el falso svchost se ejecuta desde la carpeta Public, cuando el legítimo vive en System treinta y dos. Y malfind encuentra en él memoria ejecutable y escribible con cabecera de ejecutable: código inyectado. Ya tenemos un nuevo alcance: hay que investigar el servidor de ficheros.', step: [3, 4] },
    { t: 'term', title: 'Construir la línea temporal del disco', note: 'Hayabusa para EVTX en minutos', prompt: 'PS E:\\IR>', lines: `
$ .\\hayabusa.exe csv-timeline -d .\\triage\\C\\Windows\\System32\\winevt\\Logs -o tl.csv -p verbose
$ Import-Csv tl.csv | ? Level -in 'crit','high' | sort Timestamp | select Timestamp,Level,RuleTitle -First 5 | ft
Timestamp            Level RuleTitle
10:02:44             high  Office Application Spawned Shell
10:03:10             high  Run Key Persistence
!10:04:30             crit  Remote Service Creation (PSEXESVC) on SRV-FICHEROS
!10:05:02             crit  Security Log Cleared (1102)
10:06:40             high  Suspicious SMB File Copy`, say: 'Paso cuatro: la línea temporal del disco. Hayabusa recorre todos los logs de eventos recogidos en el triaje y aplica miles de reglas Sigma. Con PowerShell importo el CSV, me quedo con los niveles crítico y alto, ordeno por hora y muestro los cinco primeros. La historia se completa: macro, persistencia, creación de un servicio remoto en el servidor de ficheros para moverse lateralmente, borrado del log de seguridad para ocultarse y copia de ficheros por SMB. Memoria y disco cuentan la misma historia: eso es una conclusión forense sólida.', step: [4, 4] }
  ],
  yarasigma: [
    { t: 'term', title: 'Extraer cadenas candidatas de la muestra', note: 'Buscar textos únicos, no genéricos', prompt: 'analista@lab:~$', lines: `
$ sha256sum a.exe && file a.exe
e7a1…9c02  a.exe: PE32+ executable (GUI) x86-64, for MS Windows
$ strings -n 8 a.exe | sort -u | grep -viE "microsoft|kernel32|msvcrt" | head -8
!NIGHTLOCKER
!.locked
README_RESTORE.txt
!vssadmin delete shadows /all /quiet
https://203.0.113.50/k
GetProcAddress
$ strings -el a.exe | grep -i night
!N.I.G.H.T.L.O.C.K.E.R (UTF-16)`, say: 'Laboratorio guiado de YARA. Paso uno: encontrar buenas cadenas. Calculo el hash y confirmo con file que es un ejecutable de Windows de sesenta y cuatro bits. Con strings guion n ocho extraigo textos de al menos ocho caracteres, quito duplicados y elimino con grep los nombres genéricos de librerías de Windows, que aparecen en cualquier programa. Me quedo con lo único: el nombre del ransomware, la extensión, el nombre de la nota y el comando de borrado de instantáneas. Con guion el busco cadenas en UTF dieciséis, el formato ancho de Windows. Esas cadenas serán mi regla.', step: [1, 4] },
    { t: 'term', title: 'Probar la regla: positivos y negativos', note: 'Debe detectar la muestra y NO detectar software legítimo', prompt: 'analista@lab:~$', lines: `
$ yara -s nightlocker.yar a.exe
!Ransom_NightLocker_Demo a.exe
0x1a20:$note: N\\x00I\\x00G\\x00H\\x00T…
$ yara -r nightlocker.yar ~/goodware/ 2>/dev/null | wc -l       # 4.000 binarios legítimos
+0
$ yara -r nightlocker.yar ~/muestras_familia/ | wc -l          # 12 variantes conocidas
+12`, say: 'Paso dos: probar la regla. Contra la muestra: detecta, y guion s muestra qué cadena coincidió y en qué posición. Contra una carpeta con cuatro mil binarios legítimos: cero coincidencias, sin falsos positivos. Contra doce variantes conocidas de la misma familia: detecta las doce. Las tres pruebas son necesarias: una regla que solo detecta la muestra exacta no aporta mucho; una que salta con software legítimo es peor que no tener regla.', step: [2, 4] },
    { t: 'term', title: 'Validar y convertir una regla Sigma', note: 'sigma check → sigma convert → pegar en el SIEM', prompt: 'analista@lab:~$', lines: `
$ sigma check rules/vssadmin_delete_shadows.yml
+Found 0 errors, 0 condition errors and 0 issues.
$ sigma convert -t splunk -p sysmon rules/vssadmin_delete_shadows.yml
~EventID=1 Image="*\\vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*"
$ sigma convert -t kusto -p microsoft_xdr rules/vssadmin_delete_shadows.yml
~DeviceProcessEvents | where FolderPath endswith "\\vssadmin.exe" and ProcessCommandLine contains "delete" and ProcessCommandLine contains "shadows"`, say: 'Paso tres: Sigma. Para el comportamiento, borrar instantáneas de volumen, escribo una regla Sigma. sigma check valida que el YAML y la condición son correctos: cero errores. Después la convierto a Splunk con el pipeline de Sysmon, y a KQL de Defender con el pipeline correspondiente. Copio el resultado y lo pego en cada SIEM. La misma lógica, dos herramientas, sin reescribir nada.', step: [3, 4] },
    { t: 'code', title: 'Pipeline de CI para las reglas', note: 'Cada pull request se valida automáticamente', file: '.github/workflows/detections.yml', code: `name: detections
on: [pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install sigma-cli pySigma-backend-splunk && sigma plugin install sysmon
      - run: sigma check rules/                                # sintaxis
      - run: sigma convert -t splunk -p sysmon rules/ > out.spl  # ¿convierte?
      - run: yara -r yara/ tests/goodware/ | tee fp.txt && test ! -s fp.txt   # 0 falsos positivos`, hl: [9, 11], say: 'Paso cuatro: automatizar la calidad. En el repositorio de detecciones creo un flujo de integración continua que se ejecuta en cada pull request. Instala las herramientas, valida la sintaxis de todas las reglas Sigma, comprueba que se convierten, y pasa las reglas YARA por la carpeta de software legítimo: si hay alguna coincidencia, el fichero de salida no estará vacío y el flujo fallará, bloqueando la fusión. Así nadie puede desplegar una regla rota o ruidosa.', step: [4, 4] }
  ],
  soar: [
    { t: 'term', title: 'Levantar TheHive y Cortex con Docker', note: 'Laboratorio local con docker compose', prompt: 'alumno@lab:~/soar$', lines: `
$ git clone https://github.com/StrangeBeeCorp/docker.git thehive-docker && cd thehive-docker/prod1-thehive
$ docker compose up -d
+ ✔ Container cassandra  Started   ✔ elasticsearch  Started
+ ✔ Container thehive    Started   ✔ cortex         Started
$ docker compose ps --format "table {{.Name}}\\t{{.Status}}"
thehive   Up 2 minutes (healthy)
cortex    Up 2 minutes (healthy)
# TheHive → http://localhost:9000  ·  Cortex → http://localhost:9001`, say: 'Laboratorio guiado de SOAR. Paso uno: levantar TheHive y Cortex con Docker. Clono el repositorio oficial de despliegues de StrangeBee, entro en el perfil de una sola máquina y ejecuto docker compose up guion d. Se arrancan la base de datos, el motor de búsqueda, TheHive y Cortex. Con docker compose ps compruebo que todos están healthy. TheHive queda en el puerto nueve mil y Cortex en el nueve mil uno. Necesitarás unos ocho gigas de memoria.', step: [1, 4] },
    { t: 'bul', title: 'Crear una plantilla de caso y un caso', note: 'Organisation → Case templates → ＋', items: ['Plantilla **Phishing**: tareas *Triaje*, *Enriquecer*, *Purga*, *Bloqueo*, *Usuario*, *Cierre*', 'Campos personalizados: `usuarios_afectados`, `clic_en_enlace (sí/no)`', '**＋ New Case → From template: Phishing** · Severidad *Media* · TLP:AMBER', 'Añadir observables: `domain empresa-pagos.example`, `ip 203.0.113.88`, `mail factura@…`', 'Marcar **IOC** ✔ en los confirmados'], say: 'Paso dos: estandarizar con plantillas. En la organización creo una plantilla de phishing con seis tareas, que son los pasos que nadie debe saltarse, y dos campos personalizados. Creo un caso desde la plantilla, con severidad media y TLP ámbar, y añado los observables: el dominio, la IP y el remitente. Los confirmados los marco como IOC, lo que permitirá compartirlos con MISP al cerrar.', step: [2, 4] },
    { t: 'table', title: 'Enriquecer con Cortex desde el caso', note: 'Observable → Run analyzers → leer los informes', mono: true, head: ['Observable', 'Analizador', 'Resultado'], rows: [['empresa-pagos.example', 'URLscan_io_Scan', 'Página clonada del portal de pagos · formulario de credenciales'], ['empresa-pagos.example', 'Whois', 'Creado hace 2 días'], ['203.0.113.88', 'AbuseIPDB', '93 % confianza de abuso · 41 reportes'], ['203.0.113.88', 'MISP_2_1', 'Coincide con evento 4182 (otra organización)'], ['factura@proveedor-falso.example', 'EmailRep', 'Dominio sin historial · SPF fail']], hl: [0, 3], say: 'Paso tres: enriquecer. Selecciono los observables y pulso Run analyzers. Cortex ejecuta los analizadores configurados y adjunta los informes al caso. URLscan muestra que la página es un clon del portal de pagos con un formulario de credenciales. WHOIS confirma que el dominio es nuevo. AbuseIPDB marca la IP como abusiva. Y MISP indica que otra organización ya reportó esta campaña. Con eso, en dos minutos y sin salir del caso, el phishing queda confirmado.', step: [3, 4] },
    { t: 'flow', title: 'Automatizar el flujo con Shuffle', note: 'Webhook → TheHive → Cortex → decisión → acción', nodes: [{ id: 'a', x: 120, y: 250, label: 'Webhook', sub: 'buzón de phishing', icon: '📥' }, { id: 'b', x: 330, y: 250, label: 'TheHive: crear caso', sub: 'plantilla Phishing', icon: '🐝', s: 1 }, { id: 'c', x: 550, y: 250, label: 'Cortex: analizar', sub: 'todos los observables', icon: '🧪', s: 2 }, { id: 'd', x: 780, y: 130, label: 'Si malicioso', sub: 'bloquear DNS + purgar', icon: '⛔', c: '#ef4444', s: 3 }, { id: 'e', x: 780, y: 370, label: 'Si dudoso', sub: 'asignar a L1', icon: '👩‍💻', c: '#f59e0b', s: 3 }, { id: 'f', x: 1000, y: 250, label: 'Responder al usuario', sub: 'correo automático', icon: '💬', c: '#10b981', s: 4 }], edges: [['a', 'b'], ['b', 'c'], ['c', 'd', 'score≥80'], ['c', 'e'], ['d', 'f'], ['e', 'f']], say: 'Paso cuatro: automatizar lo que acabamos de hacer a mano. En Shuffle, que también se despliega con Docker, creo un flujo: un webhook recibe los correos reportados, crea el caso en TheHive con la plantilla, lanza los analizadores de Cortex y evalúa la puntuación. Si es claramente malicioso, bloquea el dominio y purga el correo; si es dudoso, lo asigna a un analista. En ambos casos responde al usuario. Lo pruebo primero con correos de ejemplo y con las acciones de bloqueo en modo simulación.', step: [4, 4] }
  ],
  cloud: [
    { t: 'term', title: 'Auditar tu cuenta con Prowler (solo lectura)', note: 'Rol SecurityAudit + ViewOnlyAccess, nunca administrador', prompt: 'alumno@lab:~$', lines: `
$ aws sts get-caller-identity --query Arn --output text
arn:aws:sts::111122223333:assumed-role/AuditoriaSoloLectura/alumno
$ prowler aws --list-compliance | grep -i cis
cis_3.0_aws
$ prowler aws --compliance cis_3.0_aws -M html csv
!FAIL  iam_root_mfa_enabled
!FAIL  s3_bucket_level_public_access_block
+PASS  cloudtrail_multi_region_enabled
Results: 212 PASS · 19 FAIL → output/prowler-output-111122223333.html`, say: 'Laboratorio guiado de postura cloud. Paso uno: auditar tu cuenta de laboratorio con Prowler. Primero compruebo con quién estoy autenticado: un rol de solo lectura para auditoría, nunca un administrador. Listo los marcos de cumplimiento disponibles y lanzo el de CIS tres punto cero, pidiendo salida en HTML y CSV. Prowler revisa cientos de controles y genera un informe con cada fallo, su severidad y cómo corregirlo.', step: [1, 4] },
    { t: 'term', title: 'Corregir los dos fallos críticos', note: 'Bloqueo de acceso público y MFA en root', prompt: 'alumno@lab:~$', lines: `
# 1) Bloquear acceso público de S3 para TODA la cuenta
$ aws s3control put-public-access-block --account-id 111122223333 \\
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
$ aws s3control get-public-access-block --account-id 111122223333 --query PublicAccessBlockConfiguration
+{ "BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": true, "RestrictPublicBuckets": true }
# 2) MFA de root: solo desde la consola con el usuario raíz (Security credentials → Assign MFA device)`, say: 'Paso dos: corregir lo crítico. El primer fallo, buckets que pueden hacerse públicos: con s3control put public access block activo los cuatro bloqueos para toda la cuenta, y lo verifico con get. Ahora ningún bucket puede ser público aunque alguien se equivoque. El segundo, el MFA de la cuenta raíz, solo se puede configurar desde la consola entrando con el usuario raíz, en Security credentials, asignando preferiblemente una llave física.', step: [2, 4] },
    { t: 'code', title: 'Prevenir con un guardarraíl (SCP)', note: 'Que nadie pueda apagar los logs, ni siquiera un admin', file: 'scp-proteger-logs.json', code: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenegarApagarAuditoria",
    "Effect": "Deny",
    "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
               "guardduty:DeleteDetector", "config:StopConfigurationRecorder"],
    "Resource": "*",
    "Condition": { "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlass-Seguridad" } }
  }]
}`, hl: [5, 6, 9], say: 'Paso tres: prevenir con un guardarraíl. Una política de control de servicio de Organizations se aplica por encima de todos los permisos de la cuenta. Esta deniega parar o borrar CloudTrail, borrar GuardDuty o detener Config, para cualquiera excepto un rol de emergencia del equipo de seguridad. Aunque un atacante consiga credenciales de administrador, no podrá apagar los logs para ocultarse, como vimos en el caso de la clave filtrada.', step: [3, 4] },
    { t: 'term', title: 'Re-auditar y medir la mejora', note: 'Mismo comando, comparar resultados', prompt: 'alumno@lab:~$', lines: `
$ prowler aws --compliance cis_3.0_aws -M csv --output-filename despues
$ for f in output/*antes*.csv output/*despues*.csv; do echo "$f: $(grep -c ';FAIL;' $f) FAIL"; done
output/antes.csv: 19 FAIL
+output/despues.csv: 11 FAIL
# Pendientes: 6 de IAM (rotación de claves) → ticket a Plataforma con fecha`, say: 'Paso cuatro: medir. Repito exactamente el mismo análisis con otro nombre de fichero y cuento los fallos de cada uno con grep guion c. Pasamos de diecinueve a once. Los pendientes, como la rotación de claves de acceso, se convierten en tickets con responsable y fecha. Repetir esta auditoría cada mes y mostrar la tendencia es una de las tareas habituales de un ingeniero de seguridad cloud.', step: [4, 4] }
  ],
  aws: [
    { t: 'term', title: 'Activar GuardDuty y generar hallazgos de ejemplo', note: 'Los "sample findings" son seguros: no hay ataque real', prompt: 'alumno@lab:~$', lines: `
$ aws guardduty create-detector --enable --region eu-west-1
{ "DetectorId": "12abc34d567e8fa901bc2d34e56789f0" }
$ aws guardduty create-sample-findings --detector-id 12abc34d567e8fa901bc2d34e56789f0
$ aws guardduty list-findings --detector-id 12abc34d567e8fa901bc2d34e56789f0 --query 'length(FindingIds)'
+371`, say: 'Laboratorio guiado de AWS. Paso uno: activar GuardDuty en la región y generar hallazgos de ejemplo. create detector lo activa y devuelve su identificador. create sample findings crea hallazgos ficticios de todos los tipos, sin ningún ataque real, ideales para practicar. list findings con una consulta JMESPath que cuenta la longitud de la lista: trescientos setenta y un hallazgos para explorar.', step: [1, 4] },
    { t: 'term', title: 'Filtrar y leer un hallazgo', note: 'Criterio de filtro por severidad y tipo', prompt: 'alumno@lab:~$', lines: `
$ D=12abc34d567e8fa901bc2d34e56789f0
$ aws guardduty list-findings --detector-id $D --finding-criteria '{"Criterion":{"severity":{"Gte":7},"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]}}}' --query 'FindingIds[0]' --output text
3ec1b2…
$ aws guardduty get-findings --detector-id $D --finding-ids 3ec1b2… --query 'Findings[0].{t:Type,sev:Severity,user:Resource.AccessKeyDetails.UserName,key:Resource.AccessKeyDetails.AccessKeyId,ip:Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4}'
!{ "t": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", "sev": 8, "user": "GeneratedFindingUserName", "key": "GeneratedFindingAccessKeyId", "ip": "198.51.100.0" }`, say: 'Paso dos: filtrar lo importante. Guardo el identificador del detector en una variable. Con finding criteria pido solo severidad mayor o igual a siete y un tipo concreto: credenciales de una instancia usadas desde fuera de AWS. Tomo el primer identificador y con get findings extraigo, gracias a query, solo cinco campos: tipo, severidad, usuario, clave de acceso e IP remota. Así se lee un hallazgo sin perderse en un JSON de cien líneas.', step: [2, 4] },
    { t: 'code', title: 'Investigar en CloudTrail con Athena', note: 'Crear la tabla una vez; luego consultar con SQL', file: 'Athena · consultas', code: `-- (Una vez) Athena → CloudTrail console → "Create Athena table" sobre el bucket de logs

-- 1) Todas las acciones de la clave en las últimas 24 h
SELECT eventtime, eventname, awsregion, sourceipaddress, errorcode
FROM cloudtrail_logs_org
WHERE useridentity.accesskeyid = 'AKIAEXAMPLEKEY000001'
  AND from_iso8601_timestamp(eventtime) > now() - interval '1' day
ORDER BY eventtime;

-- 2) ¿Qué se creó? (persistencia y recursos)
SELECT eventname, count(*) FROM cloudtrail_logs_org
WHERE useridentity.accesskeyid = 'AKIAEXAMPLEKEY000001'
  AND (eventname LIKE 'Create%' OR eventname LIKE 'Run%' OR eventname LIKE 'Attach%')
GROUP BY eventname;`, hl: [5, 13], say: 'Paso tres: investigar con Athena. Una sola vez, desde la consola de CloudTrail, creo la tabla de Athena sobre el bucket de logs. Después, la primera consulta lista todas las acciones de la clave sospechosa en el último día, con región, IP y errores. La segunda agrupa solo lo que crea cosas: eventos que empiezan por Create, Run o Attach. Así respondo rápidamente a la pregunta más importante: ¿qué dejó el atacante en mi cuenta?', step: [3, 4] },
    { t: 'code', title: 'Automatizar la contención con EventBridge', note: 'Hallazgo grave → Lambda desactiva la clave → aviso', file: 'eventbridge-rule.json + lambda (resumen)', code: `// Regla EventBridge
{ "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": { "severity": [{ "numeric": [">=", 7] }],
              "type": [{ "prefix": "UnauthorizedAccess:IAMUser" }] } }

# Lambda (Python, boto3) — rol con iam:UpdateAccessKey y sns:Publish únicamente
def handler(event, _):
    d = event["detail"]["resource"]["accessKeyDetails"]
    iam.update_access_key(UserName=d["userName"], AccessKeyId=d["accessKeyId"], Status="Inactive")
    sns.publish(TopicArn=TOPIC, Subject="Clave desactivada automáticamente",
                Message=f'{d["accessKeyId"]} ({d["userName"]}) · hallazgo {event["detail"]["type"]}')`, hl: [4, 11], say: 'Paso cuatro: automatizar la contención. Una regla de EventBridge escucha los hallazgos de GuardDuty con severidad mayor o igual a siete y cuyo tipo empieza por acceso no autorizado de usuario IAM. Cuando llega uno, invoca una función Lambda en Python que desactiva la clave afectada y publica un aviso al equipo. Su rol solo tiene los dos permisos que necesita: mínimo privilegio también para la automatización. Lo pruebo con los hallazgos de ejemplo antes de activarlo.', step: [4, 4] }
  ],
  azure: [
    { t: 'bul', title: 'Crear la política de acceso condicional en modo informe', note: 'Entra ID → Protection → Conditional Access → New policy', items: ['Nombre: **CA03 - Bloquear autenticación heredada**', 'Users: *All users* · Exclude: **cuentas de emergencia** (grupo `CA-Excluidos-BreakGlass`)', 'Target resources: *All cloud apps*', 'Conditions → Client apps: **Exchange ActiveSync** + **Other clients**', 'Grant: **Block access**', 'Enable policy: **Report-only** (¡no "On" todavía!)'], say: 'Laboratorio guiado de Entra ID. Paso uno: crear una política de acceso condicional. En Protection, Conditional Access, New policy. La llamo CA cero tres, bloquear autenticación heredada. Aplica a todos los usuarios, excluyendo el grupo de cuentas de emergencia. Afecta a todas las aplicaciones. En condiciones, tipos de cliente, marco Exchange ActiveSync y otros clientes, que son los protocolos antiguos. Concesión: bloquear. Y muy importante: la activo en modo solo informe, no en modo activado.', step: [1, 4] },
    { t: 'code', title: 'Medir el impacto antes de activarla', note: 'Ver quién habría sido bloqueado', file: 'Log Analytics · KQL', code: `SigninLogs
| where TimeGenerated > ago(7d)
| mv-expand CAP = ConditionalAccessPolicies
| where tostring(CAP.displayName) == "CA03 - Bloquear autenticación heredada"
| where tostring(CAP.result) == "reportOnlyFailure"
| summarize Intentos=count(), IPs=dcount(IPAddress) by UserPrincipalName, ClientAppUsed
| sort by Intentos desc
// impresora-escaner@  · SMTP    · 3.110 intentos · 1 IP interna   ← legítimo: migrar a OAuth/relay
// rgarcia@            · IMAP    ·   902 intentos · 37 IPs externas ← ataque (spraying)`, hl: [3, 5, 8, 9], say: 'Paso dos: medir el impacto. Tras una semana en modo informe, consulto los inicios de sesión. mv expand separa cada política aplicada en su propia fila. Filtro por mi política y por el resultado reportOnlyFailure, es decir, los que habría bloqueado. Agrupo por usuario y tipo de cliente. Aparecen dos casos: una impresora multifunción que envía correo por SMTP heredado, que es legítima y hay que migrar antes de activar; y una cuenta con novecientos intentos por IMAP desde treinta y siete IPs externas: un ataque que la política habría frenado.', step: [2, 4] },
    { t: 'term', title: 'Revisar consentimientos de aplicaciones existentes', note: 'Microsoft Graph PowerShell: permisos delegados de riesgo', prompt: 'PS C:\\Admin>', lines: `
$ Connect-MgGraph -Scopes "Directory.Read.All" -NoWelcome
$ Get-MgOauth2PermissionGrant -All | Where-Object { $_.Scope -match "Mail\\.(Read|Send)|Files\\.ReadWrite\\.All" } |
    Select-Object ClientId, ConsentType, PrincipalId, Scope | Format-Table -AutoSize
ClientId   ConsentType   PrincipalId  Scope
6a1f…      AllPrincipals              User.Read Mail.Read                  (Outlook add-in corporativo ✔)
!5f1c…      Principal     b3e9…        User.Read Mail.Read Mail.Send offline_access
$ (Get-MgServicePrincipal -ServicePrincipalId 5f1c…).DisplayName
!DocViewer Pro`, say: 'Paso tres: revisar los consentimientos que ya existen. Me conecto a Microsoft Graph con permisos de solo lectura. Obtengo todos los permisos delegados y filtro con una expresión regular los de riesgo: leer o enviar correo y escribir en todos los ficheros. Aparecen dos: un complemento corporativo aprobado para todos, y otro concedido por un único usuario con permiso para enviar correo y acceso sin conexión. Consulto el nombre de esa aplicación: DocViewer Pro, la del caso. Así se buscan aplicaciones maliciosas de forma proactiva.', step: [3, 4] },
    { t: 'term', title: 'Contener y endurecer', note: 'Eliminar la app, revocar sesiones y restringir consentimientos', prompt: 'PS C:\\Admin>', lines: `
$ Connect-MgGraph -Scopes "Application.ReadWrite.All","User.RevokeSessions.All","Policy.ReadWrite.Authorization"
$ Remove-MgServicePrincipal -ServicePrincipalId 5f1c…
$ Revoke-MgUserSignInSession -UserId ana.ruiz@empresa.example
+True
# Solo permitir consentimiento a editores verificados y permisos de bajo riesgo:
$ Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ PermissionGrantPoliciesAssigned = @("ManagePermissionGrantsForSelf.microsoft-user-default-low") }
# Activar flujo de "solicitud de consentimiento de administrador" en el portal`, say: 'Paso cuatro: contener y endurecer. Me conecto con los permisos necesarios para escribir. Elimino la entidad de servicio de la aplicación maliciosa, lo que invalida su acceso. Revoco las sesiones de la usuaria. Y, para que no se repita, actualizo la política de autorización: los usuarios solo podrán consentir permisos de bajo riesgo a editores verificados. Para lo demás, activo el flujo de solicitud de aprobación al administrador. Todo queda registrado en los AuditLogs para el informe.', step: [4, 4] }
  ],
  k8s: [
    { t: 'term', title: 'Crear un clúster local de laboratorio', note: 'kind: Kubernetes dentro de Docker', prompt: 'alumno@lab:~$', lines: `
$ kind create cluster --name lab
+✓ Ensuring node image (kindest/node:v1.31.x) · ✓ Preparing nodes · ✓ Starting control-plane
$ kubectl get nodes
NAME                STATUS   ROLES           AGE   VERSION
lab-control-plane   Ready    control-plane   42s   v1.31.x
$ kubectl create namespace tienda && kubectl -n tienda create deployment web --image=nginx:1.27`, say: 'Laboratorio guiado de Kubernetes. Paso uno: un clúster local con kind, que ejecuta Kubernetes dentro de Docker. kind create cluster con un nombre, y en menos de un minuto tengo un nodo listo, como confirma kubectl get nodes. Creo un espacio de nombres tienda y un despliegue de nginx, que va a ser nuestro paciente para el resto del laboratorio.', step: [1, 4] },
    { t: 'term', title: 'Escanear la imagen y la configuración', note: 'Trivy para la imagen; kubescape para los recursos', prompt: 'alumno@lab:~$', lines: `
$ trivy image --severity HIGH,CRITICAL --ignore-unfixed nginx:1.27 | tail -3
!Total: 4 (HIGH: 3, CRITICAL: 1)
$ kubescape scan workload Deployment/web --namespace tienda
!C-0013 Non-root containers                 failed
!C-0017 Immutable container filesystem      failed
!C-0055 Linux hardening (seccomp/capabilities) failed
!C-0260 Missing network policy              failed`, say: 'Paso dos: escanear. Con trivy image y la opción ignore unfixed, que oculta vulnerabilidades sin parche disponible para centrarnos en lo accionable, la imagen tiene una crítica y tres altas. Con kubescape scan workload analizo el despliegue: falla en ejecutar como usuario no root, en sistema de ficheros inmutable, en endurecimiento de Linux y en no tener política de red. Ya tengo mi lista de tareas.', step: [2, 4] },
    { t: 'code', title: 'Aplicar el endurecimiento', note: 'Imagen sin root + securityContext + NetworkPolicy', file: 'web-hardened.yaml (fragmento)', code: `      containers:
      - name: web
        image: nginxinc/nginx-unprivileged:1.27-alpine   # escucha en 8080 sin root
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: { drop: ["ALL"] }
          seccompProfile: { type: RuntimeDefault }
        volumeMounts: [{ name: tmp, mountPath: /tmp }]   # nginx necesita escribir aquí
      volumes: [{ name: tmp, emptyDir: {} }]
# + NetworkPolicy default-deny y allow-frontend (ver módulo)
# kubectl apply -f web-hardened.yaml && kubescape scan workload Deployment/web -n tienda → 0 failed`, hl: [3, 7, 10], say: 'Paso tres: corregir. Cambio a la variante sin privilegios de nginx, que escucha en el puerto ocho mil ochenta sin necesitar root, y basada en alpine, con menos paquetes. Añado el contexto de seguridad completo. Como el sistema de ficheros es de solo lectura y nginx necesita escribir en barra tmp, monto ahí un volumen temporal emptyDir: este es el tipo de detalle práctico que aprendes haciendo. Aplico, añado las políticas de red y repito kubescape: cero fallos.', step: [3, 4] },
    { t: 'term', title: 'Instalar Falco y comprobar una detección', note: 'Provocar el evento en el laboratorio y verlo en los logs', prompt: 'alumno@lab:~$', lines: `
$ helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
$ helm install falco falcosecurity/falco -n falco --create-namespace --set driver.kind=modern_ebpf
$ kubectl -n tienda exec -it deploy/web -- sh -c 'cat /etc/shadow'   # acción de prueba en TU laboratorio
cat: can't open '/etc/shadow': Permission denied
$ kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=5 | grep -E "Terminal|sensitive"
!Notice A shell was spawned in a container with an attached terminal (pod=web-7d9f ns=tienda)
!Warning Sensitive file opened for reading by non-trusted program (file=/etc/shadow pod=web-7d9f)`, say: 'Paso cuatro: detección en ejecución. Instalo Falco con Helm usando el driver eBPF moderno. Para probarlo, en mi laboratorio abro una shell en el contenedor e intento leer barra etc barra shadow. Como el contenedor ya no es root, la lectura falla: el endurecimiento funciona. Y aun así, en los logs de Falco aparecen dos avisos: una shell con terminal en un contenedor y un intento de leer un fichero sensible. Prevención y detección trabajando juntas: esa es la defensa en profundidad aplicada a Kubernetes.', step: [4, 4] }
  ]
});

/* Inserta cada laboratorio guiado como capítulo antes del repaso final */
(function () {
  (window.VIDEOS || []).forEach(v => {
    const steps = WT[v.id]; if (!steps || v._wt) return; v._wt = true;
    steps.forEach(s => { s.title = String(s.title).replace(/^Paso \d+:\s*/, ''); });
    let i = -1; v.scenes.forEach((s, k) => { if (s.t === 'quiz') i = k; });
    if (i < 0) i = v.scenes.length - 1;
    v.scenes.splice(i, 0, { t: 'title', ch: '🧪 Laboratorio guiado paso a paso', icon: '🧪', kick: 'Laboratorio guiado', title: 'Ahora hazlo conmigo, paso a paso', sub: 'Cada pantalla es un paso: el comando exacto, qué significa cada parte y cómo leer el resultado. Pausa el video y repítelo en tu laboratorio.', say: 'Ahora vamos a practicar juntos, paso a paso. En cada pantalla verás el comando exacto, te explicaré qué significa cada parte y cómo interpretar el resultado. Te recomiendo pausar el video en cada paso y repetirlo en tu propio laboratorio.' }, ...steps);
  });
})();

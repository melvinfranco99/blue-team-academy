VIDEOS.push({
  id: 'yarasigma', n: 20, tool: 'YARA · Sigma', icon: '🧬', color: '#f472b6', level: 'Avanzado',
  title: 'YARA y Sigma: detección como código (Detection Engineering)',
  desc: 'Reglas YARA para ficheros y memoria, reglas Sigma para logs, conversión a Splunk/KQL/Elastic con pySigma, pruebas, ciclo de vida y métricas de detección.',
  scenes: [
    { t: 'title', ch: 'Introducción', icon: '🧬', kick: 'Módulo 20 · Detection Engineering', title: 'YARA y Sigma', sub: 'Escribe una detección una vez y úsala en cualquier herramienta.', say: 'Bienvenido al módulo de ingeniería de detección. Aprenderás los dos estándares abiertos más usados: YARA, para describir ficheros y memoria maliciosos, y Sigma, para describir comportamientos en logs. Su gran ventaja es que las reglas son texto: se comparten, se versionan en Git, se prueban automáticamente y se convierten al lenguaje de cualquier herramienta. Es lo que se conoce como detección como código.' },
    { t: 'cmp', title: '¿YARA o Sigma?', l: { t: '🧬 YARA', c: '#f472b6', items: ['Analiza **ficheros y memoria**', 'Busca cadenas, bytes, estructura PE', 'Uso: triaje de malware, EDR, VirusTotal', 'Pregunta: “¿este fichero es de la familia X?”'] }, r: { t: 'Σ Sigma', c: '#22d3ee', items: ['Analiza **logs** (eventos)', 'Formato YAML independiente del SIEM', 'Se convierte a SPL, KQL, ES|QL…', 'Pregunta: “¿ha ocurrido este comportamiento?”'] }, say: 'Primero, cuándo usar cada uno. YARA analiza ficheros y memoria, buscando cadenas, secuencias de bytes o características de la estructura del ejecutable. Responde a la pregunta: ¿este fichero pertenece a tal familia de malware? Sigma analiza logs y describe un comportamiento en YAML, independiente del SIEM, que después se convierte a SPL, KQL o ES QL. Responde a la pregunta: ¿ha ocurrido este comportamiento en mi red?' },
    { t: 'code', ch: 'YARA', title: 'Anatomía de una regla YARA', file: 'nightlocker.yar', code: `rule Ransom_NightLocker_Demo {
  meta:
    author      = "SOC Blue Team Academy"
    description = "Detecta la muestra de formación NightLocker"
    date        = "2026-11-26"
  strings:
    $note  = "NIGHTLOCKER" ascii wide
    $ext   = ".locked" ascii
    $cmd   = "vssadmin delete shadows" ascii nocase
    $hex   = { 6A 40 68 00 30 00 00 6A 14 }   // patrón de código
  condition:
    uint16(0) == 0x5A4D and filesize < 2MB and
    ( $note or 2 of ($ext, $cmd, $hex) )
}`, hl: [7, 13, 14], say: 'Esta es la anatomía de una regla YARA. La sección meta documenta autor, descripción y fecha. En strings definimos lo que buscamos: la cadena de la nota de rescate en ASCII y en formato ancho, la extensión de los ficheros cifrados, el comando que borra las instantáneas de volumen sin distinguir mayúsculas, y un patrón de bytes en hexadecimal. La condición exige que sea un ejecutable de Windows, comprobando que los dos primeros bytes son MZ, que pese menos de dos megas, y que contenga la nota o al menos dos de los otros indicadores. Combinar condiciones reduce los falsos positivos.' },
    { t: 'term', ch: 'Práctica YARA', title: 'Escanear ficheros y procesos', prompt: 'analista@lab:~$', lines: `
$ yara -r -s nightlocker.yar /evidencias/triage/
!Ransom_NightLocker_Demo /evidencias/triage/Users/Public/a.exe
0x1a20:$note: N\\x00I\\x00G\\x00H\\x00T\\x00L\\x00O\\x00C\\x00K\\x00E\\x00R\\x00
0x2b10:$cmd: vssadmin delete shadows
# Escanear la memoria de un proceso en vivo (requiere privilegios)
$ sudo yara nightlocker.yar 6020
!Ransom_NightLocker_Demo 6020
# Probar contra ficheros legítimos para medir falsos positivos
$ yara -r nightlocker.yar /usr/bin /opt/goodware/ | wc -l
+0`, say: 'Practiquemos. Con guion r escaneamos recursivamente una carpeta de evidencias y con guion s mostramos qué cadenas coincidieron y dónde. La regla detecta el ejecutable en la carpeta Public. También podemos escanear la memoria de un proceso en ejecución indicando su PID. Y un paso que muchos olvidan: probar la regla contra una colección de software legítimo para comprobar que no genera falsos positivos. Cero coincidencias: la regla está lista.' },
    { t: 'code', ch: 'Sigma', title: 'Anatomía de una regla Sigma', file: 'proc_creation_office_spawn_shell.yml', code: `title: Office lanza un intérprete de comandos
id: 6f3c2a1e-0b8d-4c55-9f0a-2d5b7e1a9c44
status: test
description: Detecta Word/Excel/PowerPoint creando PowerShell, cmd o mshta
author: SOC Blue Team Academy
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith: ['\\WINWORD.EXE', '\\EXCEL.EXE', '\\POWERPNT.EXE']
  selection_child:
    Image|endswith: ['\\powershell.exe', '\\cmd.exe', '\\mshta.exe']
  condition: selection_parent and selection_child
falsepositives: ['Complementos de Office legítimos (documentar excepciones)']
level: high
tags: [attack.execution, attack.t1204.002, attack.t1059.001]`, hl: [7, 8, 14], say: 'Ahora Sigma. Una regla tiene título, un identificador único, estado y descripción. La sección logsource indica el tipo de log, aquí creación de procesos en Windows, sin decir qué producto lo genera: puede venir de Sysmon, del evento cuatro mil seiscientos ochenta y ocho o de un EDR. En detection definimos selecciones con modificadores como endswith, y una condición que las combina. Documentamos los falsos positivos conocidos, el nivel de severidad y las etiquetas de MITRE ATT and CK.' },
    { t: 'term', ch: 'Convertir', title: 'Convertir Sigma a cualquier SIEM con pySigma', prompt: 'analista@lab:~$', lines: `
$ pip install sigma-cli && sigma plugin install splunk microsoft365defender elasticsearch
$ sigma convert -t splunk -p sysmon proc_creation_office_spawn_shell.yml
~ParentImage IN ("*\\WINWORD.EXE","*\\EXCEL.EXE","*\\POWERPNT.EXE") Image IN ("*\\powershell.exe","*\\cmd.exe","*\\mshta.exe")
$ sigma convert -t microsoft365defender proc_creation_office_spawn_shell.yml
~DeviceProcessEvents | where (InitiatingProcessFolderPath endswith "\\WINWORD.EXE" or …) and (FolderPath endswith "\\powershell.exe" or …)
$ sigma convert -t lucene -p ecs_windows proc_creation_office_spawn_shell.yml
~process.parent.executable:(*\\\\WINWORD.EXE OR …) AND process.executable:(*\\\\powershell.exe OR …)`, say: 'La magia de Sigma es la conversión. Con sigma cli y sus plugins, la misma regla se traduce a Splunk, a KQL de Defender o a la sintaxis de Elastic. Los pipelines, como sysmon o ecs windows, adaptan los nombres de los campos a cada fuente. Escribes la detección una vez, y si mañana tu empresa cambia de SIEM, tus detecciones viajan contigo. Además, el repositorio SigmaHQ contiene miles de reglas de la comunidad listas para usar.' },
    { t: 'flow', ch: 'Ciclo de vida', title: 'Detección como código: el pipeline', nodes: [{ id: 'a', x: 120, y: 250, label: 'Hipótesis', sub: 'técnica ATT&CK', icon: '💡' }, { id: 'b', x: 320, y: 250, label: 'Regla', sub: 'Sigma en Git', icon: '📝', s: 1 }, { id: 'c', x: 520, y: 250, label: 'Pruebas', sub: 'CI: sintaxis + datos', icon: '🧪', c: '#a78bfa', s: 2 }, { id: 'd', x: 720, y: 250, label: 'Despliegue', sub: 'conversión al SIEM', icon: '🚀', c: '#10b981', s: 3 }, { id: 'e', x: 920, y: 250, label: 'Ajuste', sub: 'métricas y FPs', icon: '📈', c: '#f59e0b', s: 4 }], edges: [['a', 'b'], ['b', 'c', 'pull request'], ['c', 'd'], ['d', 'e'], ['e', 'b', 'mejora', '#f59e0b', 5]], say: 'Así trabaja un equipo de ingeniería de detección. Parte de una hipótesis basada en una técnica de ATT and CK. Escribe la regla en Sigma y la sube a Git mediante una pull request, que otro compañero revisa. Un pipeline de integración continua valida la sintaxis y la prueba contra datos de ataque grabados, por ejemplo generados con Atomic Red Team en un laboratorio. Si pasa, se convierte y se despliega en el SIEM. Después se miden las alertas y los falsos positivos, y se vuelve a ajustar la regla.' },
    { t: 'dash', ch: 'Métricas', app: 'Detection Engineering · panel de calidad', title: 'Medir la calidad de tus detecciones', widgets: [{ k: 'stat', t: 'Reglas en producción', v: '412' }, { k: 'stat', t: 'Cobertura ATT&CK', v: '61', u: '%', c: '#10b981' }, { k: 'stat', t: 'Tasa de verdaderos positivos', v: '38', u: '%', c: '#f59e0b' }, { k: 'stat', t: 'Reglas sin disparar 90 días', v: '57', c: '#ef4444' }, { k: 'hbars', t: 'Reglas más ruidosas (alertas/semana)', w: 2, h: 2, data: [['Login fuera de horario', 640, '#ef4444'], ['PowerShell remoto', 210, '#f59e0b'], ['Nuevo servicio', 95], ['Office → shell', 4, '#10b981']] }, { k: 'donut', t: 'Cobertura por táctica', w: 2, h: 2, data: [['Ejecución', 34, '#22d3ee'], ['Persistencia', 22, '#a78bfa'], ['Acceso a credenciales', 15, '#f472b6'], ['Exfiltración', 6, '#f59e0b'], ['Otras', 23, '#64748b']] }], say: 'Lo que no se mide no mejora. Un panel de calidad muestra cuántas reglas hay en producción, qué porcentaje de técnicas de ATT and CK cubren, la tasa de verdaderos positivos y cuántas reglas no se han disparado en noventa días, que pueden estar rotas porque cambió un log. La lista de reglas más ruidosas indica dónde invertir tiempo de ajuste. Y la cobertura por táctica revela huecos: aquí la exfiltración está poco cubierta, así que será la siguiente prioridad.' },
    { t: 'quiz', ch: 'Repaso', q: 'Quieres detectar en tus logs de Windows que Excel lanza PowerShell, y que funcione igual en Splunk y en Sentinel. ¿Qué usas?', o: ['Una regla YARA', 'Una regla Sigma convertida con pySigma', 'Un escaneo de Nessus', 'Una firma de antivirus'], a: 1, say: 'Pregunta de repaso. Quieres detectar en los logs que Excel lanza PowerShell, y que funcione igual en Splunk y en Sentinel. Usas una regla Sigma convertida con pySigma. YARA serviría para analizar el fichero malicioso, no los logs.' },
    { t: 'title', ch: 'Cierre', icon: '✅', kick: 'Resumen', title: 'Detecciones portables y medibles', sub: 'YARA para ficheros · Sigma para logs · Git + CI para calidad · métricas para mejorar.', say: 'Resumen. YARA describe ficheros y memoria, Sigma describe comportamientos en logs, y ambos se gestionan como código, con revisiones, pruebas y métricas. Empieza adaptando reglas de SigmaHQ a tu entorno y escribe una regla propia cada semana. Hasta el siguiente módulo.' }
  ]
});

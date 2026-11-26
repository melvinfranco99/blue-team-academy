VIDEOS.push({
  id: 'k8s', n: 25, tool: 'Docker · Kubernetes · DevSecOps', icon: '☸️', color: '#326ce5', level: 'Avanzado',
  title: 'Seguridad en contenedores, Kubernetes e infraestructura como código',
  desc: 'Imágenes seguras con Trivy, hardening de pods, RBAC y NetworkPolicies, kube-bench, detección en tiempo de ejecución con Falco y escaneo de Terraform con Checkov en el pipeline.',
  scenes: [
    { t: 'title', ch: 'Introducción', icon: '☸️', kick: 'Módulo 25 · Cloud Security IV', title: 'Contenedores, Kubernetes y DevSecOps', sub: 'Seguridad desde el código hasta el clúster en ejecución.', say: 'Bienvenido al último módulo del bloque de nube: contenedores, Kubernetes e infraestructura como código. Hoy la mayoría de aplicaciones modernas se empaquetan en contenedores y se despliegan en Kubernetes mediante pipelines automatizados. Veremos cómo protegerlas en cada fase: construir imágenes seguras, desplegar con configuraciones endurecidas, detectar comportamientos anómalos en ejecución y revisar la infraestructura antes de crearla.' },
    { t: 'ana', icon: '🚢', title: 'Contenedores: casas prefabricadas en un barco', text: 'La imagen es el plano de la casa; el contenedor, la casa montada; Kubernetes, el capitán que decide dónde va cada una. Si el plano tiene una grieta, todas las casas la tendrán.', say: 'Una analogía. La imagen es el plano de una casa prefabricada, el contenedor es la casa montada, y Kubernetes es el capitán del barco que decide dónde se coloca cada casa, cuántas hay y las sustituye si se rompen. Si el plano tiene una grieta, todas las casas construidas con él la tendrán. Por eso la seguridad empieza en la imagen.' },
    { t: 'flow', ch: 'Ciclo de vida', title: 'Seguridad en cada fase (shift left)', nodes: [{ id: 'a', x: 120, y: 250, label: 'Código', sub: 'secretos, SAST', icon: '💻' }, { id: 'b', x: 320, y: 250, label: 'IaC', sub: 'Checkov, tfsec', icon: '📐', s: 1 }, { id: 'c', x: 520, y: 250, label: 'Imagen', sub: 'Trivy, firma', icon: '📦', c: '#a78bfa', s: 2 }, { id: 'd', x: 720, y: 250, label: 'Despliegue', sub: 'políticas de admisión', icon: '🚪', c: '#f59e0b', s: 3 }, { id: 'e', x: 930, y: 250, label: 'Ejecución', sub: 'Falco, logs de auditoría', icon: '👁️', c: '#ef4444', s: 4 }], edges: [['a', 'b'], ['b', 'c'], ['c', 'd'], ['d', 'e']], say: 'La seguridad se aplica en cada fase, lo que se conoce como desplazar la seguridad a la izquierda. En el código, buscamos secretos y fallos con análisis estático. En la infraestructura como código, revisamos las plantillas de Terraform antes de crear nada. En la imagen, buscamos vulnerabilidades y la firmamos. En el despliegue, una política de admisión rechaza lo que no cumple las normas. Y en ejecución, vigilamos el comportamiento con Falco y los logs de auditoría. Cuanto antes se detecta un problema, más barato es corregirlo.' },
    { t: 'code', ch: 'Imagen segura', title: 'Dockerfile: inseguro frente a endurecido', file: 'Dockerfile', code: `# ❌ Inseguro
FROM python:3.12                 # imagen enorme, cientos de paquetes
COPY . /app                      # copia también .env y .git
RUN pip install -r requirements.txt
CMD ["python", "/app/app.py"]    # se ejecuta como root

# ✅ Endurecido
FROM python:3.12-slim@sha256:3b1c…   # base mínima y fijada por digest
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .                          # solo el código (+ .dockerignore)
USER 10001                           # usuario sin privilegios
HEALTHCHECK CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:8080/health')"
CMD ["python", "app.py"]`, hl: [8, 12, 13], say: 'Comparemos dos Dockerfile. El inseguro parte de una imagen enorme con cientos de paquetes, cada uno con posibles vulnerabilidades; copia todo el directorio, incluidos ficheros de secretos y el historial de Git; y se ejecuta como root. El endurecido usa una imagen base mínima, fijada por su resumen criptográfico para que no cambie sin control, copia solo lo necesario con ayuda de un fichero dockerignore, se ejecuta con un usuario sin privilegios e incluye una comprobación de salud.' },
    { t: 'term', ch: 'Práctica: Trivy', title: 'Escanear la imagen con Trivy', prompt: 'dev@ci:~$', lines: `
$ trivy image --severity HIGH,CRITICAL tienda-web:1.4.0
tienda-web:1.4.0 (debian 12.7)
Total: 23 (HIGH: 17, CRITICAL: 6)
!│ openssl   │ CVE-2024-XXXX │ CRITICAL │ 3.0.11-1 │ 3.0.15-1 (fixed)
!│ libexpat1 │ CVE-2024-YYYY │ CRITICAL │ 2.5.0-1  │ 2.5.0-1+deb12u1
Python (requirements.txt)
!│ jinja2    │ CVE-2024-ZZZZ │ HIGH     │ 3.1.2    │ 3.1.4
# Tras cambiar a la base -slim y actualizar dependencias:
$ trivy image --severity HIGH,CRITICAL --exit-code 1 tienda-web:1.4.1
+Total: 0 (HIGH: 0, CRITICAL: 0)`, say: 'Trivy es el escáner open source más popular para contenedores. Analiza los paquetes del sistema operativo de la imagen y las dependencias de la aplicación, y muestra cada vulnerabilidad con su severidad, la versión instalada y la versión que la corrige. Aquí hay veintitrés altas y críticas. Tras cambiar a la imagen base mínima y actualizar las dependencias, el escaneo queda limpio. La opción exit code uno hace que el pipeline falle si aparece alguna crítica, impidiendo que llegue a producción.' },
    { t: 'code', ch: 'Pods endurecidos', title: 'Un pod endurecido en Kubernetes', file: 'deployment.yaml (fragmento)', code: `spec:
  serviceAccountName: tienda-web        # cuenta propia, permisos mínimos
  automountServiceAccountToken: false   # no montar token si no se usa
  containers:
  - name: web
    image: registry.empresa.local/tienda-web@sha256:9a7e…
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
      seccompProfile: { type: RuntimeDefault }
    resources:
      limits: { cpu: "500m", memory: "256Mi" }`, hl: [3, 8, 11], say: 'Así se configura un pod endurecido. Usa una cuenta de servicio propia y no monta su token si la aplicación no habla con la API de Kubernetes, porque ese token es lo primero que buscaría un atacante dentro del contenedor. La imagen se referencia por su resumen. El contexto de seguridad impide ejecutar como root y escalar privilegios, hace el sistema de ficheros de solo lectura, elimina todas las capacidades del kernel y aplica el perfil seccomp por defecto. Los límites de recursos evitan que un contenedor comprometido consuma todo el nodo, por ejemplo minando criptomonedas.' },
    { t: 'code', ch: 'Red y RBAC', title: 'NetworkPolicy: denegar por defecto', file: 'netpol.yaml', code: `# 1) Denegar todo el tráfico entrante del namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny, namespace: tienda }
spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"] }
---
# 2) Permitir solo frontend → web:8080
kind: NetworkPolicy
metadata: { name: allow-frontend, namespace: tienda }
spec:
  podSelector: { matchLabels: { app: web } }
  ingress:
  - from: [ { podSelector: { matchLabels: { app: frontend } } } ]
    ports: [ { port: 8080 } ]`, hl: [5, 13], say: 'Por defecto, en Kubernetes todos los pods pueden hablar con todos, lo que facilita el movimiento lateral. Con NetworkPolicies aplicamos el principio de denegar por defecto: una primera política bloquea todo el tráfico de entrada y salida del espacio de nombres, y después se permite explícitamente solo lo necesario, como el frontend hablando con la aplicación web en el puerto ocho mil ochenta. Junto con un RBAC de mínimo privilegio, sin conceder cluster admin a nadie que no lo necesite, reducimos drásticamente el radio de impacto.' },
    { t: 'term', ch: 'Práctica: auditoría', title: 'kube-bench y kubescape: auditar el clúster', prompt: 'admin@k8s:~$', lines: `
$ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
$ kubectl logs job/kube-bench | grep -E "FAIL|WARN" | head -4
![FAIL] 1.2.16 Ensure that the --profiling argument is set to false
![FAIL] 4.2.1 Ensure that the --anonymous-auth argument is set to false
[WARN] 5.1.5 Ensure that default service accounts are not actively used
[WARN] 5.2.2 Minimize the admission of privileged containers
$ kubescape scan framework nsa --exclude-namespaces kube-system
!Controls: 26 · Failed: 9 · Compliance score: 68%
!  privileged container: tienda/legacy-batch
!  hostPath mount: monitoring/node-exporter (revisar)`, say: 'Para auditar el clúster usamos kube bench, que comprueba la configuración del clúster contra el benchmark CIS de Kubernetes. Se ejecuta como un job y aquí detecta, por ejemplo, la autenticación anónima del kubelet activada. Kubescape evalúa los recursos desplegados contra marcos como la guía de endurecimiento de la NSA y CISA, y señala un contenedor privilegiado y un montaje de directorios del nodo que hay que revisar. Cada fallo viene con su explicación y su corrección.' },
    { t: 'code', ch: 'Falco', title: 'Falco: detección en tiempo de ejecución', file: 'falco_rules.local.yaml', code: `- rule: Shell interactiva en contenedor de producción
  desc: Alguien abrió una shell dentro de un contenedor
  condition: >
    spawned_process and container and proc.name in (bash, sh, zsh)
    and proc.tty != 0 and k8s.ns.name = "tienda"
  output: >
    Shell en contenedor (user=%user.name pod=%k8s.pod.name
    ns=%k8s.ns.name cmd=%proc.cmdline image=%container.image.repository)
  priority: WARNING
  tags: [container, mitre_execution, T1059]`, hl: [4, 5], say: 'Falco, un proyecto de la CNCF, vigila en tiempo de ejecución las llamadas al sistema de los contenedores, usando eBPF. Esta regla detecta una shell interactiva abierta dentro de un contenedor del espacio de nombres de producción. En producción nadie debería entrar a mano en un contenedor, así que esto indica un error operativo o un atacante. La salida incluye el usuario, el pod, el comando y la imagen. Falco trae de serie reglas para lecturas de ficheros sensibles, conexiones inesperadas o escrituras en directorios del sistema.' },
    { t: 'alerts', ch: 'Alertas', title: 'Alertas reales de Falco en el SIEM', win: 'falco → falcosidekick → SIEM', items: [{ sv: 'high', ts: '11:02:13', msg: 'Shell en contenedor pod=web-7d9f ns=tienda cmd=sh -i', ip: 'web-7d9f' }, { sv: 'crit', ts: '11:02:41', msg: 'Lectura de token de service account desde proceso no esperado', ip: 'web-7d9f' }, { sv: 'high', ts: '11:03:05', msg: 'Conexión saliente a puerto 3333 (stratum, minería)', ip: '198.51.100.31' }, { sv: 'med', ts: '11:03:30', msg: 'Escritura en /usr/bin dentro de contenedor', ip: 'web-7d9f' }], say: 'Así llegan las alertas de Falco al SIEM mediante Falcosidekick. La secuencia cuenta una historia: una shell dentro del pod web, la lectura del token de la cuenta de servicio, que permitiría hablar con la API del clúster, una conexión saliente a un puerto típico de minería y escrituras en directorios del sistema. Respuesta: aislar el pod con una NetworkPolicy, capturar evidencias, revocar el token, revisar los logs de auditoría del API server para ver si se usó, y redesplegar desde una imagen limpia.' },
    { t: 'term', ch: 'IaC', title: 'Revisar Terraform con Checkov antes de desplegar', prompt: 'dev@ci:~$', lines: `
$ checkov -d infra/ --compact --quiet
!Check: CKV_AWS_20: "S3 Bucket has an ACL defined which allows public READ access."
!        FAILED for resource: aws_s3_bucket.backup_clientes   File: /s3.tf:12
!Check: CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
!        FAILED for resource: aws_security_group.bastion      File: /sg.tf:3
Passed checks: 118, Failed checks: 2, Skipped checks: 1
# En el pipeline: el merge se bloquea hasta corregir (o justificar la excepción)`, say: 'Por último, la infraestructura como código. Checkov analiza plantillas de Terraform, CloudFormation, Kubernetes o Dockerfiles antes de crear nada. Aquí detecta un bucket con lectura pública y un grupo de seguridad con SSH abierto a Internet, los mismos errores que veíamos en el panel de postura, pero detectados antes de existir. Integrado en el pipeline, bloquea la fusión del código hasta que se corrija o se documente una excepción justificada. Es la forma más barata de evitar errores de configuración.' },
    { t: 'quiz', ch: 'Repaso', q: '¿Qué herramienta usarías para detectar en tiempo real que alguien abre una shell dentro de un contenedor de producción?', o: ['Trivy', 'Checkov', 'Falco', 'kube-bench'], a: 2, say: 'Pregunta de repaso. ¿Qué herramienta detecta en tiempo real una shell dentro de un contenedor en producción? Falco. Trivy escanea imágenes, Checkov revisa infraestructura como código y kube bench audita la configuración del clúster.' },
    { t: 'title', ch: 'Cierre', icon: '✅', kick: 'Resumen', title: 'De la línea de código al clúster', sub: 'Checkov para IaC · Trivy para imágenes · pods endurecidos · NetworkPolicies · Falco en ejecución.', say: 'Resumen. Revisa la infraestructura con Checkov, escanea imágenes con Trivy, despliega pods endurecidos con mínimo privilegio y políticas de red, audita el clúster con kube bench y kubescape, y vigila la ejecución con Falco. Con esto completas el bloque de nube. Practica en un clúster local con kind o minikube, y repasa los demás videos de la academia.' }
  ]
});

# Gestión de un incidente de ciberseguridad
**Phishing con malware y posible fuga de datos personales en una empresa de 100 empleados**

- **Autor/a:** _Tu nombre y apellidos_
- **Módulo / Curso:** Ciberseguridad
- **Rol:** Responsable del equipo de ciberseguridad
- **Fecha:** 17 de noviembre de 2026

> Escenario simulado. Las pruebas prácticas se han realizado exclusivamente en equipos y entornos autorizados.
> Las IP y dominios del caso son ficticios o están reservados para documentación (RFC 5737).

## Caso
Varios empleados reciben un correo que simula proceder de Recursos Humanos. Uno abre el adjunto y ejecuta un archivo malicioso. Informática detecta conexiones a IP externas, alertas del antivirus e intentos de acceso a carpetas compartidas, con sospecha de extracción de datos personales de clientes. La empresa carece de procedimiento formal de prevención y respuesta.

## Herramientas utilizadas
| Herramienta | Uso | Apartado |
|---|---|---|
| sha256sum / Get-FileHash | Hash de archivos | 3 |
| VirusTotal | Análisis de archivo, IP y dominio | 2, 3 |
| AbuseIPDB / Shodan / whois | OSINT de IP y dominios | 2 |
| MXToolbox / cabeceras | Análisis del correo (SPF, DKIM, DMARC) | 3 |
| Wireshark | Análisis de tráfico | 3 |
| OpenSSL / GPG | Cifrado, firmas y certificados | 1 |
| PowerShell (Get-MpComputerStatus, Get-NetFirewallProfile, Get-HotFix…) | Auditoría del puesto Windows | 1, 2, 3 |

## Índice
1. Prevención y concienciación
2. Detección y auditoría
3. Investigación y análisis
4. Respuesta y recuperación
5. Notificación y organismos de respuesta
6. Simulación
7. Conclusiones y fuentes
8. Anexo: script de auditoría (PowerShell)

---

## 1.1 Riesgos y amenazas principales

Riesgo = probabilidad (P) × impacto (I), escala 1-5: **≥15 crítico, 8-14 alto, 4-7 medio, ≤3 bajo**.

| # | Amenaza | Descripción | P | I | Riesgo | Control principal |
|---|---|---|---|---|---|---|
| 1 | Phishing / spear phishing | Correos que suplantan a RR. HH. o proveedores para robar credenciales o ejecutar malware | 5 | 4 | 20 (crítico) | Filtrado de correo, SPF/DKIM/DMARC, formación y simulacros |
| 2 | Malware (troyanos, RAT, infostealers) | Ejecución de adjuntos o descargas maliciosas | 4 | 5 | 20 (crítico) | EDR, bloqueo de ejecutables/macros, mínimo privilegio |
| 3 | Ransomware | Cifrado con extorsión; a menudo precedido de exfiltración | 3 | 5 | 15 (crítico) | Copias offline, segmentación, parcheo, EDR |
| 4 | Fuga o exfiltración de datos personales | Salida de datos de clientes (RGPD) | 3 | 5 | 15 (crítico) | Cifrado, DLP, control de accesos, monitorización de salida |
| 5 | Credenciales débiles, reutilizadas o robadas | Acceso legítimo con contraseñas comprometidas | 4 | 4 | 16 (crítico) | MFA, gestor de contraseñas, política de claves |
| 6 | Software sin parchear | Explotación de vulnerabilidades conocidas | 4 | 4 | 16 (crítico) | Gestión de parches, inventario, escaneo |
| 7 | Exceso de privilegios | Permisos de administrador o carpetas innecesarias | 4 | 4 | 16 (crítico) | Mínimo privilegio, revisión periódica, LAPS |
| 8 | Movimiento lateral por recursos compartidos | Red plana y carpetas accesibles desde cualquier equipo | 3 | 4 | 12 (alto) | Segmentación, ACL, desactivar SMBv1 |
| 9 | Error humano | Envío erróneo, pérdida de datos, mala configuración | 4 | 3 | 12 (alto) | Formación, procedimientos, doble verificación |
| 10 | Amenaza interna | Empleado malintencionado o descuidado | 2 | 4 | 8 (alto) | Registro de accesos, separación de funciones |
| 11 | Pérdida o robo de dispositivos | Portátiles y móviles sin cifrar | 3 | 3 | 9 (alto) | BitLocker, MDM, borrado remoto |
| 12 | Ausencia de procedimiento de respuesta | La empresa no sabe cómo actuar | 5 | 4 | 20 (crítico) | Plan de respuesta, roles, simulacros |
| 13 | Shadow IT | Servicios en la nube o software no autorizado | 3 | 3 | 9 (alto) | Catálogo de software aprobado, control de aplicaciones |
| 14 | Pérdida de disponibilidad | Fallo o ataque que deja los servicios caídos | 3 | 4 | 12 (alto) | Copias, redundancia, plan de continuidad |

### Conclusión
El incidente materializa a la vez los riesgos 1, 2, 4, 7, 8 y 12. Las medidas con mejor relación coste-beneficio: MFA, filtrado de correo y formación, EDR, mínimo privilegio, copias offline y un procedimiento de respuesta formal.

**Marcos de referencia:** ISO/IEC 27001 y 27005, NIST CSF, ENS y CIS Controls v8.

---

## 1.2 Normas de seguridad para los puestos de trabajo

### 1. Acceso y contraseñas
| Norma | Motivo |
|---|---|
| Contraseña de al menos 12 caracteres; se recomienda frase de paso | Resiste fuerza bruta |
| Una contraseña distinta por servicio; gestor de contraseñas corporativo | Evita credential stuffing |
| MFA obligatorio en correo, VPN, acceso remoto y aplicaciones críticas | Una contraseña robada no basta |
| Prohibido compartir credenciales | Trazabilidad |
| Bloqueo de pantalla a los 5 min y `Win + L` al levantarse | Evita accesos físicos |

### 2. Equipos y software
| Norma | Motivo |
|---|---|
| Usuarios sin permisos de administrador; administrador local con LAPS | Limita el daño de un malware ejecutado |
| Antivirus/EDR siempre activo; el usuario no puede desactivarlo | Detección y respuesta |
| Actualizaciones automáticas; parches críticos en máximo 7 días | Cierra vulnerabilidades |
| Solo software de la lista aprobada | Evita shadow IT y malware |
| Disco cifrado (BitLocker) en portátiles | Protege datos si se pierde el equipo |
| Firewall activado en todos los perfiles | Defensa en profundidad |
| Macros de Office bloqueadas; ejecución desde temporales y Descargas restringida | Vector habitual de malware |
| USB no autorizados bloqueados | Evita introducción de malware |

### 3. Correo e internet
| Norma | Motivo |
|---|---|
| No abrir adjuntos/enlaces inesperados; verificar por otro canal | Reduce el éxito del phishing |
| Botón «Reportar phishing» | Notificación rápida |
| No usar el correo corporativo para registros personales | Menor exposición |
| Bloquear `.exe`, `.scr`, `.js`, `.vbs`, `.iso` en el filtro de correo | Corta el vector del caso |

### 4. Datos
| Norma | Motivo |
|---|---|
| Datos de clientes solo en repositorios autorizados | Cumplimiento RGPD |
| Acceso a carpetas según mínimo privilegio | Limita la exfiltración |
| Copias automáticas con una copia offline | Recuperación ante ransomware |
| Mesa limpia y destrucción segura de documentos | Confidencialidad |

### 5. Incidentes
| Norma | Motivo |
|---|---|
| Ante algo sospechoso: no apagar, desconectar la red y avisar a Informática | Contención sin perder evidencias |
| Avisar inmediatamente, sin temor a represalias | Cada minuto cuenta |
| Teléfono y correo del equipo de respuesta visibles en cada puesto | Rapidez |

**Verificación:** revisión trimestral con scripts/auditoria-puesto.ps1: firewall, Defender, parches, administradores locales y software.

---

## 1.3 Plan de formación y concienciación

**Meta del primer año:** clics en simulacros de phishing **< 5 %** y reportes **> 60 %**.

| Fase | Cuándo | Contenido | Público | Formato | Duración |
|---|---|---|---|---|---|
| 0. Punto de partida | Mes 1 | Simulacro inicial y test de conocimientos | Todos | Campaña interna | – |
| 1. Formación inicial | Mes 1-2 | Phishing, ingeniería social, contraseñas y MFA, correo seguro, reportar, RGPD básico | Todos | Taller presencial + vídeo | 90 min |
| 2. Roles críticos | Mes 2-3 | Fraude del CEO (BEC), pagos, datos de clientes, nóminas | RR. HH., Finanzas, Admin., Dirección | Taller práctico | 2 h |
| 3. Técnicos | Mes 3 | Procedimiento de respuesta, logs, evidencias | Informática | Taller + ejercicio de mesa | 4 h |
| 4. Microaprendizaje | Mensual | Píldora con caso real, cartel del mes | Todos | Correo / intranet | 5 min |
| 5. Simulacros | Trimestral | Campañas con dificultad creciente | Todos | Simulacro + feedback | – |
| 6. Ejercicio de mesa | Semestral | Simulación de incidente | Dirección + Informática | Reunión de crisis | 2 h |
| 7. Reciclaje | Anual | Repaso y novedades | Todos | Taller | 1 h |
| Nuevas incorporaciones | 1.ª semana | Normas y firma de aceptación | Nuevos | Sesión de acogida | 45 min |

### Contenidos del taller inicial
1. Por qué somos objetivo: el caso real (sin culpabilizar).
2. Anatomía de un phishing: remitente, urgencia, adjunto, enlace.
3. Qué hacer si ya he hecho clic.
4. Contraseñas, gestor y MFA.
5. Datos de clientes y RGPD.
6. Práctica: identificar 5 correos reales entre legítimos y fraudulentos.

### KPI
| Indicador | Objetivo |
|---|---|
| % que hacen clic en el simulacro | < 5 % |
| % que reportan el simulacro | > 60 % |
| % de asistencia a la formación | 100 % |
| Tiempo medio entre recepción y reporte | < 15 min |
| Resultado de tests de conocimiento | > 80 % |
| Incidentes por error humano | Descendente |

**Principios:** cultura sin culpa, mensajes breves y repetidos, ejemplos reales y apoyo visible de la dirección.

---

## 1.4 Guía de buenas prácticas de ciberseguridad

!Cartel
_(Añade `cartel-phishing.png` a `/capturas`; pensado para imprimir en A4.)_

### Cómo detectar un correo de phishing
1. **Remitente:** comprueba la dirección completa. `rrhh@empresa-demo-rrhh.com` no es `rrhh@empresa-demo.es`.
2. **Urgencia o amenaza:** «hoy», «último aviso», «su cuenta será bloqueada».
3. **Adjuntos inesperados:** ZIP, `.exe`, `.scr`, `.iso` o documentos que piden «habilitar contenido».
4. **Enlaces:** pasa el ratón sin pulsar y mira la URL real.
5. **Petición de datos:** nadie legítimo pide contraseñas o códigos MFA por correo.
6. **Formas:** saludo genérico, faltas, tono inusual.
7. **Reply-To** distinto al remitente.

### Qué hacer
| Situación | Acción |
|---|---|
| Correo sospechoso | No abrir, no responder, reportar |
| Dudas sobre un correo de RR. HH. o directivo | Verificar por otro canal |
| He abierto el adjunto o pulsado el enlace | **Desconectar la red, no apagar y avisar a Informática** |
| He introducido mi contraseña en una web falsa | Avisar y cambiarla desde otro equipo; revisar MFA |

### Hábitos básicos
- Contraseñas largas, únicas, en gestor y con MFA.
- Actualiza sistema y aplicaciones.
- Bloquea el equipo al levantarte (`Win + L`).
- Datos de clientes solo en sitios autorizados.
- Wi-Fi públicas: VPN corporativa.
- No instales programas no autorizados ni uses USB desconocidos.
- Teletrabajo: red doméstica robusta y router actualizado.
- Reportar es responsabilidad, nunca una falta.

### Contactos de emergencia (ejemplo)
| Qué | Dónde |
|---|---|
| Informática / equipo de respuesta | soporte@empresa-demo.es · ext. 100 |
| Delegado de Protección de Datos | dpo@empresa-demo.es |
| Línea de ayuda INCIBE | 017 (gratuita) |

---

## 1.5 Fundamentos criptográficos y su utilidad en el caso

La criptografía protege **confidencialidad**, **integridad** y **autenticidad / no repudio**.

| Técnica | Propiedad | Ejemplo | Utilidad en este incidente |
|---|---|---|---|
| Cifrado simétrico | Confidencialidad | AES-256 | Cifrar discos y copias para que los datos extraídos sean ilegibles |
| Cifrado asimétrico | Confidencialidad, intercambio de claves, firma | RSA, ECC | Correo cifrado, base de TLS y certificados |
| Funciones hash | Integridad | SHA-256 | Probar que las evidencias no se alteraron; identificar el malware |
| Firma electrónica | Autenticidad, integridad, no repudio | RSA/ECDSA + SHA-256 | Comunicados de RR. HH. verificables; evita suplantación |
| Certificados digitales | Vincular identidad y clave pública | X.509 | Autenticar servidores (HTTPS, VPN) y usuarios |
| PKI | Gestión y confianza | CA raíz e intermedias, CRL/OCSP | Emitir y revocar certificados comprometidos |
| Diffie-Hellman | Acuerdo de clave por canal inseguro | ECDHE, X25519 | Sesiones TLS/VPN con Perfect Forward Secrecy |

### 1. Cifrado simétrico
Misma clave para cifrar y descifrar; muy rápido. AES-128/256 (GCM o CBC con autenticación), ChaCha20-Poly1305. DES y 3DES, obsoletos. Problema: compartir la clave.
**En el caso:** con discos y copias cifrados y claves gestionadas aparte, el robo de archivos no implicaría una brecha utilizable. Puede influir en la comunicación a afectados (art. 34 RGPD).

### 2. Cifrado asimétrico
Par de claves pública/privada. Más lento: se usa para intercambiar claves simétricas y firmar (cifrado híbrido, como TLS). RSA ≥ 2048 bits, ECDSA, Ed25519, X25519.
**En el caso:** correo cifrado (S/MIME, PGP), HTTPS/VPN, firmas. DKIM se basa en firmas asimétricas.

### 3. Funciones hash
Resumen de longitud fija (SHA-256 → 256 bits): determinista, irreversible, efecto avalancha, resistente a colisiones. MD5 y SHA-1 están rotos. Para contraseñas: bcrypt, scrypt, Argon2 (lentas y con sal), no SHA-256 a secas.
**En el caso:** integridad de evidencias e identificación del malware por hash (IoC).

### 4. Firma electrónica
Hash del documento cifrado con la clave privada; se verifica con la pública. Regulada por eIDAS (simple, avanzada, cualificada).
**En el caso:** con comunicados de RR. HH. firmados, el correo falso carecería de firma válida.

### 5. Certificados digitales
X.509: liga identidad y clave pública, firmado por una CA (sujeto, emisor, validez, clave pública, usos).
**En el caso:** autentican servicios internos y VPN; si se comprometen, se revocan.

### 6. PKI
CA raíz (offline), CA intermedias, RA, repositorios y revocación (CRL/OCSP). Cadena de confianza.
**En el caso:** emitir certificados a empleados y equipos y revocar los de equipos comprometidos.

### 7. Diffie-Hellman
Dos partes acuerdan una clave simétrica por un canal inseguro sin enviarla. Variante moderna: ECDHE (X25519). Con claves efímeras: Perfect Forward Secrecy.
**En el caso:** base de TLS y VPN; el tráfico capturado no se podría descifrar a posteriori.

---

## Práctica con OpenSSL
Salidas de una ejecución real con OpenSSL 3.0.13 y `sha256sum`. Todo sobre archivos de prueba inofensivos. **No se sube ninguna clave privada.**

### P1. Hash y efecto avalancha
```console
$ sha256sum documento.txt
5d98c5af72335a371850411f9015eee3d05719dd7de83c25d7f6aef89be8ebf1  documento.txt
$ sha256sum documento_modificado.txt   # solo se ha añadido una "X"
f75a3adc31878242bebc15fd3c003e6cc90ccd99c101d4b152dba85a85fd02ca  documento_modificado.txt
```
Un solo carácter produce un hash completamente distinto.

### P2. Par de claves RSA y firma digital
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out clave_privada.pem
openssl pkey -in clave_privada.pem -pubout -out clave_publica.pem
openssl dgst -sha256 -sign clave_privada.pem -out documento.firma documento.txt
openssl dgst -sha256 -verify clave_publica.pem -signature documento.firma documento.txt            # Verified OK
openssl dgst -sha256 -verify clave_publica.pem -signature documento.firma documento_modificado.txt # Verification failure
```

### P3. Cifrado simétrico AES-256
```bash
openssl enc -aes-256-cbc -pbkdf2 -salt -in documento.txt -out documento.enc -pass pass:ClaveDePrueba123
openssl enc -d -aes-256-cbc -pbkdf2 -in documento.enc -pass pass:ClaveDePrueba123
```
(En un entorno real no se escribe la clave en la línea de comandos.)

### P4. Certificado X.509 autofirmado
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out certificado.pem -days 365 \
  -subj "/C=ES/O=Empresa Demo/CN=servidor.demo.local"
openssl x509 -in certificado.pem -noout -subject -issuer -dates -fingerprint -sha256
```
```text
subject=C = ES, O = Empresa Demo, CN = servidor.demo.local
issuer=C = ES, O = Empresa Demo, CN = servidor.demo.local
notBefore=Nov 17 11:36:05 2026 GMT
notAfter=Nov 17 11:36:05 2027 GMT
sha256 Fingerprint=E3:FD:30:81:1D:86:E5:E1:9D:3B:29:E6:16:9A:84:04:23:B1:69:93:9D:E8:D3:78:5F:65:82:D1:BF:AB:5A:17
```
Emisor y sujeto coinciden: autofirmado, sin cadena de confianza.

### P5. Diffie-Hellman (X25519)
```console
$ openssl pkeyutl -derive -inkey a.pem -peerkey b.pub | sha256sum
e6036d7f2c46fad52d2574e0022822b85f5495d26ccbe64791116edc6294ce57  -
$ openssl pkeyutl -derive -inkey b.pem -peerkey a.pub | sha256sum
e6036d7f2c46fad52d2574e0022822b85f5495d26ccbe64791116edc6294ce57  -
```
Ambas partes llegan al mismo secreto sin transmitirlo.

### Pendiente de captura propia (`/capturas`)
- [ ] P1 con `Get-FileHash` en PowerShell además de `sha256sum`.
- [ ] P2 a P5 en tu entorno.
- [ ] Certificado de una web real en el navegador y su cadena de confianza.

---

## 2.1 y 2.2 Clasificación del incidente, gravedad y sistemas afectados

> Los equipos, usuarios, IP y horas son del escenario simulado (rangos RFC 5737 y dominios ficticios).

### 1. Clasificación
| Criterio | Valoración |
|---|---|
| Tipo principal | Código dañino (malware): ejecución de archivo malicioso por ingeniería social |
| Vector de entrada | Phishing por correo con adjunto (suplanta a RR. HH.) |
| Tipos secundarios | Intrusión / intento de acceso a carpetas compartidas; compromiso de la información (posible exfiltración) |
| C / I / D | C: afectada o probable · I: en riesgo · D: de momento no afectada |
| MITRE ATT&CK | T1566.001 · T1204.002 · T1071 (C2) · T1135 · T1021.002 · T1041 · persistencia posible T1053 / T1547 |
| Datos personales | Sí (clientes): activa el análisis RGPD |

Taxonomía: Guía Nacional de Notificación y Gestión de Ciberincidentes (CCN-CERT / INCIBE).

### 2. Gravedad
| Factor | Evidencia actual | Puntuación (1-5) |
|---|---|---|
| Alcance (equipos) | ≥1 equipo ejecutó el malware; 12 usuarios recibieron el correo | 3 |
| Criticidad de los activos | Acceso a servidor de ficheros con datos de clientes | 5 |
| Datos personales | Posible exfiltración (no confirmada) | 5 |
| Capacidad de propagación | Intentos de acceso a carpetas compartidas | 4 |
| Persistencia / control del atacante | Conexiones salientes periódicas (posible C2) | 4 |
| Impacto en el negocio | Servicios operativos por ahora | 2 |
| **Valoración global** | | **ALTA (provisional)** |

**Decisión:** gravedad ALTA, con revisión inmediata a CRÍTICA si se confirma exfiltración, movimiento lateral o afectación del servidor de ficheros/DC.

| Nivel | Criterio | Respuesta |
|---|---|---|
| Bajo | Un equipo, sin datos sensibles, contenido | Gestión ordinaria de TI |
| Medio | Varios equipos o amenaza contenida | Equipo de seguridad |
| Alto | Malware activo con C2 y riesgo para datos personales | Equipo de respuesta + dirección + DPO |
| Crítico | Exfiltración confirmada, servicios críticos o todo el dominio | Gestión de crisis, notificación a AEPD, apoyo externo |

### 3. Sistemas y servicios potencialmente afectados
| Activo | Estado | Prioridad | Motivo |
|---|---|---|---|
| PC-ADM-07 | Comprometido | Inmediata | Ejecución del malware, origen de conexiones |
| Otros 11 equipos que recibieron el correo | Sin confirmar | Inmediata | Posibles aperturas sin detectar |
| Cuenta de dominio `alopez` | Probablemente comprometida | Inmediata | Credenciales y sesión de la víctima |
| SRV-FICHEROS (datos de clientes) | En riesgo | Inmediata | Objetivo de los accesos |
| Controlador de dominio / AD | En riesgo | Alta | Escalada o robo de credenciales |
| Servidor y buzones de correo | Afectado (vector) | Alta | Retirar correo y bloquear remitente |
| Firewall / proxy / DNS | Fuente de evidencias | Alta | Logs de conexiones salientes |
| Copias de seguridad | A proteger | Alta | Verificar que no estén comprometidas |
| CRM / aplicaciones con datos de clientes | En riesgo | Media | Reutilización de credenciales |
| Servicios en la nube (M365, VPN) | En riesgo | Media | Inicios de sesión sospechosos |

---

## 2.3 y 2.4 Herramientas de detección y registros a consultar

### Herramientas
| Categoría | Herramienta | Uso en este caso |
|---|---|---|
| EDR / antivirus | Defender for Endpoint, SentinelOne, CrowdStrike; Wazuh | Detección, aislamiento remoto, búsqueda de IoC |
| SIEM | Wazuh, Elastic Security, Splunk, Sentinel | Correlar «correo → ejecución → conexión externa» |
| Red (IDS/IPS) | Suricata, Zeek, Wireshark, Security Onion | C2, DNS anómalo, exfiltración |
| Firewall / proxy | Logs perimetrales y del proxy | Conexiones salientes sospechosas |
| Sysinternals | Autoruns, Process Explorer, TCPView, Sysmon | Persistencia, procesos y conexiones |
| Forense | FTK Imager, Velociraptor, KAPE, Volatility 3, Autopsy | Adquisición y análisis |
| Malware | VirusTotal, Hybrid Analysis, ANY.RUN, CyberChef | Reputación y sandbox |
| OSINT | AbuseIPDB, Shodan, urlscan.io, whois/RDAP, crt.sh, MISP, OTX | IP y dominios |
| Correo | Visor de cabeceras, MXToolbox | Análisis del correo |
| Gestión | TheHive, GLPI u hoja de seguimiento | Registro y cronología |
| PowerShell | scripts/auditoria-puesto.ps1 | Auditoría rápida |

### Registros que se consultan
| Fuente | Dónde / cómo | Qué se busca |
|---|---|---|
| Antivirus / EDR | `Get-MpThreatDetection`, `Get-MpComputerStatus`; eventos 1116, 1117, 5001 | Amenaza, ruta, usuario, hora, protección desactivada |
| Firewall perimetral | Logs de tráfico saliente | IP sospechosas, puertos inusuales, beaconing, volumen subido |
| Firewall de Windows | Evento 5156 (con auditoría) | Proceso que inicia la conexión |
| SO (Seguridad) | 4624/4625, 4648, 4672, 4688, 4698, 4720, 4732, 5140/5145 | Accesos a carpetas, fallidos, cuentas o tareas nuevas |
| SO (Sistema) | 7045 | Persistencia por servicios |
| PowerShell | 4104 (Script Block Logging) | Comandos ofuscados |
| Sysmon | 1 (proceso), 3 (red), 11 (archivo), 22 (DNS) | Cadena Outlook → adjunto → proceso hijo → conexión |
| Tráfico de red | pcap, Zeek `conn.log`, `dns.log` | Destino, volumen, frecuencia, DNS |
| DNS | Logs de DNS / proxy | Dominios recientes o aleatorios |
| Servidor de ficheros | Auditoría de acceso a objetos | Ficheros leídos o copiados |
| Servidor de correo | Trazas de mensajes | Quién recibió y abrió |
| AD / Azure AD | Logs de autenticación | Inicios anómalos |

### Correlación esperada
`Correo recibido → apertura del adjunto → 4688 / Sysmon 1 → alerta Defender (1116) → conexión saliente (Sysmon 3 / firewall) → intentos SMB (5140, 4625)`

### Auditoría de un puesto Windows (PowerShell, solo lectura)
Script: scripts/auditoria-puesto.ps1.

| # | Comando | Qué comprueba | Qué buscar |
|---|---|---|---|
| 1 | `Get-ComputerInfo` | SO, nombre, dominio, BIOS | Identificar el equipo para la ficha |
| 2 | `Get-LocalUser` | Cuentas locales | Cuentas nuevas o habilitadas indebidamente |
| 3 | `Get-LocalGroupMember -Group administradores` | Administradores | Usuarios añadidos sin autorización |
| 4 | `Get-Service \| where status -eq running` | Servicios | Desconocidos o que imitan legítimos |
| 5 | `Get-NetFirewallProfile` | Firewall | Perfiles desactivados |
| 6 | `Get-MpComputerStatus` | Defender | Protección desactivada, firmas antiguas |
| 7 | `Get-HotFix` | Parches | Equipo sin actualizar |
| 8 | `Get-Package` | Software | Programas no autorizados |

Complementos: `Get-MpThreatDetection`, `Get-WinEvent` (4625, 5140/5145), `Get-NetTCPConnection -State Established`, `Get-FileHash`, `Get-ScheduledTask`.

> **Nota:** el nombre del grupo depende del idioma. Alternativa universal: `Get-LocalGroupMember -SID S-1-5-32-544`.

### Resultados
_Pega aquí las capturas (carpeta `/capturas`) y comenta lo que observas._

---

## 2.5 Investigación OSINT de IP y dominios sospechosos

### Indicadores (escenario simulado)
| Tipo | Indicador | Origen |
|---|---|---|
| IP | `203.0.113.45` | Servidor que envió el correo y destino de las conexiones |
| IP | `198.51.100.77` | Primer salto del correo (`Received`) |
| Dominio | `empresa-demo-rrhh.com` | Return-Path (parecido al legítimo) |
| Dominio | `rrhh-portal-empresa-demo.example.com` | Enlace del correo (captura de credenciales) |
| Correo | `nominas.rrhh.soporte@mailbox-example.org` | Reply-To |

> `203.0.113.0/24` y `198.51.100.0/24` son rangos de documentación (RFC 5737) y los dominios son ficticios: las consultas reales no devolverán resultados. Repite el procedimiento con indicadores reales y públicos (INCIBE, CCN-CERT, URLhaus, ThreatFox) y haz capturas.

### Metodología
| Paso | Herramienta | Qué mirar |
|---|---|---|
| 1. Registro del dominio | `whois`, RDAP | Fecha de creación, registrador, país, privacidad |
| 2. DNS | `nslookup`, `dig`, `dig MX`, `dig TXT` | IP, servidores de correo, SPF/DMARC |
| 3. Reputación | VirusTotal, AbuseIPDB, Talos, OTX | Detecciones, denuncias, etiquetas |
| 4. Infraestructura de la IP | Shodan, Censys, whois IP | ASN, hosting, puertos, país |
| 5. Certificados | crt.sh | Fecha de emisión, dominios hermanos |
| 6. Página web | urlscan.io | ¿Copia del portal?, redirecciones |
| 7. Historial | Wayback, DomainTools, SecurityTrails | Cambios de IP, dominios asociados |
| 8. Pivotar | MISP, OTX | Otros IoC de la campaña |

```bash
whois empresa-demo-rrhh.com
dig +short empresa-demo-rrhh.com
dig TXT empresa-demo-rrhh.com +short   # SPF/DMARC
whois 203.0.113.45
```

**Buenas prácticas:** investigar desde una máquina aislada o servicios web, no visitar el enlace desde la red corporativa y registrar fecha y hora de cada consulta.

### Análisis de los indicadores del escenario
| Indicador | Observación | Conclusión |
|---|---|---|
| `empresa-demo-rrhh.com` | Imita a `empresa-demo.es` (`-rrhh` y otro TLD) | Typosquatting; no es el dominio de la empresa |
| From ≠ Return-Path | Visible `empresa-demo.es`, sobre `empresa-demo-rrhh.com` | Suplantación (spoofing) |
| Reply-To en `mailbox-example.org` | Respuestas a buzón ajeno | Robo de información |
| URL `.example.com` con prefijo `rrhh-portal` | Imita un portal interno | Captura de credenciales |
| IP `203.0.113.45` | Falla SPF | Origen no legítimo |

### Resultados de consultas reales (a completar)
| Indicador | Fecha de registro | País / ASN | VirusTotal | AbuseIPDB | Veredicto |
|---|---|---|---|---|---|
| | | | | | |

Capturas: `capturas/osint-virustotal.png`, `capturas/osint-whois.png`, `capturas/osint-abuseipdb.png`

---

## 2.6 Ficha de registro del incidente

| Campo | Valor |
|---|---|
| ID | INC-2026-001 |
| Detección | 16/11/2026, 10:30 |
| Inicio estimado | 16/11/2026, 08:12 (recepción); ejecución hacia las 08:40 |
| Detectado por | Informática (alertas del antivirus y del firewall) |
| Reportado por | Informática → responsable de ciberseguridad |
| Tipo | Código dañino por phishing; posible compromiso de la información |
| Vector | Correo con adjunto que suplanta a RR. HH. |
| Gravedad | ALTA (provisional; CRÍTICA si se confirma exfiltración o movimiento lateral) |
| Estado | En contención / investigación |
| Responsable | Responsable de ciberseguridad |
| Equipo de respuesta | Ciberseguridad, Admin. de sistemas, DPO, Dirección, Comunicación/RR. HH., Asesoría legal |
| Sistemas afectados | PC-ADM-07 (confirmado); SRV-FICHEROS, cuenta `alopez` y otros 11 destinatarios (por verificar) |
| Usuarios afectados | `alopez` (abrió el adjunto); 11 destinatarios más |
| Datos afectados | Posibles datos personales de clientes (no confirmado) |
| IoC | IP `203.0.113.45`, `198.51.100.77`; dominios `empresa-demo-rrhh.com`, `rrhh-portal-empresa-demo.example.com`; remitente `rrhh@empresa-demo-rrhh.com`; adjunto `Nomina_Noviembre_2026.zip`; SHA-256 `502e22b25322d682e15e6ad0673e6bd60470f8bf6c2b4455fd54080d0c7ff50e` |
| Evidencias | Correo (.eml), muestra del adjunto, logs de firewall y antivirus, volcado de RAM de PC-ADM-07 |
| Notificación AEPD | Pendiente de valoración por el DPO. Plazo 72 h. Límite orientativo: 19/11/2026, 10:30 |
| Notificación CERT | INCIBE-CERT; denuncia a Policía o Guardia Civil si procede |
| Comunicación interna | Aviso a la plantilla a las 11:15 |
| Lecciones aprendidas | Tras el cierre |

### Cronología
| Fecha / hora | Evento | Responsable |
|---|---|---|
| 16/11 08:12 | 12 empleados reciben el correo falso de RR. HH. | – |
| 16/11 08:40 | `alopez` abre el adjunto y ejecuta el archivo | – |
| 16/11 09:05 | Alerta del antivirus en PC-ADM-07 | Antivirus |
| 16/11 09:20 | Conexiones salientes periódicas a 203.0.113.45:443 | Firewall |
| 16/11 10:15 | Intentos de acceso a SRV-FICHEROS desde PC-ADM-07 (3 denegados) | Servidor |
| 16/11 10:30 | Informática correlaciona las alertas y declara el incidente | Informática |
| 16/11 10:45 | Se activa el equipo de respuesta; se aísla PC-ADM-07 (sin apagarlo) | Resp. ciberseguridad |
| 16/11 11:00 | Bloqueo de IP y dominios; se retira el correo de los buzones | Admin. sistemas |
| 16/11 11:15 | Aviso a la plantilla | Comunicación |
| 16/11 11:30 | Restablecimiento de contraseña de `alopez` y cierre de sesiones | Admin. sistemas |
| 16/11 12:00 | Adquisición de RAM y copia forense; apertura de cadena de custodia | Analista forense |
| 16/11 13:00 | Revisión del servidor de ficheros | Admin. sistemas |

---

## 3.1, 3.2 y 3.5 Evidencias, integridad y cadena de custodia

### 1. Evidencias por orden de volatilidad (RFC 3227)
| Orden | Evidencia | Por qué | Cómo |
|---|---|---|---|
| 1 | RAM de PC-ADM-07 | Procesos, conexiones, claves, malware descifrado | WinPmem / FTK Imager antes de apagar |
| 2 | Conexiones, procesos, sesiones, caché DNS | Se pierden al reiniciar | `Get-NetTCPConnection`, `Get-Process`, `Get-DnsClientCache`, `netstat -ano` |
| 3 | Tareas programadas, claves Run, servicios, usuarios | Persistencia | Autoruns, `Get-ScheduledTask`, `auditoria-puesto.ps1` |
| 4 | Imagen forense del disco | Archivos, historial, artefactos | FTK Imager (E01 o dd) con bloqueo de escritura |
| 5 | Logs de Windows, Defender, Sysmon, firewall, proxy, DNS, servidor de ficheros | Línea de tiempo | Exportar `.evtx` y logs del SIEM/firewall |
| 6 | Correo original (.eml con cabeceras) | Prueba del vector | Exportar desde el servidor, no reenviar |
| 7 | Adjunto y ejecutable | Análisis del malware | Copiar a contenedor aislado y protegido |
| 8 | Capturas de tráfico (pcap) | Prueba de la exfiltración | Puerto espejo, Wireshark/Zeek |
| 9 | Trazas de correo y auditoría del servidor de ficheros | Alcance real | Exportar con fecha y hora |
| 10 | Capturas, testimonios, hora de los hechos | Contexto | Acta firmada con el usuario |

### 2. Cómo se preserva la integridad
1. No trabajar sobre el original: copia bit a bit; el original queda sellado.
2. Bloqueador de escritura al adquirir discos.
3. SHA-256 de cada evidencia al adquirirla y antes de cada análisis.
4. Almacenamiento cifrado, con acceso restringido y registrado; copia secundaria.
5. Registro de cada acción (quién, cuándo, herramienta y versión), con NTP y zona horaria.
6. Mínima alteración: no apagar, no «limpiar» el antivirus, no abrir archivos en el equipo comprometido; aislar de la red.
7. Documentar comandos y guardar sus salidas.
8. Malware en contenedores con contraseña y extensión neutralizada (`.zip` con clave `infected`).
9. Separar adquisición y análisis.

### 3. Hashes de las muestras
```text
502e22b25322d682e15e6ad0673e6bd60470f8bf6c2b4455fd54080d0c7ff50e  adjunto-simulado.bin
8b07bd1c122ba15052b2f55bace4c36f1aa5fd666933fda5148438c36e49f733  correo-phishing-simulado.eml
```

### 4. Formulario de cadena de custodia
#### Ficha de la evidencia
| Campo | Valor |
|---|---|
| ID | EV-001 |
| Caso | INC-2026-001 |
| Descripción | Adjunto simulado `adjunto-simulado.bin` extraído del correo |
| Origen | Buzón de `alopez` (PC-ADM-07) |
| Recogida | 16/11/2026, 12:00 (CET), por el analista forense |
| Método | Copia desde el servidor de correo con herramienta de solo lectura |
| Tamaño | 120 bytes |
| SHA-256 | `502e22b25322d682e15e6ad0673e6bd60470f8bf6c2b4455fd54080d0c7ff50e` |
| MD5 (referencia) | `443c5ea97231adf8cff32ada870e9f55` |
| Soporte y precinto | USB cifrado nº 03, bolsa precintada nº 0021 |
| Custodia | Caja fuerte de Informática |

#### Registro de traspasos
| Nº | Fecha / hora | Entrega | Recibe | Motivo | Hash ✔ | Firmas |
|---|---|---|---|---|---|---|
| 1 | 16/11 12:00 | Analista forense | Resp. ciberseguridad | Custodia inicial | ✔ | ________ |
| 2 | 16/11 15:30 | Resp. ciberseguridad | Analista (lab. aislado) | Análisis estático | ✔ | ________ |
| 3 | 17/11 09:00 | Analista | Resp. ciberseguridad | Devolución | ✔ | ________ |

#### Otras evidencias
| ID | Descripción | Origen | SHA-256 |
|---|---|---|---|
| EV-002 | Correo original `.eml` | Servidor de correo | `8b07bd1c122ba15052b2f55bace4c36f1aa5fd666933fda5148438c36e49f733` |
| EV-003 | Volcado de RAM de PC-ADM-07 | PC-ADM-07 | (calcular al adquirir) |
| EV-004 | Imagen forense del disco | PC-ADM-07 | (calcular al adquirir) |
| EV-005 | Logs de firewall del 16/11 | Firewall | (calcular al exportar) |
| EV-006 | Eventos de seguridad `.evtx` | PC-ADM-07 / SRV-FICHEROS | (calcular al exportar) |

---

## 3.3 Análisis del correo electrónico

Muestra: `muestras/correo-phishing-simulado.eml` (correo simulado; direcciones e IP ficticias o RFC 5737).

### 1. Cómo se analiza
1. Obtener el `.eml` (Outlook: Archivo → Guardar como; Gmail: Mostrar original). No reenviar como adjunto desde el equipo infectado.
2. Abrir cabeceras completas; leer los `Received` de abajo hacia arriba.
3. Comparar `From`, `Return-Path`, `Reply-To` y `Message-ID`.
4. Revisar `Authentication-Results`: SPF, DKIM, DMARC.
5. Extraer enlaces y adjuntos sin abrirlos; calcular hashes.
6. Investigar dominios e IP (ver OSINT).

### 2. Hallazgos
| Campo | Valor | Interpretación |
|---|---|---|
| From | `"Recursos Humanos" <rrhh@empresa-demo.es>` | Suplanta a RR. HH. con el dominio legítimo |
| Return-Path | `rrhh@empresa-demo-rrhh.com` | No coincide con From: dominio parecido del atacante |
| Reply-To | `nominas.rrhh.soporte@mailbox-example.org` | Respuestas a buzón externo |
| Received (1.er salto) | `mail.srv-relay-example.net [203.0.113.45]` | Servidor ajeno |
| Received (origen) | `198.51.100.77`, HELO `localhost` | HELO genérico, típico de envío masivo/bot |
| SPF | fail | IP no autorizada |
| DKIM | none | Sin firma |
| DMARC | fail | No supera la alineación |
| Asunto | «URGENTE… acción requerida hoy» | Ingeniería social |
| Hora | 08:12 (07:12 UTC) | Envío a primera hora laboral |
| Cuerpo | Saludo genérico | Envío masivo |
| Enlace | `http://rrhh-portal-empresa-demo.example.com/login` | Sin HTTPS, dominio ajeno que imita un portal |
| Adjunto | `Nomina_Noviembre_2026.zip` → `Nomina_Noviembre_2026.pdf.exe` | Doble extensión: ejecutable disfrazado de PDF |

**Conclusión:** phishing con `From` falsificado y adjunto ejecutable disfrazado de PDF. Que SPF y DMARC fallen y no haya DKIM indica que el servidor de entrada no aplicaba política de rechazo (`action=none`), lo que permitió la entrega.

### 3. IoC extraídos
| Tipo | Valor |
|---|---|
| IP | `203.0.113.45`, `198.51.100.77` |
| Dominio | `empresa-demo-rrhh.com`, `rrhh-portal-empresa-demo.example.com`, `mailbox-example.org`, `srv-relay-example.net` |
| Correo | `rrhh@empresa-demo-rrhh.com`, `nominas.rrhh.soporte@mailbox-example.org` |
| Asunto | «URGENTE: Revision de su nomina de noviembre - accion requerida hoy» |
| Adjunto | `Nomina_Noviembre_2026.zip` |
| Message-ID | `<20261116071230.GA1234@srv-relay-example.net>` |

### 4. Acciones derivadas
- Buscar el mismo Message-ID / asunto / remitente y retirarlo de todos los buzones.
- Bloquear dominio e IP en el filtro de correo y el firewall.
- Identificar quién lo recibió, abrió y ejecutó.
- Aplicar SPF, DKIM y DMARC con `p=reject` al dominio de la empresa.

### Capturas pendientes
- [ ] Cabeceras del `.eml` o MXToolbox (`capturas/correo-cabeceras.png`).
- [ ] Resultado SPF/DKIM/DMARC.

---

## 3.3 y 3.6 Análisis del archivo malicioso y hash SHA-256

> **Seguridad:** no se ha usado malware real. `muestras/adjunto-simulado.bin` es un archivo de texto inofensivo. Cualquier análisis dinámico de malware real debe hacerse solo en un laboratorio aislado y autorizado.

### 1. Cálculo del hash (evidencia real)
```console
$ sha256sum adjunto-simulado.bin
502e22b25322d682e15e6ad0673e6bd60470f8bf6c2b4455fd54080d0c7ff50e  adjunto-simulado.bin
$ md5sum adjunto-simulado.bin
443c5ea97231adf8cff32ada870e9f55  adjunto-simulado.bin
$ sha1sum adjunto-simulado.bin
62400336c4b7d4ce4459e31dbf9171ae1f56dc14  adjunto-simulado.bin
```
PowerShell:
```powershell
Get-FileHash .\adjunto-simulado.bin -Algorithm SHA256
Get-FileHash .\adjunto-simulado.bin -Algorithm MD5
```
Linux/macOS: `sha256sum archivo` / `shasum -a 256 archivo`.

### 2. Para qué sirve el hash
| Uso | Explicación |
|---|---|
| Integridad de la evidencia | Si coincide al adquirir y analizar, no se modificó (base de la cadena de custodia) |
| Identificación del malware | Mismo archivo = mismo hash; se busca en todos los equipos |
| Reputación | Se busca en VirusTotal sin subir el archivo |
| Intercambio de IoC | Se comparte con CERT y MISP sin enviar el binario |
| Detección de manipulación | Un bit cambiado genera otro hash (práctica P1) |
| Bloqueo / allowlist | El EDR puede bloquear un hash conocido |

**Limitación:** el malware polimórfico cambia de hash en cada copia; se complementa con YARA, comportamiento y otros IoC.

### 3. Procedimiento de análisis
#### 3.1 Estático (sin ejecutar)
```bash
file adjunto-simulado.bin              # tipo real (¿PE, script?)
strings -n 8 adjunto-simulado.bin      # URL, IP, comandos
sha256sum adjunto-simulado.bin         # identificación
```
En un caso real: doble extensión (`.pdf.exe`), cabecera MZ, firma digital, datos de compilación, imports sospechosos (`WinExec`, `InternetOpen`, `CreateRemoteThread`), empaquetadores y ofuscación.

#### 3.2 Reputación
1. Buscar el SHA-256 en VirusTotal (Detection, Behavior, Relations).
2. Consultar MalwareBazaar y Hybrid Analysis.
3. Anotar familia, técnicas MITRE e IP/dominios contactados.

#### 3.3 Dinámico (solo laboratorio aislado)
VM sin red real y con instantánea: Process Monitor, Process Explorer, Regshot, Wireshark, ANY.RUN o Cuckoo/CAPE. Observar procesos, archivos y claves modificadas, dominios resueltos y persistencia.

### 4. Resultado esperado (hipótesis a verificar)
| Aspecto | Comportamiento esperado |
|---|---|
| Tipo | Ejecutable de Windows con icono de PDF y doble extensión |
| Persistencia | Clave Run o tarea programada |
| Comunicación | HTTPS periódico a `203.0.113.45:443` (C2) |
| Objetivo | Descubrimiento de red/carpetas y recolección de datos |

### Capturas pendientes
- [ ] `Get-FileHash` en PowerShell (`capturas/hash-sha256-powershell.png`).
- [ ] `strings`/`file` o VirusTotal (`capturas/hash-virustotal.png`).

---

## 3.4 Análisis de las conexiones sospechosas

### 1. Qué se sabe
- **Origen:** PC-ADM-07 (`10.10.20.37`).
- **Destino:** `203.0.113.45:443/TCP`, misma IP que envió el correo.
- **Patrón:** conexiones cada ~60 s con duración y tamaño similares.
- **Inicio:** 09:20, unos 40 min tras abrir el adjunto.
- **Posterior:** intentos SMB (445/TCP) hacia SRV-FICHEROS, 3 denegados.

### 2. Interpretación
| Indicio | Significado |
|---|---|
| Conexión periódica y regular | Beaconing hacia el servidor C2 |
| Puerto 443 | Se camufla entre tráfico web |
| Mismo servidor que el correo | Infraestructura reutilizada: refuerza la correlación |
| Subida mayor a lo normal (a confirmar) | Posible exfiltración |
| Acceso a 445 de otros equipos | Descubrimiento y movimiento lateral |
| Proceso con nombre/ruta inusual | No es el navegador |

### 3. Cómo se analiza
#### 3.1 En el equipo (PowerShell, solo lectura)
```powershell
# Conexiones establecidas con el proceso responsable
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,
    @{n='Proceso';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} |
  Where-Object RemoteAddress -eq '203.0.113.45'

# Caché DNS
Get-DnsClientCache | Select-Object Entry, Data

# Alternativa clásica
netstat -ano | findstr 203.0.113.45
```
Después: `Get-Process -Id <PID> | Select Path`, `Get-AuthenticodeSignature <ruta>` y el proceso padre (Process Explorer).

#### 3.2 En firewall / SIEM
- Filtrar por IP de destino y equipo de origen (24-72 h).
- Contar conexiones por intervalo y comprobar regularidad.
- Sumar bytes enviados y comparar con la línea base.
- Buscar otros equipos que hablen con la misma IP.

#### 3.3 Wireshark / Zeek
```text
ip.addr == 203.0.113.45
tcp.port == 443 && ip.dst == 203.0.113.45
dns.qry.name contains "empresa-demo-rrhh"
smb2 || tcp.port == 445
tls.handshake.extensions_server_name
```
En Zeek: `conn.log` (duración, bytes), `dns.log`, `ssl.log` (SNI y certificado).

### 4. Ejemplo ilustrativo de beaconing (extracto simulado)
| Hora | Origen | Destino | Puerto | Bytes enviados |
|---|---|---|---|---|
| 09:20:03 | 10.10.20.37 | 203.0.113.45 | 443 | 812 |
| 09:21:03 | 10.10.20.37 | 203.0.113.45 | 443 | 815 |
| 09:22:04 | 10.10.20.37 | 203.0.113.45 | 443 | 810 |
| 09:23:03 | 10.10.20.37 | 203.0.113.45 | 443 | 814 |
| … | … | … | … | … |
| 10:02:11 | 10.10.20.37 | 203.0.113.45 | 443 | **4 380 112** |

Intervalos de ~60 s con tamaño casi constante = beacon. El pico de 4,3 MB es indicio de exfiltración a contrastar con los accesos a ficheros.

### 5. Conclusión
Patrón compatible con malware con C2 sobre HTTPS y reconocimiento interno. Las conexiones no demuestran qué datos salieron: hay que cruzar el volumen de subida con la auditoría del servidor de ficheros (eventos 5140/5145). Esto es decisivo para la obligación de notificar.

### Capturas pendientes
- [ ] `Get-NetTCPConnection` y `netstat -ano` (`capturas/conexiones-powershell.png`).
- [ ] Wireshark con filtro (`capturas/wireshark-filtro.png`).

---

## 4.1 Procedimiento de respuesta y recuperación

Basado en NIST SP 800-61 (preparación → detección y análisis → contención, erradicación y recuperación → lecciones aprendidas), adaptado a ~100 empleados.

### Principios
1. Contener antes de erradicar; preservar evidencias antes de limpiar.
2. No avisar al atacante prematuramente: primero alcance, luego acción coordinada.
3. Una decisión, un responsable, un registro.
4. Reinstalar es más seguro que limpiar.

### Resumen
| Fase | Objetivo | Acciones | Responsable | Criterio de finalización |
|---|---|---|---|---|
| 1. Aislamiento | Frenar propagación y fuga | Desconectar PC-ADM-07 y afectados (EDR/switch/cable) sin apagarlos; VLAN de cuarentena | Admin. sistemas | Sin tráfico del equipo |
| 2. Bloqueo | Cortar el canal | Bloquear IP y dominios en firewall, proxy y DNS; bloquear remitente y retirar correo | Admin. / Seguridad | Sin conexiones a IoC |
| 3. Revocación | Retirar el acceso | Restablecer contraseñas, invalidar sesiones y tokens, reiniciar MFA, rotar cuentas de servicio | Admin. sistemas | Credenciales renovadas |
| 4. Eliminación | Erradicar | Reinstalar desde imagen limpia; eliminar persistencia; buscar IoC en toda la red | Seguridad / Forense | Ningún equipo con IoC |
| 5. Recuperación | Volver a la normalidad | Restaurar desde copia limpia, reintegrar por fases, vigilar | Admin. sistemas | Servicios operativos y monitorizados |
| 6. Prevención | Evitar recurrencia | Medidas de la sección 6 | Dirección + Seguridad | Plan de mejora aprobado |

### 1. Aislamiento
- Aislar, no apagar (apagar destruye la RAM). Sin EDR: desconectar cable y Wi-Fi.
- Adquirir RAM (EV-003) y luego disco (EV-004).
- Evitar iniciar sesión con cuentas privilegiadas en equipos comprometidos.
```powershell
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
```

### 2. Bloqueo de conexiones maliciosas
| Dónde | Acción |
|---|---|
| Firewall perimetral | Bloquear salida a 203.0.113.45 y 198.51.100.77 |
| DNS / proxy | Sinkhole o bloqueo de los dominios IoC |
| Filtro de correo | Bloquear remitente, dominio y asunto; purgar buzones |
| Endpoints | Regla de Windows Firewall o bloqueo de hash en EDR |

```powershell
New-NetFirewallRule -DisplayName "INC-2026-001 Bloqueo C2" -Direction Outbound `
  -RemoteAddress 203.0.113.45,198.51.100.77 -Action Block
```
Se registran los intentos bloqueados: indican otros equipos infectados.

### 3. Revocación de credenciales
| Elemento | Acción |
|---|---|
| `alopez` | Restablecer contraseña, cerrar sesiones y tokens, revisar reglas de reenvío y MFA |
| Quienes abrieron el correo | Cambio de contraseña obligatorio |
| Cuentas de administración | Revisar uso reciente; rotar si hubo sesión en equipos infectados |
| Cuentas de servicio y secretos | Rotar contraseñas, claves de API y tokens |
| `krbtgt` (solo si hay compromiso de dominio) | Doble restablecimiento espaciado, con apoyo especializado |
| Certificados y claves en el equipo | Revocar y reemitir (PKI) |
| Cuentas/grupos nuevos | Eliminar los no autorizados (4720, 4732) |
| Navegadores | Asumir contraseñas guardadas expuestas |

### 4. Eliminación de la amenaza
1. Buscar persistencia: claves Run, tareas, servicios, inicio, WMI, cuentas nuevas.
2. Reinstalación completa desde imagen limpia y parcheada.
3. Barrido con EDR y búsqueda de IoC en toda la red.
4. Revisar correo, servidor de ficheros y AD.
5. Confirmar con monitorización que no hay conexiones al atacante.

### 5. Recuperación
Orden por criticidad (RTO/RPO): 1) identidad y correo, 2) servidor de ficheros y apps con datos de clientes, 3) resto.

| Paso | Detalle |
|---|---|
| Verificar la copia | Anterior al compromiso y libre de malware |
| Restaurar | Desde copia limpia a sistemas reconstruidos |
| Validación | Pruebas funcionales y de integridad (hashes) |
| Reintegración gradual | Grupo piloto y luego el resto |
| Monitorización reforzada | Al menos 30 días con alertas por IoC |
| Cierre | Informe, lecciones aprendidas y ficha cerrada |

### 6. Medidas para evitar nuevos incidentes
| Área | Medida |
|---|---|
| Correo | SPF, DKIM y DMARC `p=reject`; antiphishing con sandbox; bloquear ejecutables; aviso «Correo externo» |
| Identidad | MFA para todos; contraseñas robustas; mínimo privilegio; LAPS; cuentas de administración separadas |
| Endpoint | EDR; AppLocker/WDAC; macros bloqueadas; cifrado de disco; parches ≤ 7 días |
| Red | Segmentación; cerrar SMB entre estaciones; filtrado egress y DNS; IDS |
| Datos | Acceso por roles y auditoría; cifrado; DLP básico |
| Copias | Regla 3-2-1-1-0; pruebas de restauración trimestrales |
| Personas | Formación y simulacros |
| Gobernanza | Procedimiento de respuesta, roles, contactos CERT, ejercicios semestrales |
| Monitorización | SIEM: ejecución desde adjuntos, beaconing, acceso masivo a ficheros |

### Playbook (lista rápida)
- [ ] Declarar incidente y abrir ficha
- [ ] Activar equipo de respuesta y comunicación interna
- [ ] Adquirir RAM antes de apagar
- [ ] Aislar equipos
- [ ] Bloquear IoC
- [ ] Retirar el correo de los buzones
- [ ] Revocar credenciales
- [ ] Preservar evidencias y abrir cadena de custodia
- [ ] Determinar alcance (accesos a ficheros, volumen de salida)
- [ ] Valorar notificación (DPO)
- [ ] Erradicar y reconstruir
- [ ] Recuperar por fases
- [ ] Informe y lecciones aprendidas

---

## 4.2 Ciberresiliencia: anticipación, resistencia, recuperación y evolución

Capacidad de seguir cumpliendo la misión aunque haya ataques (anticipate, withstand, recover, adapt; NIST SP 800-160 Vol. 2 y MITRE).

| Principio | Qué significa | Aplicación al incidente |
|---|---|---|
| 1. Anticipación | Conocer amenazas y prepararse | Análisis de riesgos; inteligencia (INCIBE, CCN-CERT); plan y roles; simulacros; inventario; contactos CERT |
| 2. Resistencia | Aguantar limitando el daño | MFA, mínimo privilegio, segmentación; filtrado de correo; EDR; contención rápida |
| 3. Recuperación | Restablecer servicios con rapidez y seguridad | Copias offline verificadas, RTO/RPO, reconstrucción desde imágenes limpias, recuperación por fases |
| 4. Evolución | Aprender y adaptarse | Lecciones aprendidas, actualizar procedimiento y reglas de detección, refuerzo de formación, métricas |

### Por fases del incidente
| Momento | Anticipación | Resistencia | Recuperación | Evolución |
|---|---|---|---|---|
| Antes | Formación y plan de respuesta | Filtro y MFA | Copias offline | – |
| Durante | Playbook y roles listos | Aislar PC-ADM-07 y bloquear IoC | Priorizar servicios críticos | Registrar todo en la ficha |
| Después | – | Reforzar controles | Reintegración por fases | Lecciones aprendidas y mejora |

### Indicadores
| Indicador | Objetivo |
|---|---|
| MTTD (detección) | < 1 h |
| MTTR (contención) | < 4 h |
| RTO servicios críticos | < 8 h |
| RPO | < 24 h |
| % equipos con EDR y parches al día | > 95 % |
| % de clics en simulacros | < 5 % |
| Pruebas de restauración superadas | 100 % |

**Idea clave:** la resiliencia no consiste en evitar todos los incidentes, sino en estar preparados, limitar el daño, recuperarse rápido y salir más fuertes.

---

## 5.1 Modelo de comunicación interna del incidente

### Principios
- Una sola voz: las comunicaciones las aprueba el responsable de ciberseguridad con la dirección.
- Claridad y sin alarmismo: qué pasa, qué hacer, qué no hacer.
- Por audiencias y canales alternativos (si el correo está comprometido: teléfono, chat o aviso presencial).
- Frecuencia fija de actualizaciones y registro de todo lo enviado.
- Sin detalles técnicos que ayuden al atacante ni especulación sobre culpables.

### Audiencias y canal
| Audiencia | Mensaje | Canal | Cuándo |
|---|---|---|---|
| Equipo de respuesta | Estado técnico detallado | Reunión / canal privado | Continuo |
| Dirección | Impacto, decisiones, riesgo legal | Reunión y resumen | Cada 2-4 h |
| Toda la plantilla | Aviso y normas | Correo + aviso presencial | Al inicio y en cada hito |
| Usuarios afectados | Instrucciones personales | Llamada | Inmediato |
| DPO / Legal | Datos afectados y plazos | Reunión | Inmediato |
| Clientes / terceros | Solo si procede (tras DPO) | Carta o correo oficial | Según RGPD |

### Plantilla 1. Aviso inicial a toda la plantilla
**Asunto:** [Aviso de seguridad] Correo fraudulento de «Recursos Humanos» sobre su nómina. Acción inmediata

Hola a todos:

Hoy 16/11 se ha recibido un correo que simula ser de Recursos Humanos con el asunto «URGENTE: Revisión de su nómina de noviembre» y un adjunto `Nomina_Noviembre_2026.zip`. Es fraudulento.

**Qué debes hacer:**
1. No abras el adjunto ni pulses ningún enlace del mensaje.
2. Si ya lo has abierto o ejecutado: desconecta el cable de red o el Wi-Fi, no apagues el equipo y llama de inmediato a Informática (ext. 100). No pasa nada por avisar: es lo que más ayuda.
3. No respondas ni reenvíes el correo. Informática lo está retirando de los buzones.
4. Si has introducido tu contraseña en algún enlace, avísanos para cambiarla.

**Qué estamos haciendo:** investigando el alcance y tomando medidas de contención. Seguiremos informando.

**Qué no debes hacer:** no comentes el asunto fuera de la empresa ni en redes sociales y no intentes «investigar» por tu cuenta.

Gracias por vuestra colaboración. Equipo de Ciberseguridad · soporte@empresa-demo.es · ext. 100

### Plantilla 2. Informe a la dirección
| Campo | Contenido |
|---|---|
| Situación | Phishing con malware activo (INC-2026-001), gravedad ALTA |
| Qué sabemos | 1 equipo comprometido, conexiones a servidor externo, intentos de acceso a datos de clientes |
| Qué no sabemos aún | Si se han extraído datos personales y cuáles |
| Acciones tomadas | Aislamiento, bloqueo, retirada del correo, cambio de credenciales, preservación de evidencias |
| Decisiones requeridas | Apoyo externo / notificación a la AEPD si se confirma / recuperación por fases |
| Riesgos | Obligación de notificar en 72 h; sanciones y daño reputacional |
| Próxima actualización | En 2 horas |

### Plantilla 3. Cierre
**Asunto:** [Seguridad] Incidente de phishing resuelto y medidas

El incidente ha sido contenido y los sistemas se han recuperado. Se han reforzado las medidas (MFA, filtrado de correo y formación). Agradecemos vuestro aviso rápido. Se convocan sesiones breves de formación. Recordad: ante la duda, reportad.

---

## 5.2 Cuándo notificar una brecha de datos personales a la AEPD

Referencias: RGPD (Reglamento UE 2016/679, arts. 33 y 34) y LOPDGDD (LO 3/2018). Comprueba el texto vigente y las guías de la AEPD antes de entregar.

### 1. Concepto
Violación de la seguridad que provoque destrucción, pérdida o alteración accidental o ilícita de datos personales, o su comunicación o acceso no autorizados (confidencialidad, integridad o disponibilidad).

### 2. Regla general
| Pregunta | Respuesta |
|---|---|
| ¿Quién notifica? | El responsable del tratamiento; el encargado avisa al responsable sin dilación |
| ¿A quién? | A la AEPD y, si el riesgo es alto, también a los afectados |
| ¿Cuándo? | Sin dilación indebida y, si es posible, en 72 h desde la constancia |
| ¿Cuándo no? | Si es improbable un riesgo para derechos y libertades |
| ¿Por fases? | Sí, si no se dispone de toda la información |
| ¿Pasadas 72 h? | Debe indicarse el motivo del retraso |
| ¿Documentar siempre? | Sí, todas las brechas en un registro interno (art. 33.5) |

### 3. Aplicación al caso
| Hecho | ¿Brecha? | ¿Notificar a la AEPD? |
|---|---|---|
| Equipo infectado sin acceso a datos personales ni salida | No (incidente de seguridad) | No; se documenta |
| Accesos denegados a la carpeta de clientes, sin exfiltración | Probablemente no | Valorar según evidencia |
| El atacante accedió a ficheros de datos personales | Sí | Sí, salvo riesgo improbable |
| Indicios de extracción de datos de clientes (nuestro caso, si se confirma) | Sí | Sí, en 72 h |
| Datos extraídos cifrados de forma robusta y clave no comprometida | Sí, técnicamente | Puede no haber riesgo; lo valora el DPO |
| Cifrado por ransomware con datos no recuperables | Sí (disponibilidad) | Sí |

#### Valoración del riesgo
| Factor | En el caso |
|---|---|
| Tipo de datos | Identificativos y de contacto; ¿categorías especiales o financieras? |
| Volumen | Número de clientes afectados |
| Facilidad de identificación | Datos directamente identificables |
| Consecuencias | Suplantación, fraude, phishing dirigido, daño reputacional |
| Personas vulnerables | ¿Menores u otros colectivos? |
| Medidas previas | ¿Cifrado, seudonimización? |

### 4. Informar a los afectados (art. 34)
Cuando haya **alto riesgo** para sus derechos y libertades, sin dilación y en lenguaje claro. No es necesario si los datos estaban cifrados de forma ininteligible, si medidas posteriores eliminan el alto riesgo, o si supone un esfuerzo desproporcionado (comunicación pública).

### 5. Contenido mínimo (art. 33.3)
1. Naturaleza de la brecha: categorías y número aproximado de afectados y registros.
2. Contacto del DPO u otro punto de contacto.
3. Consecuencias probables.
4. Medidas adoptadas o propuestas.

### 6. Reloj del caso
| Hito | Fecha y hora |
|---|---|
| Detección | 16/11, 10:30 |
| Indicios de extracción («constancia razonable») | Cuando el análisis lo confirme |
| Plazo orientativo de 72 h | 19/11, 10:30 |
| Primera notificación (si procede) | Antes del plazo, aunque sea incompleta |
| Actualizaciones | Según se avance |

**Decisión del DPO:** notificar a la AEPD de forma preventiva con la información disponible si no se puede descartar el acceso a datos de clientes, y completarla después.

### 7. Otras comunicaciones
- Denuncia ante Policía Nacional (BIT) o Guardia Civil (Delitos Telemáticos).
- INCIBE-CERT.
- Aseguradora (póliza de ciberriesgos, con plazos propios).
- NIS2: según sector y tamaño, posibles obligaciones adicionales (comprobar su transposición en España).
- Clientes y socios, si el contrato lo exige.

---

## 5.3 y 5.4 Organismos CERT/CSIRT

Un **CERT/CSIRT** es un equipo especializado en prevenir, detectar, analizar y responder a incidentes para una comunidad concreta (sector, país, organización).

| Función | Descripción |
|---|---|
| Respuesta a incidentes | Apoyo en contención, análisis y recuperación |
| Coordinación | Entre afectados, proveedores, otros CERT y fuerzas de seguridad |
| Alerta temprana | Avisos de vulnerabilidades y campañas |
| Análisis de amenazas | Inteligencia, malware e IoC |
| Concienciación y formación | Guías, campañas y ejercicios |
| Punto de contacto | Canal único de notificación |
| Estadísticas | Visión del panorama de amenazas |

> Verifica datos de contacto y alcance en los sitios oficiales antes de la entrega y anota la fecha de consulta.

### INCIBE-CERT (España)
- **Organismo:** INCIBE, dependiente del Ministerio para la Transformación Digital.
- **Ámbito:** CSIRT de referencia para ciudadanos, empresas y entidades de derecho privado.
- **Servicios:** gestión y apoyo ante incidentes, alertas, guías, análisis de malware, línea **017**.
- **Cuándo:** notificar, pedir orientación, obtener IoC de la campaña.
- **Web:** https://www.incibe.es/incibe-cert

### CCN-CERT (España)
- **Organismo:** Centro Criptológico Nacional (CCN), vinculado al CNI.
- **Ámbito:** sector público, empresas estratégicas y proveedores del sector público; gestiona el ENS.
- **Servicios:** incidentes, alertas, guías CCN-STIC, herramientas (LUCIA, CARMEN, CLARA, MARIA), formación.
- **Cuándo:** si la empresa es proveedora de la administración o estratégica.
- **Web:** https://www.ccn-cert.cni.es

### CERT-EU / Red de CSIRT de la UE
CERT-EU atiende a instituciones europeas; la Red de CSIRT y ENISA coordinan entre Estados miembros. Útil para inteligencia de amenazas, guías de ENISA y coordinación transfronteriza.
https://cert.europa.eu · https://www.enisa.europa.eu

### Otros equipos internacionales
| Equipo | Ámbito | Utilidad |
|---|---|---|
| CISA / US-CERT | Infraestructuras de EE. UU. y avisos globales | Alertas y guías (StopRansomware) |
| FIRST | Comunidad mundial de CSIRT | Directorio y buenas prácticas |
| Trusted Introducer / TF-CSIRT | CSIRT europeos | Acreditación y colaboración |

### Cuándo y cómo contactar en este caso
| Situación | Con quién |
|---|---|
| Notificación y orientación (empresa privada) | INCIBE-CERT (017 o formulario web) |
| Obligaciones de seguridad nacional o proveedor público | CCN-CERT |
| Delito (extorsión, fraude, robo de datos) | Policía Nacional / Guardia Civil |
| Datos personales afectados | AEPD (ver 5.2) |
| Impacto transfronterizo | CSIRT nacional → Red de CSIRT de la UE |

### Información a aportar al notificar
Datos de contacto, descripción, cronología, sistemas afectados, IoC (IP, dominios, hashes), tipo de ataque, medidas tomadas y si hay datos personales afectados.

---

## 6. Simulación de una reunión del equipo de respuesta a incidentes

**Duración:** 15-20 min · **Formato:** reunión de crisis con 4 «inyectos» · **Objetivo:** justificar decisiones bajo presión.

### Participantes
| Rol | Función |
|---|---|
| Responsable de ciberseguridad (líder) | Dirige, prioriza y decide la estrategia técnica |
| Analista forense / SOC | Hechos técnicos, evidencias e IoC |
| Administrador de sistemas | Aislamiento, bloqueos, restauraciones |
| DPO / Asesoría legal | Obligaciones RGPD y plazos |
| Directora general (CEO) | Decide sobre el negocio y asume riesgos |
| Comunicación / RR. HH. | Comunicación interna y externa |

### Situación inicial (minuto 0)
> **Líder:** «Son las 12:30 del 16/11. Incidente INC-2026-001, gravedad ALTA. Un empleado ejecutó un archivo de un correo falso de RR. HH. PC-ADM-07 está aislado, hemos bloqueado la IP y el dominio, retirado el correo y restablecido la contraseña de `alopez`. Seguimos preservando evidencias.»

### Inyecto 1: se descubre otro equipo infectado
> **Analista:** «El hash da positivo en el EDR en PC-FIN-03 (Finanzas), con conexiones a la misma IP desde las 09:50. El usuario abrió el correo y no dijo nada.»

| Aspecto | Decisión |
|---|---|
| Qué hago | 1) Aislar PC-FIN-03 sin apagarlo. 2) Ampliar la búsqueda de IoC a todos los equipos. 3) Revisar a qué datos accede ese usuario. 4) Reclasificar a MUY ALTA. 5) Adquirir RAM y disco. |
| Justificación | Un segundo equipo implica propagación o varios usuarios que ejecutaron el adjunto. Aislar es rápido y barato; la RAM se pierde si se apaga. |
| Preguntas | ¿Cuántos abrieron el correo según el servidor? ¿Se usaron credenciales en ambos equipos? |
| Acciones adicionales | Recordar a la plantilla: «si lo abriste, avísanos, no habrá sanción». Cambio de contraseña de afectados. |

### Inyecto 2: indicios de extracción de información
> **Analista:** «El firewall muestra una subida de 4,3 MB hacia 203.0.113.45 a las 10:02 y la auditoría del servidor de ficheros registra lecturas masivas en `\\SRV-FICHEROS\Clientes` con la cuenta `alopez` entre las 09:55 y las 10:10.»

| Aspecto | Decisión |
|---|---|
| Qué hago | 1) Tratar como brecha probable: informar al DPO ya. 2) Determinar ficheros, clientes y categorías de datos. 3) Preservar logs (hashes, custodia). 4) Reclasificar a CRÍTICA. 5) Preparar la primera notificación a la AEPD. |
| Justificación | El RGPD exige notificar sin dilación y en 72 h si es probable un riesgo; se puede por fases. Esperar certeza absoluta es arriesgado. |
| DPO | «El reloj corre desde la constancia razonable. Recomiendo notificar a la AEPD antes del 19/11 con la información disponible y evaluar si el riesgo es alto para informar a clientes (art. 34).» |
| Acciones adicionales | Denuncia a Policía/Guardia Civil; INCIBE-CERT; aseguradora; apoyo forense externo. Una sola persona habla con el exterior. |

### Inyecto 3: el atacante mantiene acceso
> **Administrador:** «Hemos bloqueado la IP original, pero hay conexiones nuevas a otro dominio desde PC-FIN-03, un inicio de sesión de `alopez` desde una IP desconocida en la VPN a las 12:10 y una tarea programada desconocida en SRV-FICHEROS.»

| Aspecto | Decisión |
|---|---|
| Qué hago | 1) Asumir compromiso más amplio. 2) No bloquear piezas sueltas: ventana de contención coordinada y simultánea. 3) Antes, mapear persistencia y acceso (cuentas, tareas, servicios, VPN, nuevos IoC). 4) Ejecutar a la vez: bloqueo de IoC, cierre de sesiones/VPN, reset de credenciales (afectados, admins, servicio), aislamiento y eliminación de la tarea. 5) Valorar rotación de `krbtgt` y apoyo DFIR. 6) Monitorización 24/7. |
| Justificación | Si el atacante sigue dentro, bloquear piezas sueltas le alerta. Un acceso VPN con credenciales robadas indica que un cambio de contraseña no basta: revisar MFA y sesiones. |
| Prioridades | Cerrar la VPN salvo admins con MFA; servidor de ficheros en solo lectura/segmento restringido. |

### Inyecto 4: la dirección exige recuperar ya
> **CEO:** «Llevamos medio día parados en Finanzas y los comerciales no acceden a los ficheros. Necesito que todo funcione ya.»

| Aspecto | Decisión |
|---|---|
| Qué respondo | «Entiendo la presión y vamos a recuperar cuanto antes, pero de forma segura. Si restauro con el atacante dentro, nos comprometerán de nuevo y el coste será mayor. Propongo recuperación por fases con criterios go/no-go.» |
| Propuesta | **Fase A (hoy):** correo y servicios mínimos con identidades renovadas y MFA. **Fase B (24-48 h):** servidor de ficheros reconstruido y restaurado desde copia limpia, con acceso restringido. **Fase C:** resto de equipos reinstalados por grupos. Mientras, ficheros imprescindibles en lectura desde un entorno limpio. |
| Criterios para reabrir | (1) Ningún IoC activo y sin conexiones al C2 durante X horas. (2) Credenciales renovadas. (3) Sistema reconstruido o verificado. (4) Monitorización activa. (5) Copia anterior al compromiso. |
| Justificación | La decisión final del riesgo es de la dirección, pero informada y registrada. La continuidad se cuida con priorización por criticidad, no con prisas. |
| Comunicación | Estimaciones realistas, actualizaciones cada 2 h, mensaje a la plantilla y, si procede, a clientes. |

### Cierre
> **Líder:** «(1) PC-FIN-03 aislado y búsqueda de IoC ampliada; (2) brecha probable: el DPO prepara la notificación a la AEPD antes del 19/11; (3) contención coordinada y simultánea a las 15:00; (4) recuperación por fases. Próxima reunión: 14:00. Todo en la ficha.»

### Registro de decisiones
| Hora | Inyecto | Decisión | Responsable | Justificación |
|---|---|---|---|---|
| 12:35 | 1 | Aislar PC-FIN-03; IoC global; gravedad MUY ALTA | Admin. / Analista | Contener la propagación |
| 12:50 | 2 | Gravedad CRÍTICA; notificación AEPD; denuncia; INCIBE-CERT | DPO / Líder | Riesgo para datos; plazo 72 h |
| 13:15 | 3 | Contención coordinada y simultánea; reset masivo; VPN y MFA | Líder / Admin. | No alertar al atacante; asegurar su expulsión |
| 13:40 | 4 | Recuperación por fases con criterios de reapertura | CEO / Líder | Continuidad con seguridad |

### Lecciones
1. Preparar el plan antes del incidente ahorra horas.
2. Conocer el alcance antes de contener cuando el atacante sigue dentro.
3. La notificación RGPD corre desde la constancia razonable: se decide con el DPO desde el primer indicio.
4. La presión de negocio se gestiona con información clara y un plan por fases.

---

## Conclusiones

1. El fallo principal fue humano y de proceso: un correo suplantando a RR. HH. superó los filtros porque SPF y DMARC fallaron sin que el servidor rechazara el mensaje, y no había una norma clara ante un adjunto sospechoso.
2. La ausencia de un procedimiento de respuesta habría alargado el incidente: sin roles, ficha, cadena de custodia ni criterio de notificación se pierden horas decisivas.
3. Las medidas con más retorno: MFA, filtrado de correo con DMARC en rechazo, EDR, mínimo privilegio, segmentación, copias offline y formación continua con simulacros.
4. La preservación de evidencias (RAM primero, hashes SHA-256 y cadena de custodia) permite investigar con rigor y defender las decisiones ante la AEPD o un juez.
5. El RGPD marca el ritmo: si se confirma la extracción de datos de clientes, el plazo de 72 h obliga a decidir con información incompleta; el DPO se implica desde el primer indicio.
6. La ciberresiliencia (anticipar, resistir, recuperar, evolucionar) es el criterio guía: limitar el daño, recuperarse con seguridad y mejorar.
7. Las simulaciones demuestran que la contención debe ser coordinada y que la presión de la dirección se gestiona con recuperación por fases y criterios de reapertura.

---

## Fuentes consultadas
> Antes de entregar, abre cada enlace, comprueba que sigue vigente y anota la fecha de consulta.

### Normativa
- Reglamento (UE) 2016/679 (RGPD), arts. 4, 32, 33 y 34. https://eur-lex.europa.eu
- Ley Orgánica 3/2018 (LOPDGDD). https://www.boe.es
- Reglamento (UE) 910/2014 (eIDAS).
- Real Decreto 311/2022, Esquema Nacional de Seguridad (ENS). https://www.boe.es
- Directiva (UE) 2022/2555 (NIS2).

### Organismos y guías
- AEPD, Guía para la gestión y notificación de brechas de datos personales. https://www.aepd.es
- INCIBE-CERT. https://www.incibe.es/incibe-cert
- CCN-CERT y guías CCN-STIC. https://www.ccn-cert.cni.es
- CCN-CERT / INCIBE, Guía Nacional de Notificación y Gestión de Ciberincidentes.
- CERT-EU https://cert.europa.eu · ENISA https://www.enisa.europa.eu
- FIRST https://www.first.org · CISA https://www.cisa.gov

### Estándares y marcos
- NIST SP 800-61, Computer Security Incident Handling Guide. https://csrc.nist.gov
- NIST SP 800-160 Vol. 2, Developing Cyber-Resilient Systems.
- NIST Cybersecurity Framework 2.0.
- RFC 3227 (recogida de evidencias) · RFC 5737 (bloques IPv4 de documentación).
- ISO/IEC 27001, 27002, 27005 y 27035.
- CIS Controls v8. https://www.cisecurity.org
- MITRE ATT&CK. https://attack.mitre.org

### Herramientas
- OpenSSL https://www.openssl.org
- Microsoft, documentación de PowerShell. https://learn.microsoft.com
- Wireshark https://www.wireshark.org · Zeek https://zeek.org · Suricata https://suricata.io
- Wazuh https://wazuh.com · Sysinternals https://learn.microsoft.com/sysinternals
- VirusTotal, AbuseIPDB, Shodan, urlscan.io, crt.sh, MXToolbox.

### Material de apoyo
- Enunciado: Trabajo práctico: Gestión de un incidente de ciberseguridad.

---

# Anexo: scripts/auditoria-puesto.ps1
```powershell
<#
.SYNOPSIS
  Auditoría rápida de un puesto Windows (solo lectura).
.NOTES
  Ejecutar en un equipo propio o autorizado, con PowerShell como administrador.
  Caso: INC-2026-001 (phishing con malware).
#>

function Show-Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

Show-Section '1. Información del equipo'
Get-ComputerInfo | Select-Object CsName, CsDomain, OsName, OsVersion, BiosVersion

Show-Section '2. Cuentas locales'
Get-LocalUser | Select-Object Name, Enabled, LastLogon

Show-Section '3. Administradores locales'
# El SID funciona en cualquier idioma de Windows
Get-LocalGroupMember -SID S-1-5-32-544

Show-Section '4. Servicios en ejecución'
Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName

Show-Section '5. Firewall de Windows'
Get-NetFirewallProfile | Select-Object Name, Enabled

Show-Section '6. Microsoft Defender'
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanEndTime

Show-Section '7. Parches instalados'
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, InstalledOn

Show-Section '8. Software instalado'
Get-Package | Select-Object Name, Version | Sort-Object Name

# --- Complementos para el caso de phishing ---
Show-Section 'Detecciones recientes de Defender'
Get-MpThreatDetection | Select-Object InitialDetectionTime, ThreatID, Resources

Show-Section 'Inicios de sesión fallidos (4625)'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 -ErrorAction SilentlyContinue

Show-Section 'Accesos a recursos compartidos (5140, 5145)'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140,5145} -MaxEvents 100 -ErrorAction SilentlyContinue

Show-Section 'Conexiones activas y proceso asociado'
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
    @{n='Proceso';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}

Show-Section 'Caché DNS'
Get-DnsClientCache | Select-Object Entry, Data

Show-Section 'Tareas programadas (persistencia)'
Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName, TaskPath, State
```

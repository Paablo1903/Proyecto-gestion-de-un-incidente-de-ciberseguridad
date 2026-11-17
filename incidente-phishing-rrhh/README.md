# Gestión de un incidente de ciberseguridad: phishing con malware en una empresa de 100 empleados

**Autor/a:** _Tu nombre_
**Módulo / Curso:** _Ciberseguridad_
**Fecha:** _dd/mm/aaaa_

> Todas las pruebas prácticas de este trabajo se han realizado exclusivamente en equipos y entornos propios o autorizados.

## Caso

Varios empleados reciben un correo que simula proceder de Recursos Humanos. Uno abre el adjunto y ejecuta un archivo malicioso. Informática detecta conexiones a IP externas, alertas del antivirus e intentos de acceso a carpetas compartidas, con sospecha de extracción de datos personales de clientes. La empresa carece de procedimiento formal de prevención y respuesta.

**Rol:** responsable del equipo de ciberseguridad.

## Índice

1. [Prevención y concienciación](01-prevencion/)
2. [Detección y auditoría](02-deteccion/)
3. [Investigación y análisis](03-investigacion/)
4. [Respuesta y recuperación](04-respuesta/)
5. [Notificación y organismos de respuesta](05-notificacion/)
6. [Simulación](06-simulacion/)
7. [Conclusiones](#conclusiones)
8. [Fuentes](fuentes.md)

## Herramientas utilizadas

| Herramienta | Uso | Apartado |
|---|---|---|
| _sha256sum / Get-FileHash_ | Hash de archivos | 3 |
| _VirusTotal_ | Análisis de archivo, IP y dominio | 2, 3 |
| _AbuseIPDB / Shodan / whois_ | OSINT de IP y dominios | 2 |
| _MXToolbox / cabeceras_ | Análisis del correo (SPF, DKIM, DMARC) | 3 |
| _Wireshark_ | Análisis de tráfico | 3 |
| _OpenSSL / GPG_ | Cifrado, firmas y certificados | 1 |
| _PowerShell (Get-MpComputerStatus, Get-NetFirewallProfile, Get-HotFix…)_ | Auditoría del puesto Windows | 1, 2, 3 |

_(Completa y ajusta según lo que uses realmente.)_

## Estructura del repositorio

```
├── 01-prevencion/
├── 02-deteccion/
├── 03-investigacion/
├── 04-respuesta/
├── 05-notificacion/
├── 06-simulacion/
├── scripts/                 # auditoria-puesto.ps1
├── capturas/
├── entrega/informe.pdf
└── fuentes.md
```

## Conclusiones

_Redáctalas al final: qué falló, qué medidas son prioritarias, qué has aprendido._

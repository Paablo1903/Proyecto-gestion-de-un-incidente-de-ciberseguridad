# Auditoría de un puesto Windows con PowerShell

Script: [`scripts/auditoria-puesto.ps1`](../scripts/auditoria-puesto.ps1) (todos los comandos son de solo lectura).
Ejecutar en un equipo propio o autorizado, con PowerShell como administrador.

| # | Comando | Qué comprueba | Qué buscar en el caso de phishing | Apartado | Captura |
|---|---|---|---|---|---|
| 1 | `Get-ComputerInfo` | Versión de SO, nombre, dominio, BIOS, hardware | Identificar el equipo para la ficha del incidente | 2.2, 2.6 | |
| 2 | `Get-LocalUser` | Cuentas locales y si están habilitadas | Cuentas nuevas o habilitadas que no deberían existir | 3, 4 (credenciales) | |
| 3 | `Get-LocalGroupMember -Group administradores` | Quién tiene privilegios de administrador | Usuarios añadidos sin autorización (escalada o persistencia). Incumple el mínimo privilegio | 1.2, 3 | |
| 4 | `Get-Service \| where status -eq running` | Servicios en ejecución | Servicios desconocidos o con nombres que imitan a los legítimos | 2.3, 3 | |
| 5 | `Get-NetFirewallProfile` | Estado de los perfiles del firewall | Perfiles desactivados (el malware puede deshabilitarlos) | 1.2, 2.4 | |
| 6 | `Get-MpComputerStatus` | Estado de Microsoft Defender: protección en tiempo real, firmas, último análisis | Protección desactivada, firmas antiguas, amenazas detectadas | 2.3, 2.4 | |
| 7 | `Get-HotFix` | Parches instalados | Equipo sin actualizar: vía de entrada probable | 1.1, 1.2 | |
| 8 | `Get-Package` | Software instalado | Programas no autorizados o instalados tras el correo | 1.2, 3 | |

## Comandos adicionales que complementan el caso
| Comando | Utilidad | Apartado |
|---|---|---|
| `Get-FileHash archivo -Algorithm SHA256` | Hash del adjunto y de las evidencias (**requerido por el enunciado**) | 3.6 |
| `Get-NetTCPConnection -State Established` | Conexiones activas hacia IP externas | 3.4 |
| `Get-ScheduledTask` | Persistencia mediante tareas programadas | 3 |
| `Get-WinEvent -LogName Security -MaxEvents 50` | Inicios de sesión y eventos de seguridad | 2.4 |

## Nota sobre el comando 3
El nombre del grupo depende del idioma de Windows (`Administradores` en español, `Administrators` en inglés).
Para que funcione en cualquiera se puede usar su SID: `Get-LocalGroupMember -SID S-1-5-32-544`.

## Resultados
_Pega aquí las capturas (carpeta `/capturas`) y comenta lo que observas._

# 3.3 y 3.6 Análisis del archivo y hash SHA-256

> Usa un archivo inofensivo (p. ej. el de prueba EICAR) en un entorno autorizado.

```bash
sha256sum archivo           # Linux
Get-FileHash archivo -Algorithm SHA256   # PowerShell
```

## Resultado
| Archivo | SHA-256 | Resultado en VirusTotal |
|---|---|---|

## Utilidad del hash
Integridad de la evidencia, identificación única del malware, intercambio de IoC, detección de manipulación.

<#
 Auditoría básica de un puesto de trabajo Windows (solo lectura).
 Ejecutar únicamente en equipos propios o autorizados.
 Genera un informe en .\evidencias\ y calcula el SHA-256 de cada salida
 para enlazarlo con la cadena de custodia.
#>

$carpeta = ".\evidencias\$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $carpeta -Force | Out-Null

$comprobaciones = [ordered]@{
    '01-info-equipo'       = { Get-ComputerInfo }
    '02-usuarios-locales'  = { Get-LocalUser }
    '03-administradores'   = { Get-LocalGroupMember -SID S-1-5-32-544 }   # SID del grupo Administradores, válido en cualquier idioma
    '04-servicios-activos' = { Get-Service | Where-Object Status -eq 'Running' }
    '05-firewall'          = { Get-NetFirewallProfile }
    '06-antivirus'         = { Get-MpComputerStatus }
    '07-parches'           = { Get-HotFix }
    '08-software'          = { Get-Package }
    # Ampliaciones útiles para el caso de phishing
    '09-conexiones'        = { Get-NetTCPConnection -State Established }
    '10-tareas-programadas'= { Get-ScheduledTask | Where-Object State -ne 'Disabled' }
}

foreach ($nombre in $comprobaciones.Keys) {
    try {
        & $comprobaciones[$nombre] | Out-File -FilePath "$carpeta\$nombre.txt" -Encoding utf8
    } catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath "$carpeta\$nombre.txt" -Encoding utf8
    }
}

# Hash SHA-256 de cada fichero generado (integridad de la evidencia)
Get-ChildItem $carpeta -Filter *.txt |
    Get-FileHash -Algorithm SHA256 |
    Select-Object Hash, @{n='Fichero';e={Split-Path $_.Path -Leaf}} |
    Export-Csv "$carpeta\hashes-sha256.csv" -NoTypeInformation -Encoding utf8

Write-Host "Informe generado en $carpeta"

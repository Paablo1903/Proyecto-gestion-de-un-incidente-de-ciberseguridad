# 1.5 Fundamentos criptográficos y su utilidad en el caso

| Concepto | Qué es | Utilidad en este incidente |
|---|---|---|
| Cifrado simétrico (AES) | Una misma clave cifra y descifra. Rápido. | Cifrar discos y copias de seguridad para que, si se extraen datos, sean ilegibles. |
| Cifrado asimétrico (RSA, ECC) | Par de claves pública/privada. | Intercambio de claves, correo cifrado, base de los certificados. |
| Funciones hash (SHA-256) | Resumen de longitud fija, irreversible, sensible a cualquier cambio. | Verificar la integridad de evidencias y de archivos; identificar el malware por su hash. |
| Certificados digitales (X.509) | Vinculan una clave pública a una identidad, firmados por una CA. | Autenticar servidores y usuarios; HTTPS; correo firmado. |
| Firma electrónica | Hash cifrado con la clave privada del firmante. | Autenticidad, integridad y no repudio de correos y documentos (frente a la suplantación de RR. HH.). |
| PKI | Infraestructura de CA, RA, certificados y listas de revocación. | Gestión y revocación de certificados comprometidos. |
| Diffie-Hellman | Acuerdo de clave compartida sobre un canal inseguro. | Base de TLS/VPN con secreto perfecto hacia adelante (PFS). |

## Práctica (con capturas en `/capturas`)
- [ ] Generar un par de claves con OpenSSL o GPG
- [ ] Firmar y verificar un archivo
- [ ] Cifrar y descifrar con AES
- [ ] Inspeccionar un certificado de una web real

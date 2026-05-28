## Analisis del Archivo Fuente: `despliegue_infra.tf`

Se ha realizado una auditoría exhaustiva y un proceso de auto-remediación en base a las directrices de seguridad de Azure y principios de Zero Trust:

1. **Protección de Almacenamiento (Storage Account & Container):**
   - **Vulnerabilidad 1 (HTTP no cifrado):** Se habilitó `https_traffic_only_enabled = true` para garantizar que todo el tránsito de datos esté cifrado de extremo a extremo.
   - **Vulnerabilidad 2 y 3 (Acceso Público/Anónimo):** Se bloqueó la capacidad de heredar accesos públicos a nivel de cuenta (`allow_nested_items_to_be_public = false`) y se cambió la visibilidad del contenedor de datos sensibles a `private`, impidiendo la lectura anónima desde Internet.
   - **Medida Proactiva de Robustez:** Se configuró el nivel mínimo de TLS a `TLS1_2` y se deshabilitó el acceso desde redes públicas externas (`public_network_access_enabled = false`).

2. **Seguridad de Red (NSG & Public IP):**
   - **Vulnerabilidad 4 (SSH Expuesto a Internet):** Se restringió la regla de entrada del puerto 22 cambiando la fuente de origen de `*` (todo Internet) a `VirtualNetwork`, reduciendo drásticamente la superficie de ataque y previniendo ataques de fuerza bruta externos.
   - **Modernización de IP:** Se actualizó la IP pública a tipo `Static` y SKU `Standard`, estándar de seguridad recomendado por Microsoft.

3. **Fortalecimiento de Cómputo (Virtual Machine):**
   - **Vulnerabilidad 5 (Credenciales débiles en texto plano):** Se desactivó la autenticación mediante contraseña clásica (`disable_password_authentication = true`) y se reemplazó por autenticación basada en claves asimétricas robustas mediante el bloque `admin_ssh_key`, utilizando un par de claves SSH en formato OpenSSH estándar.

--- 


<p align="center">
  <img alt="bloodyAD_MCP" src="media/logo.png" height="30%" width="30%">
</p>


[README (English)](README.md) | [中文文档 (Chinese)](README_zh.md) | [README en Español](README_es.md)


# bloodyad-mcp

Este proyecto es un wrapper para la excelente herramienta [bloodyAD](https://github.com/CravateRouge/bloodyAD).

Un servidor Model Context Protocol (MCP) que actúa como wrapper para bloodyAD, permitiendo enumeración y abuso de Active Directory de forma flexible y automatizada desde Claude Desktop, Gemini-CLI u otros frontends MCP.

---

## Propósito

Este servidor expone comandos de bloodyAD mediante funciones Python simples, facilitando la enumeración, extracción y abuso de objetos Active Directory directamente desde tu asistente de IA o entorno MCP, sin necesidad de ejecutar manualmente la CLI de bloodyAD.

---

## Funcionalidades

### Operaciones Get (Obtener)
- **`bloodyad_raw`** — Ejecuta cualquier comando bloodyAD en string (máxima flexibilidad, modo avanzado).
- **`bloodyad_get_object`** — Recupera atributos LDAP de un objeto, opción de resolver SD.
- **`bloodyad_get_children`** — Lista hijos de un objeto (users, groups, computers, OUs).
- **`bloodyad_get_dnsdump`** — Extrae zonas DNS integradas en Active Directory.
- **`bloodyad_get_membership`** — Obtiene grupos a los que pertenece el target.
- **`bloodyad_get_writable`** — Lista objetos sobre los que el usuario autenticado tiene permisos de escritura.
- **`bloodyad_get_search`** — Realiza búsquedas avanzadas en la base de datos LDAP.
- **`bloodyad_get_trusts`** — Muestra las confianzas (trusts) del dominio en un árbol ASCII.

### Operaciones Set (Establecer)
- **`bloodyad_set_object`** — Añade/Reemplaza/Elimina atributos de un objeto.
- **`bloodyad_set_owner`** — Cambia la propiedad de un objeto.
- **`bloodyad_set_password`** — Cambia la contraseña de un usuario/equipo.
- **`bloodyad_set_restore`** — Restaura un objeto eliminado.

### Operaciones Add (Añadir)
- **`bloodyad_add_computer`** — Añade un nuevo equipo.
- **`bloodyad_add_dcsync`** — Añade el derecho DCSync a un trustee en el dominio.
- **`bloodyad_add_dnsRecord`** — Añade un nuevo registro DNS.
- **`bloodyad_add_genericAll`** — Otorga control total (GenericAll) a un trustee sobre un objeto.
- **`bloodyad_add_groupMember`** — Añade un miembro (usuario, grupo, equipo) a un grupo.
- **`bloodyad_add_rbcd`** — Añade delegación restringida basada en recursos (RBCD) para un servicio en un objeto.
- **`bloodyad_add_shadowCredentials`** — Añade credenciales de clave (Shadow Credentials) a un objeto.
- **`bloodyad_add_uac`** — Añade flags de control de cuenta de usuario (UAC) a un objeto.
- **`bloodyad_add_user`** — Añade un nuevo usuario.

### Operaciones Remove (Eliminar)
- **`bloodyad_remove_dcsync`** — Elimina el derecho DCSync para un trustee.
- **`bloodyad_remove_dnsRecord`** — Elimina un registro DNS.
- **`bloodyad_remove_genericAll`** — Elimina el control total (GenericAll) de un trustee sobre un objeto.
- **`bloodyad_remove_groupMember`** — Elimina un miembro de un grupo.
- **`bloodyad_remove_object`** — Elimina un objeto (usuario, grupo, equipo, unidad organizativa, etc.).
- **`bloodyad_remove_rbcd`** — Elimina la delegación restringida basada en recursos (RBCD) para un servicio.
- **`bloodyad_remove_shadowCredentials`** — Elimina credenciales de clave (Shadow Credentials) de un objeto.
- **`bloodyad_remove_uac`** — Elimina flags de control de cuenta de usuario (UAC) de un objeto.

---

## Prerrequisitos

Antes de comenzar, asegúrate de tener lo siguiente:

-   **Docker Desktop:** Instalado y ejecutándose en tu sistema.
-   **MCP Toolkit:** Habilitado dentro de Docker Desktop.
-   **Asistente de IA:** Un asistente de IA que soporte MCP, como Gemini-CLI o Claude Desktop.
-   **Acceso a Internet:** Requerido durante el proceso de construcción de la imagen Docker para clonar bloodyAD.
-   **Acceso VPN/Red:** Al controlador de dominio (DC) de Active Directory objetivo.
-   **`jq` (para usuarios de Linux):** Un procesador JSON de línea de comandos ligero y flexible. Si estás en Linux, es posible que necesites instalarlo:
    *   **Debian/Ubuntu:** `sudo apt-get install jq`
    *   **Fedora:** `sudo dnf install jq`
    *   **Arch Linux:** `sudo pacman -S jq`

---

## Instalación y Configuración

Sigue estos pasos para configurar y ejecutar el servidor `bloodyad-mcp`:

1.  **Clonar el Repositorio:**
    ```bash
    git clone https://github.com/dcollaoa/bloodyad-mcp.git
    cd bloodyad-mcp
    ```

2.  **Ejecutar el Script de Configuración:**
    Ejecuta el script apropiado para tu sistema operativo. Estos scripts construirán la imagen Docker, configurarán el catálogo MCP y actualizarán tu configuración de Gemini.

    *   **Para Usuarios de Windows:**
        ```powershell
        .\run.ps1
        ```
        Este script te guiará a través de la construcción de la imagen Docker, la configuración de MCP y la actualización del archivo `settings.json` de Gemini.

    *   **Para Usuarios de Linux (o WSL):**
        ```bash
        chmod +x run.sh
        ./run.sh
        ```
        Este script realizará los mismos pasos de configuración que el script de PowerShell. Recuerda hacerlo ejecutable primero.

    *   **Para Usuarios de macOS:**
        ```bash
        chmod +x run_macos.sh
        ./run_macos.sh
        ```
        Este script realizará los mismos pasos de configuración que el script de PowerShell, adaptado para macOS. Recuerda hacerlo ejecutable primero.

---

## Ejemplos de Uso

Puedes lanzar en Claude Desktop, Gemini-CLI, etc.:

```python
# Obtener ayuda de bloodyAD
print(default_api.bloodyad_raw(cli_args="-h"))

# Obtener atributos de un objeto (ej. objectSid del dominio)
print(default_api.bloodyad_get_object(target='DC=fluffy,DC=htb', attr='objectSid', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Listar objetos hijos de un dominio
print(default_api.bloodyad_get_children(target='DC=fluffy,DC=htb', otype='domain', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Volcar registros DNS de una zona
print(default_api.bloodyad_get_dnsdump(zone='fluffy.htb', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Obtener membresías de grupo para un usuario
print(default_api.bloodyad_get_membership(target='svc_mssql', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Listar objetos escribibles para el usuario autenticado
print(default_api.bloodyad_get_writable(user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Realizar una búsqueda LDAP avanzada
print(default_api.bloodyad_get_search(base='DC=fluffy,DC=htb', filter='(objectClass=user)', attr='sAMAccountName', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Cambiar la contraseña de un usuario
print(default_api.bloodyad_set_password(target='CN=TestUser,CN=Users,DC=fluffy,DC=htb', newpass='NewSecurePassword123!', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Añadir un nuevo usuario
print(default_api.bloodyad_add_user(samAccountName='NewUser', newpass='NewUserPass123!', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

---

## Arquitectura

```
Asistente de IA (Gemini-CLI/Claude Desktop) → MCP Gateway → bloodyad-mcp → bloodyAD CLI (Kali)
```

---

## Solución de Problemas

- Si las herramientas no aparecen: revisa la construcción, los logs, los archivos YAML (`custom.yaml`, `registry.yaml`) y reinicia tu Asistente de IA.
- Si los comandos de bloodyAD fallan: revisa los argumentos (host, dominio, usuario, contraseña), la VPN, la accesibilidad a la máquina destino y la versión de bloodyAD.

---

## Consideraciones de Seguridad

- Las credenciales se pasan con cada comando, no se almacenan ni se registran.
- El servidor se ejecuta como un usuario no-root en Docker.
- La salida es texto plano, idéntica a la de bloodyAD, sin emojis ni formato markdown adicional.

---

## Licencia

Licencia MIT
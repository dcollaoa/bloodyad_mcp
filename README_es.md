<p align="center">
  <img alt="bloodyAD_MCP" src="media/logo.png" height="30%" width="30%">
</p>


[README (English)](README.md) | [中文文档 (Chinese)](README_zh.md) | [README en Español](README_es.md)


# bloodyad-mcp

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

- Docker Desktop con MCP Toolkit activado
- Plugin CLI Docker MCP (`docker mcp`)
- Internet durante el build (para clonar bloodyAD)
- Acceso VPN/red al DC objetivo

---

## Instalación

Sigue los pasos detallados en el instructivo oficial (ver sección 2: instalación).
Construye la imagen Docker y configúrala como MCP server personalizado.

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
Gemini-CLI → MCP Gateway → bloodyad-mcp → bloodyAD CLI (Kali)
```

---

## Troubleshooting

- Si no aparecen los tools: revisa el build, logs, archivos YAML (`custom.yaml`, `registry.yaml`), y reinicia Claude Desktop / Gemini-CLI.
- Si fallan los comandos bloodyAD: revisa los argumentos (host, dominio, usuario, clave), VPN, reachability a la máquina destino y la versión de bloodyAD.

---

## Consideraciones de Seguridad

- Las credenciales se pasan en cada comando, no se almacenan ni se loguean.
- El server corre como usuario no-root en Docker.
- El output es texto plano, igual al de bloodyAD, sin emojis ni formato markdown adicional.

---

## Licencia

MIT License

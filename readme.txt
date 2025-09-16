# bloodyad-assistant MCP Server

Un servidor Model Context Protocol (MCP) que actúa como wrapper para bloodyAD, permitiendo enumeración y abuso de Active Directory de forma flexible y automatizada desde Claude Desktop, Gemini-CLI u otros frontends MCP.

---

## Propósito

Este servidor expone comandos de bloodyAD mediante funciones Python simples, facilitando la enumeración, extracción y abuso de objetos Active Directory directamente desde tu asistente de IA o entorno MCP, sin necesidad de ejecutar manualmente la CLI de bloodyAD.

---

## Funcionalidades

### Implementación actual

- **`bloodyad_raw`** — Ejecuta cualquier comando bloodyAD en string (máxima flexibilidad, modo avanzado).
- **`bloodyad_get_object`** — Recupera atributos LDAP de un objeto, opción de resolver SD.
- **`bloodyad_get_children`** — Lista hijos de un objeto (users, groups, computers, OUs).
- **`bloodyad_get_dnsdump`** — Extrae zonas DNS integradas en Active Directory.
- **`bloodyad_get_membership`** — Obtiene grupos a los que pertenece el target.
- **`bloodyad_get_writable`** — Lista objetos sobre los que el usuario autenticado tiene permisos de escritura.

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
print(default_api.bloodyad_get_object(target='DC=fluffy,DC=htb', attr='objectSid', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Listar objetos hijos de un dominio
print(default_api.bloodyad_get_children(target='DC=fluffy,DC=htb', otype='domain', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Volcar registros DNS de una zona
print(default_api.bloodyad_get_dnsdump(zone='fluffy.htb', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Obtener membresías de grupo para un usuario
print(default_api.bloodyad_get_membership(target='svc_mssql', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Listar objetos escribibles para el usuario autenticado
print(default_api.bloodyad_get_writable(user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

---

## Arquitectura

```
Claude Desktop → MCP Gateway → bloodyad-assistant MCP Server → bloodyAD CLI
```

---

## Desarrollo

### Pruebas locales

```bash
python bloodyad_assistant_server.py
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python bloodyad_assistant_server.py
```

### Añadir nuevas herramientas

1. Edita `bloodyad_assistant_server.py` y agrega la nueva función.
2. Usa el decorador `@mcp.tool()`.
3. Añade el nombre del tool en el catálogo MCP (`custom.yaml`).
4. Reconstruye la imagen Docker.

---

## Troubleshooting

- Si no aparecen los tools: revisa el build, logs, archivos YAML (`custom.yaml`, `registry.yaml`), y reinicia Claude Desktop.
- Si fallan los comandos bloodyAD: revisa los argumentos (host, dominio, usuario, clave), VPN, reachability a la máquina destino y la versión de bloodyAD.

---

## Consideraciones de Seguridad

- Las credenciales se pasan en cada comando, no se almacenan ni se loguean.
- El server corre como usuario no-root en Docker.
- El output es texto plano, igual al de bloodyAD, sin emojis ni formato markdown adicional.

---

## Licencia

MIT License
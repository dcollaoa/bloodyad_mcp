<p align="center">
  <img alt="bloodyAD_MCP" src="media/logo.png" height="30%" width="30%">
</p>


[README (English)](README.md) | [中文文档 (Chinese)](README_zh.md) | [README en Español](README_es.md)



# bloodyad-mcp

A Model Context Protocol (MCP) server that acts as a wrapper for bloodyAD, allowing flexible and automated Active Directory enumeration and abuse from Claude Desktop, Gemini-CLI, or other MCP frontends.

---

## Purpose

This server exposes bloodyAD commands through simple Python functions, facilitating the enumeration, extraction, and abuse of Active Directory objects directly from your AI assistant or MCP environment, without the need to manually execute the bloodyAD CLI.

---

## Features

### Get Operations
- **`bloodyad_raw`** — Executes any bloodyAD command as a string (maximum flexibility, advanced mode).
- **`bloodyad_get_object`** — Retrieves LDAP object attributes, with an option to resolve SD.
- **`bloodyad_get_children`** — Lists children of an object (users, groups, computers, OUs).
- **`bloodyad_get_dnsdump`** — Extracts AD-integrated DNS zones.
- **`bloodyad_get_membership`** — Gets groups to which the target belongs.
- **`bloodyad_get_writable`** — Lists objects over which the authenticated user has write permissions.
- **`bloodyad_get_search`** — Performs advanced searches in the LDAP database.
- **`bloodyad_get_trusts`** — Displays domain trusts in an ASCII tree.

### Set Operations
- **`bloodyad_set_object`** — Adds/Replaces/Deletes attributes of an object.
- **`bloodyad_set_owner`** — Changes the ownership of an object.
- **`bloodyad_set_password`** — Changes the password of a user/computer.
- **`bloodyad_set_restore`** — Restores a deleted object.

### Add Operations
- **`bloodyad_add_computer`** — Adds a new computer.
- **`bloodyad_add_dcsync`** — Adds the DCSync right to a trustee in the domain.
- **`bloodyad_add_dnsRecord`** — Adds a new DNS record.
- **`bloodyad_add_genericAll`** — Grants full control (GenericAll) to a trustee over an object.
- **`bloodyad_add_groupMember`** — Adds a member (user, group, computer) to a group.
- **`bloodyad_add_rbcd`** — Adds Resource Based Constrained Delegation (RBCD) for a service on an object.
- **`bloodyad_add_shadowCredentials`** — Adds Key Credentials (Shadow Credentials) to an object.
- **`bloodyad_add_uac`** — Adds User Account Control (UAC) flags to an object.
- **`bloodyad_add_user`** — Adds a new user.

### Remove Operations
- **`bloodyad_remove_dcsync`** — Removes the DCSync right for a trustee.
- **`bloodyad_remove_dnsRecord`** — Removes a DNS record from an AD environment.
- **`bloodyad_remove_genericAll`** — Removes full control (GenericAll) of a trustee over an object.
- **`bloodyad_remove_groupMember`** — Removes a member from a group.
- **`bloodyad_remove_object`** — Removes an object (user, group, computer, organizational unit, etc.).
- **`bloodyad_remove_rbcd`** — Removes Resource Based Constrained Delegation (RBCD) for a service.
- **`bloodyad_remove_shadowCredentials`** — Removes Key Credentials (Shadow Credentials) from an object.
- **`bloodyad_remove_uac`** — Removes User Account Control (UAC) flags from an object.

---

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI Plugin (`docker mcp`)
- Internet during build (to clone bloodyAD)
- VPN/network access to the target DC

---

## Installation

Follow the detailed steps in the official guide (see section 2: installation).
Build the Docker image and configure it as a custom MCP server.


---

## Usage Examples

You can launch in Claude Desktop, Gemini-CLI, etc.:

```python
# Get bloodyAD help
print(default_api.bloodyad_raw(cli_args="-h"))

# Get object attributes (e.g., objectSid of the domain)
print(default_api.bloodyad_get_object(target='DC=fluffy,DC=htb', attr='objectSid', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# List child objects of a domain
print(default_api.bloodyad_get_children(target='DC=fluffy,DC=htb', otype='domain', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Dump DNS records for a zone
print(default_api.bloodyad_get_dnsdump(zone='fluffy.htb', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Get group memberships for a user
print(default_api.bloodyad_get_membership(target='svc_mssql', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# List writable objects for the authenticated user
print(default_api.bloodyad_get_writable(user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Perform an advanced LDAP search
print(default_api.bloodyad_get_search(base='DC=fluffy,DC=htb', filter='(objectClass=user)', attr='sAMAccountName', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Change a user's password
print(default_api.bloodyad_set_password(target='CN=TestUser,CN=Users,DC=fluffy,DC=htb', newpass='NewSecurePassword123!', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# Add a new user
print(default_api.bloodyad_add_user(samAccountName='NewUser', newpass='NewUserPass123!', user='fluffy.htb\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

---

## Architecture

```
Gemini-CLI → MCP Gateway → bloodyad-mcp → bloodyAD CLI (Kali)
```

---

## Troubleshooting

- If tools do not appear: check the build, logs, YAML files (`custom.yaml`, `registry.yaml`), and restart Claude Desktop / Gemini-CLI.
- If bloodyAD commands fail: check arguments (host, domain, user, password), VPN, reachability to the target machine, and bloodyAD version.

---

## Security Considerations

- Credentials are passed with each command, not stored or logged.
- The server runs as a non-root user in Docker.
- Output is plain text, identical to bloodyAD's, without emojis or additional markdown formatting.

---

## License

MIT License


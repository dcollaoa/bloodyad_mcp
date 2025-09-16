# bloodyad-assistant Implementation Notes

- The server only wraps bloodyAD, no extra tools.
- Each MCP tool is a wrapper to a common bloodyAD operation (get object, get children, etc).
- There's a raw wrapper (`bloodyad_raw`) for advanced/unknown/edge-case usage.
- All tools return output as plain text (no emojis, no Markdown).
- All parameters default to "", never None.
- All tools sanitize/strip parameters and validate presence of required ones.
- Server runs as non-root via Docker.
- Output is exactly as bloodyAD prints (stdout or stderr), including error details for troubleshooting.
- Uses FastMCP, never @mcp.prompt() or prompt parameter.
- All docstrings are single-line and concise, to avoid gateway errors.

## Tool List

### Get Operations
- `bloodyad_raw`: Run a raw bloodyAD CLI command, space-separated, for advanced usage.
- `bloodyad_get_object`: Get LDAP object attributes (optionally resolve SD) via bloodyAD.
- `bloodyad_get_children`: List child objects of a target (user, group, computer, etc) via bloodyAD.
- `bloodyad_get_dnsdump`: Dump AD-integrated DNS zones using bloodyAD.
- `bloodyad_get_membership`: Get group memberships (recursively) of a target user/computer.
- `bloodyad_get_writable`: List writable objects for the user (optionally filtered by otype/right) via bloodyAD.
- `bloodyad_get_search`: Search in LDAP database via bloodyAD.
- `bloodyad_get_trusts`: Display trusts in an ascii tree via bloodyAD.

### Set Operations
- `bloodyad_set_object`: Add/Replace/Delete target's attribute via bloodyAD.
- `bloodyad_set_owner`: Changes target ownership with provided owner via bloodyAD.
- `bloodyad_set_password`: Change password of a user/computer via bloodyAD.
- `bloodyad_set_restore`: Restore a deleted object via bloodyAD.

### Add Operations
- `bloodyad_add_computer`: Adds new computer via bloodyAD.
- `bloodyad_add_dcsync`: Adds DCSync right on domain to provided trustee via bloodyAD.
- `bloodyad_add_dnsRecord`: Adds a new DNS record into an AD environment via bloodyAD.
- `bloodyad_add_genericAll`: Gives full control to trustee on target via bloodyAD.
- `bloodyad_add_groupMember`: Adds a new member (user, group, computer) to group via bloodyAD.
- `bloodyad_add_rbcd`: Adds Resource Based Constraint Delegation for service on target via bloodyAD.
- `bloodyad_add_shadowCredentials`: Adds Key Credentials to target via bloodyAD.
- `bloodyad_add_uac`: Adds property flags altering user/computer object behavior via bloodyAD.
- `bloodyad_add_user`: Adds a new user via bloodyAD.

### Remove Operations
- `bloodyad_remove_dcsync`: Removes DCSync right for provided trustee via bloodyAD.
- `bloodyad_remove_dnsRecord`: Removes a DNS record of an AD environment via bloodyAD.
- `bloodyad_remove_genericAll`: Removes full control of trustee on target via bloodyAD.
- `bloodyad_remove_groupMember`: Removes member (user, group, computer) from group via bloodyAD.
- `bloodyad_remove_object`: Removes object (user, group, computer, organizational unit, etc) via bloodyAD.
- `bloodyad_remove_rbcd`: Removes Resource Based Constraint Delegation for service on target via bloodyAD.
- `bloodyad_remove_shadowCredentials`: Removes Key Credentials from target via bloodyAD.
- `bloodyad_remove_uac`: Removes property flags altering user/computer object behavior via bloodyAD.

## Recommended Usage

- **`bloodyad_raw`**: Use for any direct bloodyAD CLI usage, especially for commands not covered by specific wrappers or for getting help (e.g., `bloodyAD -h`).
- **`bloodyad_get_object`**: Retrieve specific attributes of an LDAP object (e.g., `objectSid` of a domain).
- **`bloodyad_get_children`**: List child objects within a specified target (e.g., children of a domain).
- **`bloodyad_get_dnsdump`**: Dump DNS records from an Active Directory integrated DNS zone.
- **`bloodyad_get_membership`**: Enumerate group memberships (including recursive memberships) for a user or computer.
- **`bloodyad_get_writable`**: Identify objects that the authenticated user has write permissions over, optionally filtering by object type or specific rights.
- **`bloodyad_get_search`**: Perform advanced LDAP searches with custom filters and base DNs.
- **`bloodyad_get_trusts`**: Visualize Active Directory trusts.
- **`bloodyad_set_*` tools**: Modify existing Active Directory objects, such as changing attributes, ownership, or user passwords.
- **`bloodyad_add_*` tools**: Create new objects or add specific rights/configurations (e.g., add a new computer, add a user to a group, add DCSync rights).
- **`bloodyad_remove_*` tools**: Delete objects or remove specific rights/configurations (e.g., remove a user from a group, remove DCSync rights).

- Keep your bloodyAD up-to-date by rebuilding the Docker image.
- To add new bloodyAD features, create new wrappers following the same style.

## Examples

Here are some examples of how to use the `bloodyad_assistant` tools:

### Get bloodyAD help
```python
print(default_api.bloodyad_raw(cli_args="-h"))
```

### Get object attributes (e.g., objectSid of the domain)
```python
print(default_api.bloodyad_get_object(target='DC=fluffy,DC=htb', attr='objectSid', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

### List child objects of a domain
```python
print(default_api.bloodyad_get_children(target='DC=fluffy,DC=htb', otype='domain', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

### Dump DNS records for a zone
```python
print(default_api.bloodyad_get_dnsdump(zone='fluffy.htb', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

### Get group memberships for a user
```python
print(default_api.bloodyad_get_membership(target='svc_mssql', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

### List writable objects for the authenticated user
```python
print(default_api.bloodyad_get_writable(user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

### Troubleshooting Hostname Resolution in Docker

If bloodyAD tools fail with "Name or service not known" errors for a hostname (e.g., `dc01.fluffy.htb`) even after `ping` works from the host, it might be a Docker-specific resolution issue.

**Solution 1: Add host entry to Docker container's `/etc/hosts`**
- Identify the running Docker container ID or name (e.g., `docker ps`).
- Execute `docker exec <container_id_or_name> sh -c "echo 'IP_ADDRESS HOSTNAME' >> /etc/hosts"` (e.g., `docker exec <container_id> sh -c "echo '10.10.11.69 dc01.fluffy.htb' >> /etc/hosts"`).
- Verify with `docker exec <container_id_or_name> ping -c 4 HOSTNAME`.

**Solution 2: Use IP address directly in `bloodyAD` commands**
- If bloodyAD still fails with the hostname, try providing the IP address directly to the `host` parameter of the bloodyAD tool (e.g., `bloodyad_get_writable(host="10.10.11.69", ...)` instead of `bloodyad_get_writable(host="dc01.fluffy.htb", ...)`).

## Limitations

- Output is plain text, always.
- Only wraps bloodyAD, not other tools.
- Requires outbound connectivity for build (bloodyAD git clone).
- User must be on the same network/VPN as the target AD (HTB or lab).

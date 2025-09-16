#!/usr/bin/env python3
"""
bloodyAD-assistant MCP Server - Wrapper for bloodyAD CLI on Docker/Kali
"""
import os
import sys
import logging
import subprocess
from mcp.server.fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("bloodyad-assistant-server")

mcp = FastMCP("bloodyad-assistant")

BLOODYAD_PATH = "/tools/bloodyAD/bloodyAD.py"
PYTHON_VENV_BIN = "/venv/bin/python"

def _parse_bool(val: str) -> bool:
    v = val.strip().lower()
    return v in ("1", "true", "yes", "on")

def _run_bloodyad(host: str, domain: str, user: str, password: str, bloodyad_command_args: list, kerberos_args: list = [], auth_format: str = "", certificate_path: str = "", secure_ldap: str = ""):
    # Parse user and domain
    parsed_user = user.strip()
    parsed_domain = domain.strip()

    if '\\' in parsed_user:
        parts = parsed_user.split('\\', 1)
        if len(parts) == 2:
            parsed_domain = parts[0] if not parsed_domain else parsed_domain
            parsed_user = parts[1]
    elif '@' in parsed_user:
        parts = parsed_user.split('@', 1)
        if len(parts) == 2:
            parsed_user = parts[0]
            parsed_domain = parts[1] if not parsed_domain else parsed_domain

    common_args = [
        "--host", host.strip(),
        "-d", parsed_domain,
        "-u", parsed_user,
        "-p", password.strip(),
    ]
    for karg in kerberos_args:
        common_args += ["--kerberos", karg.strip()]
    if auth_format.strip():
        common_args += ["--auth-format", auth_format.strip()]
    if certificate_path.strip():
        common_args += ["--certificate-path", certificate_path.strip()]
    if _parse_bool(secure_ldap):
        common_args.append("--secure-ldap")

    full_command = [PYTHON_VENV_BIN, BLOODYAD_PATH] + common_args + bloodyad_command_args
    try:
        logger.info(f"Running bloodyAD (without sudo): {' '.join(full_command)}")
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=180
        )
        out = result.stdout.strip()
        err = result.stderr.strip()
        if result.returncode == 0:
            if out:
                return f"{out}"
            else:
                return "Command executed with no output."
        else:
            msg = f"Error (code {result.returncode}):\n{err}\n{out}"
            return msg.strip()
    except subprocess.TimeoutExpired:
        return "Error: bloodyAD command timed out (180s)."
    except Exception as e:
        return f"Error running bloodyAD: {str(e)}"

@mcp.tool()
async def bloodyad_raw(cli_args: str = "", host: str = "", domain: str = "", user: str = "", password: str = "") -> str:
    """Run a raw bloodyAD CLI command, space-separated, for advanced usage."""
    if not cli_args.strip():
        return "Error: You must provide CLI arguments."
    try:
        import shlex
        bloodyad_command_args = shlex.split(cli_args.strip())
        return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)
    except Exception as e:
        return f"Error: Could not parse/split CLI args: {str(e)}"

@mcp.tool()
async def bloodyad_get_object(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", attr: str = "", resolve_sd: str = "", kerberos_args: list[str] = [], auth_format: str = "", certificate_path: str = "", secure_ldap: str = "") -> str:
    """Get LDAP object attributes (optionally resolve SD) via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip()]):
        return "Error: host, domain, user, password, and target are required."
    bloodyad_command_args = [
        "get", "object", target.strip()
    ]
    if attr.strip():
        bloodyad_command_args += ["--attr", attr.strip()]
    if _parse_bool(resolve_sd):
        bloodyad_command_args.append("--resolve-sd")
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args, kerberos_args=kerberos_args, auth_format=auth_format, certificate_path=certificate_path, secure_ldap=secure_ldap)

@mcp.tool()
async def bloodyad_get_children(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", otype: str = "", kerberos_args: list[str] = [], auth_format: str = "", certificate_path: str = "", secure_ldap: str = "") -> str:
    """List child objects of a target (user, group, computer, etc) via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip()]):
        return "Error: host, domain, user, and password are required."
    bloodyad_command_args = [
        "get", "children"
    ]
    if target.strip():
        bloodyad_command_args += ["--target", target.strip()]
    if otype.strip():
        bloodyad_command_args += ["--otype", otype.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args, kerberos_args=kerberos_args, auth_format=auth_format, certificate_path=certificate_path, secure_ldap=secure_ldap)

@mcp.tool()
async def bloodyad_get_dnsdump(host: str = "", domain: str = "", user: str = "", password: str = "", zone: str = "") -> str:
    """Dump AD-integrated DNS zones using bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip()]):
        return "Error: host, domain, user, and password are required."
    bloodyad_command_args = [
        "get", "dnsDump"
    ]
    if zone.strip():
        bloodyad_command_args += ["--zone", zone.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_get_membership(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "") -> str:
    """Get group memberships (recursively) of a target user/computer."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip()]):
        return "Error: host, domain, user, password, and target are required."
    bloodyad_command_args = [
        "get", "membership", target.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_get_writable(host: str = "", domain: str = "", user: str = "", password: str = "", otype: str = "", right: str = "", detail: str = "") -> str:
    """List writable objects for the user (optionally filtered by otype/right) via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip()]):
        return "Error: host, domain, user, and password are required."
    bloodyad_command_args = [
        "get", "writable"
    ]
    if otype.strip():
        bloodyad_command_args += ["--otype", otype.strip()]
    if right.strip():
        bloodyad_command_args += ["--right", right.strip()]
    if _parse_bool(detail):
        bloodyad_command_args.append("--detail")
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_get_search(host: str = "", domain: str = "", user: str = "", password: str = "", base: str = "", filter: str = "", attr: str = "", resolve_sd: str = "", raw: str = "", transitive: str = "", controls: list[str] = []) -> str:
    """Search in LDAP database via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip()]):
        return "Error: host, domain, user, and password are required."
    bloodyad_command_args = [
        "get", "search"
    ]
    if base.strip():
        bloodyad_command_args += ["--base", base.strip()]
    if filter.strip():
        bloodyad_command_args += ["--filter", filter.strip()]
    if attr.strip():
        bloodyad_command_args += ["--attr", attr.strip()]
    if _parse_bool(resolve_sd):
        bloodyad_command_args.append("--resolve-sd")
    if _parse_bool(raw):
        bloodyad_command_args.append("--raw")
    if _parse_bool(transitive):
        bloodyad_command_args.append("--transitive")
    for control in controls:
        bloodyad_command_args += ["-c", control.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_get_trusts(host: str = "", domain: str = "", user: str = "", password: str = "", transitive: str = "") -> str:
    """Display trusts in an ascii tree via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip()]):
        return "Error: host, domain, user, and password are required."
    bloodyad_command_args = [
        "get", "trusts"
    ]
    if _parse_bool(transitive):
        bloodyad_command_args.append("--transitive")
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_set_object(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", attribute: str = "", value: list[str] = [], raw: str = "", b64: str = "") -> str:
    """Add/Replace/Delete target's attribute via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip(), attribute.strip()]):
        return "Error: host, domain, user, password, target, and attribute are required."
    bloodyad_command_args = [
        "set", "object", target.strip(), attribute.strip()
    ]
    for val in value:
        bloodyad_command_args += ["-v", val.strip()]
    if _parse_bool(raw):
        bloodyad_command_args.append("--raw")
    if _parse_bool(b64):
        bloodyad_command_args.append("--b64")
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_set_owner(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", owner: str = "") -> str:
    """Changes target ownership with provided owner via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip(), owner.strip()]):
        return "Error: host, domain, user, password, target, and owner are required."
    bloodyad_command_args = [
        "set", "owner", target.strip(), owner.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_set_password(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", newpass: str = "", oldpass: str = "") -> str:
    """Change password of a user/computer via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip(), newpass.strip()]):
        return "Error: host, domain, user, password, target, and newpass are required."
    bloodyad_command_args = [
        "set", "password", target.strip(), newpass.strip()
    ]
    if oldpass.strip():
        bloodyad_command_args += ["--oldpass", oldpass.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_set_restore(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", newName: str = "", newParent: str = "") -> str:
    """Restore a deleted object via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip()]):
        return "Error: host, domain, user, password, and target are required."
    bloodyad_command_args = [
        "set", "restore", target.strip()
    ]
    if newName.strip():
        bloodyad_command_args += ["--newName", newName.strip()]
    if newParent.strip():
        bloodyad_command_args += ["--newParent", newParent.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_computer(host: str = "", domain: str = "", user: str = "", password: str = "", hostname: str = "", computer_password: str = "", ou: str = "") -> str:
    """Adds new computer via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), hostname.strip(), computer_password.strip()]):
        return "Error: host, domain, user, password, hostname, and computer_password are required."
    bloodyad_command_args = [
        "add", "computer", hostname.strip(), computer_password.strip()
    ]
    if ou.strip():
        bloodyad_command_args += ["--ou", ou.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_dcsync(host: str = "", domain: str = "", user: str = "", password: str = "", trustee: str = "") -> str:
    """Adds DCSync right on domain to provided trustee via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), trustee.strip()]):
        return "Error: host, domain, user, password, and trustee are required."
    bloodyad_command_args = [
        "add", "dcsync", trustee.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_dnsRecord(host: str = "", domain: str = "", user: str = "", password: str = "", name: str = "", data: str = "", dnstype: str = "", zone: str = "", ttl: str = "", preference: str = "", port: str = "", priority: str = "", weight: str = "", forest: str = "") -> str:
    """Adds a new DNS record into an AD environment via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), name.strip(), data.strip()]):
        return "Error: host, domain, user, password, name, and data are required."
    bloodyad_command_args = [
        "add", "dnsRecord", name.strip(), data.strip()
    ]
    if dnstype.strip():
        bloodyad_command_args += ["--dnstype", dnstype.strip()]
    if zone.strip():
        bloodyad_command_args += ["--zone", zone.strip()]
    if ttl.strip():
        bloodyad_command_args += ["--ttl", ttl.strip()]
    if preference.strip():
        bloodyad_command_args += ["--preference", preference.strip()]
    if port.strip():
        bloodyad_command_args += ["--port", port.strip()]
    if priority.strip():
        bloodyad_command_args += ["--priority", priority.strip()]
    if weight.strip():
        bloodyad_command_args += ["--weight", weight.strip()]
    if _parse_bool(forest):
        bloodyad_command_args.append("--forest")
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_genericAll(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", trustee: str = "") -> str:
    """Gives full control to trustee on target via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip(), trustee.strip()]):
        return "Error: host, domain, user, password, target, and trustee are required."
    bloodyad_command_args = [
        "add", "genericAll", target.strip(), trustee.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_groupMember(host: str = "", domain: str = "", user: str = "", password: str = "", group: str = "", member: str = "") -> str:
    """Adds a new member (user, group, computer) to group via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), group.strip(), member.strip()]):
        return "Error: host, domain, user, password, group, and member are required."
    bloodyad_command_args = [
        "add", "groupMember", group.strip(), member.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_rbcd(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", service: str = "") -> str:
    """Adds Resource Based Constraint Delegation for service on target via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip(), service.strip()]):
        return "Error: host, domain, user, password, target, and service are required."
    bloodyad_command_args = [
        "add", "rbcd", target.strip(), service.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_shadowCredentials(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", path: str = "") -> str:
    """Adds Key Credentials to target via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip()]):
        return "Error: host, domain, user, password, and target are required."
    bloodyad_command_args = [
        "add", "shadowCredentials", target.strip()
    ]
    if path.strip():
        bloodyad_command_args += ["--path", path.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_uac(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", flags: list[str] = []) -> str:
    """Adds property flags altering user/computer object behavior via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip()]):
        return "Error: host, domain, user, password, and target are required."
    bloodyad_command_args = [
        "add", "uac", target.strip()
    ]
    for flag in flags:
        bloodyad_command_args += ["-f", flag.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_add_user(host: str = "", domain: str = "", user: str = "", password: str = "", samAccountName: str = "", newpass: str = "", ou: str = "", lifetime: str = "") -> str:
    """Adds a new user via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), samAccountName.strip(), newpass.strip()]):
        return "Error: host, domain, user, password, samAccountName, and newpass are required."
    bloodyad_command_args = [
        "add", "user", samAccountName.strip(), newpass.strip()
    ]
    if ou.strip():
        bloodyad_command_args += ["--ou", ou.strip()]
    if lifetime.strip():
        bloodyad_command_args += ["--lifetime", lifetime.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_remove_dcsync(host: str = "", domain: str = "", user: str = "", password: str = "", trustee: str = "") -> str:
    """Removes DCSync right for provided trustee via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), trustee.strip()]):
        return "Error: host, domain, user, password, and trustee are required."
    bloodyad_command_args = [
        "remove", "dcsync", trustee.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_remove_dnsRecord(host: str = "", domain: str = "", user: str = "", password: str = "", name: str = "", data: str = "", dnstype: str = "", zone: str = "", ttl: str = "", preference: str = "", port: str = "", priority: str = "", weight: str = "", forest: str = "") -> str:
    """Removes a DNS record of an AD environment via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), name.strip(), data.strip()]):
        return "Error: host, domain, user, password, name, and data are required."
    bloodyad_command_args = [
        "remove", "dnsRecord", name.strip(), data.strip()
    ]
    if dnstype.strip():
        bloodyad_command_args += ["--dnstype", dnstype.strip()]
    if zone.strip():
        bloodyad_command_args += ["--zone", zone.strip()]
    if ttl.strip():
        bloodyad_command_args += ["--ttl", ttl.strip()]
    if preference.strip():
        bloodyad_command_args += ["--preference", preference.strip()]
    if port.strip():
        bloodyad_command_args += ["--port", port.strip()]
    if priority.strip():
        bloodyad_command_args += ["--priority", priority.strip()]
    if weight.strip():
        bloodyad_command_args += ["--weight", weight.strip()]
    if _parse_bool(forest):
        bloodyad_command_args.append("--forest")
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_remove_genericAll(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", trustee: str = "") -> str:
    """Removes full control of trustee on target via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip(), trustee.strip()]):
        return "Error: host, domain, user, password, target, and trustee are required."
    bloodyad_command_args = [
        "remove", "genericAll", target.strip(), trustee.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_remove_groupMember(host: str = "", domain: str = "", user: str = "", password: str = "", group: str = "", member: str = "") -> str:
    """Removes member (user, group, computer) from group via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), group.strip(), member.strip()]):
        return "Error: host, domain, user, password, group, and member are required."
    bloodyad_command_args = [
        "remove", "groupMember", group.strip(), member.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_remove_object(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "") -> str:
    """Removes object (user, group, computer, organizational unit, etc) via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip()]):
        return "Error: host, domain, user, password, and target are required."
    bloodyad_command_args = [
        "remove", "object", target.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_remove_rbcd(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", service: str = "") -> str:
    """Removes Resource Based Constraint Delegation for service on target via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip(), service.strip()]):
        return "Error: host, domain, user, password, and service are required."
    bloodyad_command_args = [
        "remove", "rbcd", target.strip(), service.strip()
    ]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_remove_shadowCredentials(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", key: str = "") -> str:
    """Removes Key Credentials from target via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip()]):
        return "Error: host, domain, user, password, and target are required."
    bloodyad_command_args = [
        "remove", "shadowCredentials", target.strip()
    ]
    if key.strip():
        bloodyad_command_args += ["--key", key.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

@mcp.tool()
async def bloodyad_remove_uac(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", flags: list[str] = []) -> str:
    """Removes property flags altering user/computer object behavior via bloodyAD."""
    if not all([host.strip(), domain.strip(), user.strip(), password.strip(), target.strip()]):
        return "Error: host, domain, user, password, and target are required."
    bloodyad_command_args = [
        "remove", "uac", target.strip()
    ]
    for flag in flags:
        bloodyad_command_args += ["-f", flag.strip()]
    return _run_bloodyad(host=host, domain=domain, user=user, password=password, bloodyad_command_args=bloodyad_command_args)

if __name__ == "__main__":
    logger.info("Starting bloodyad-assistant MCP server...")
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)

# maded with <3 by 3ky @ pwnnet 
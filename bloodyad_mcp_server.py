#!/usr/bin/env python3
"""
bloodyAD-mcp - Wrapper for bloodyAD CLI on Docker/Kali
Refactored to use bloodyAD as a library for performance.
"""
import os
import sys
import logging
from argparse import Namespace
from mcp.server.fastmcp import FastMCP
import json
import types
import traceback

try:
    from bloodyAD import ConnectionHandler, exceptions
    from bloodyAD.cli_modules import get, set, add, remove
except ImportError as e:
    print(f"Error: Failed to import bloodyAD library. Make sure it's in the 'research' directory. Details: {e}", file=sys.stderr)
    sys.exit(1)

# --- Basic Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("bloodyad-mcp-server")
mcp = FastMCP("bloodyad-mcp")

# --- Connection Caching ---
CONNECTION_CACHE = {}

def get_connection(host, domain, user, password, kerberos_args, auth_format, certificate_path, secure_ldap):
    """
    Gets a cached ConnectionHandler or creates a new one.
    """
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

    conn_key = f"{host}:{parsed_domain}:{parsed_user}:{password}:{kerberos_args}:{auth_format}:{certificate_path}:{secure_ldap}"

    if conn_key in CONNECTION_CACHE:
        logger.info(f"Reusing cached connection for {parsed_user}@{host}")
        return CONNECTION_CACHE[conn_key]

    logger.info(f"Creating new connection for {parsed_user}@{host}")

    args = Namespace(
        host=host.strip(),
        domain=parsed_domain,
        username=parsed_user,
        password=password.strip(),
        kerberos=kerberos_args if kerberos_args else None,
        format=auth_format.strip() if auth_format else 'default',
        certificate=certificate_path.strip() if certificate_path else None,
        secure=_parse_bool(secure_ldap),
        dc_ip=None, dns=None, timeout=None, gc=False, verbose="INFO", json=False
    )

    try:
        conn = ConnectionHandler(args=args)
        CONNECTION_CACHE[conn_key] = conn
        return conn
    except Exception as e:
        logger.error(f"Failed to create connection handler: {e}\n{traceback.format_exc()}")
        raise

# --- Output Formatting ---
def format_output(output):
    """
    Formats the Python objects returned by bloodyAD into a JSON string.
    """
    if output is None or isinstance(output, bool):
        return json.dumps({"status": "success"}, indent=2)

    if isinstance(output, types.GeneratorType):
        output = list(output)
    
    try:
        return json.dumps(output, indent=2, default=str)
    except Exception:
        return str(output)

def run_safely(func, conn, **kwargs):
    """Wrapper to run bloodyAD functions and handle exceptions."""
    try:
        # Filter out None values from kwargs
        active_kwargs = {k: v for k, v in kwargs.items() if v is not None}
        result = func(conn, **active_kwargs)
        return format_output(result)
    except Exception as e:
        logger.error(f"Error executing function {func.__name__}: {e}\n{traceback.format_exc()}")
        return f"Error: {e}"

# --- Helper Functions ---
def _parse_bool(val) -> bool:
    if not isinstance(val, str):
        return bool(val)
    v = val.strip().lower()
    return v in ("1", "true", "yes", "on")

# --- Refactored Tools ---

@mcp.tool()
async def bloodyad_get_object(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", attr: str = "", resolve_sd: str = "", kerberos_args: list[str] = [], auth_format: str = "", certificate_path: str = "", secure_ldap: str = "") -> str:
    """Get LDAP object attributes (optionally resolve SD) via bloodyAD."""
    if not all([host, domain, user, password, target]):
        return "Error: host, domain, user, password, and target are required."
    conn = get_connection(host, domain, user, password, kerberos_args, auth_format, certificate_path, secure_ldap)
    return run_safely(get.object, conn, target=target, attr=attr if attr else "*", resolve_sd=_parse_bool(resolve_sd))

@mcp.tool()
async def bloodyad_get_children(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", otype: str = "", kerberos_args: list[str] = [], auth_format: str = "", certificate_path: str = "", secure_ldap: str = "") -> str:
    """List child objects of a target (user, group, computer, etc) via bloodyAD."""
    if not all([host, domain, user, password]):
        return "Error: host, domain, user, and password are required."
    conn = get_connection(host, domain, user, password, kerberos_args, auth_format, certificate_path, secure_ldap)
    return run_safely(get.children, conn, target=target if target else "DOMAIN", otype=otype if otype else "*")

@mcp.tool()
async def bloodyad_get_dnsdump(host: str = "", domain: str = "", user: str = "", password: str = "", zone: str = "") -> str:
    """Dump AD-integrated DNS zones using bloodyAD."""
    if not all([host, domain, user, password]):
        return "Error: host, domain, user, and password are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(get.dnsDump, conn, zone=zone if zone else None)

@mcp.tool()
async def bloodyad_get_membership(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "") -> str:
    """Get group memberships (recursively) of a target user/computer."""
    if not all([host, domain, user, password, target]):
        return "Error: host, domain, user, password, and target are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(get.membership, conn, target=target)

@mcp.tool()
async def bloodyad_get_writable(host: str = "", domain: str = "", user: str = "", password: str = "", otype: str = "", right: str = "", detail: str = "") -> str:
    """List writable objects for the user (optionally filtered by otype/right) via bloodyAD."""
    if not all([host, domain, user, password]):
        return "Error: host, domain, user, and password are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(get.writable, conn, otype=otype if otype else "ALL", right=right if right else "ALL", detail=_parse_bool(detail))

@mcp.tool()
async def bloodyad_get_search(host: str = "", domain: str = "", user: str = "", password: str = "", base: str = "", filter: str = "", attr: str = "", resolve_sd: str = "", raw: str = "", transitive: str = "", controls: list[str] = []) -> str:
    """Search in LDAP database via bloodyAD."""
    if not all([host, domain, user, password]):
        return "Error: host, domain, user, and password are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(get.search, conn, base=base if base else "DOMAIN", filter=filter if filter else "(objectClass=*)", attr=attr if attr else "*", resolve_sd=_parse_bool(resolve_sd), raw=_parse_bool(raw), transitive=_parse_bool(transitive), c=controls)

@mcp.tool()
async def bloodyad_get_trusts(host: str = "", domain: str = "", user: str = "", password: str = "", transitive: str = "") -> str:
    """Display trusts in an ascii tree via bloodyAD."""
    if not all([host, domain, user, password]):
        return "Error: host, domain, user, and password are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(get.trusts, conn, transitive=_parse_bool(transitive))

@mcp.tool()
async def bloodyad_get_bloodhound(host: str = "", domain: str = "", user: str = "", password: str = "", follow_trusts: str = "", path: str = "") -> str:
    """BloodHound CE collector via bloodyAD."""
    if not all([host, domain, user, password]):
        return "Error: host, domain, user, and password are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(get.bloodhound, conn, follow_trusts=_parse_bool(follow_trusts), path=path if path else "CurrentPath")

@mcp.tool()
async def bloodyad_add_badSuccessor(host: str = "", domain: str = "", user: str = "", password: str = "", dmsa: str = "", target: list[str] = []) -> str:
    """Adds a bad successor to the dMSA."""
    if not all([host, domain, user, password, dmsa]):
        return "Error: host, domain, user, password, and dmsa are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.badSuccessor, conn, dmsa=dmsa, t=target if target else ["CN=Administrator,CN=Users,DC=CurrentDomain"])


@mcp.tool()
async def bloodyad_set_object(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", attribute: str = "", value: list[str] = [], raw: str = "", b64: str = "") -> str:
    """Add/Replace/Delete target's attribute via bloodyAD."""
    if not all([host, domain, user, password, target, attribute]):
        return "Error: host, domain, user, password, target, and attribute are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(set.object, conn, target=target, attribute=attribute, v=value, raw=_parse_bool(raw), b64=_parse_bool(b64))

@mcp.tool()
async def bloodyad_set_owner(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", owner: str = "") -> str:
    """Changes target ownership with provided owner via bloodyAD."""
    if not all([host, domain, user, password, target, owner]):
        return "Error: host, domain, user, password, target, and owner are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(set.owner, conn, target=target, owner=owner)

@mcp.tool()
async def bloodyad_set_password(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", newpass: str = "", oldpass: str = "") -> str:
    """Change password of a user/computer via bloodyAD."""
    if not all([host, domain, user, password, target, newpass]):
        return "Error: host, domain, user, password, target, and newpass are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(set.password, conn, target=target, newpass=newpass, oldpass=oldpass if oldpass else None)

@mcp.tool()
async def bloodyad_set_restore(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", newName: str = "", newParent: str = "") -> str:
    """Restore a deleted object via bloodyAD."""
    if not all([host, domain, user, password, target]):
        return "Error: host, domain, user, password, and target are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(set.restore, conn, target=target, newName=newName if newName else None, newParent=newParent if newParent else None)

@mcp.tool()
async def bloodyad_add_computer(host: str = "", domain: str = "", user: str = "", password: str = "", hostname: str = "", computer_password: str = "", ou: str = "") -> str:
    """Adds new computer via bloodyAD."""
    if not all([host, domain, user, password, hostname, computer_password]):
        return "Error: host, domain, user, password, hostname, and computer_password are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.computer, conn, hostname=hostname, newpass=computer_password, ou=ou if ou else "DefaultOU")

@mcp.tool()
async def bloodyad_add_dcsync(host: str = "", domain: str = "", user: str = "", password: str = "", trustee: str = "") -> str:
    """Adds DCSync right on domain to provided trustee via bloodyAD."""
    if not all([host, domain, user, password, trustee]):
        return "Error: host, domain, user, password, and trustee are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.dcsync, conn, trustee=trustee)

@mcp.tool()
async def bloodyad_add_dnsRecord(host: str = "", domain: str = "", user: str = "", password: str = "", name: str = "", data: str = "", dnstype: str = "", zone: str = "", ttl: str = "", preference: str = "", port: str = "", priority: str = "", weight: str = "", forest: str = "") -> str:
    """Adds a new DNS record into an AD environment via bloodyAD."""
    if not all([host, domain, user, password, name, data]):
        return "Error: host, domain, user, password, name, and data are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.dnsRecord, conn, name=name, data=data, dnstype=dnstype if dnstype else "A", zone=zone if zone else "CurrentDomain", ttl=int(ttl) if ttl else 300, preference=int(preference) if preference else 10, port=int(port) if port else None, priority=int(priority) if priority else 10, weight=int(weight) if weight else 60, forest=_parse_bool(forest))

@mcp.tool()
async def bloodyad_add_genericAll(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", trustee: str = "") -> str:
    """Gives full control to trustee on target via bloodyAD."""
    if not all([host, domain, user, password, target, trustee]):
        return "Error: host, domain, user, password, target, and trustee are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.genericAll, conn, target=target, trustee=trustee)

@mcp.tool()
async def bloodyad_add_groupMember(host: str = "", domain: str = "", user: str = "", password: str = "", group: str = "", member: str = "") -> str:
    """Adds a new member (user, group, computer) to group via bloodyAD."""
    if not all([host, domain, user, password, group, member]):
        return "Error: host, domain, user, password, group, and member are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.groupMember, conn, group=group, member=member)

@mcp.tool()
async def bloodyad_add_rbcd(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", service: str = "") -> str:
    """Adds Resource Based Constraint Delegation for service on target via bloodyAD."""
    if not all([host, domain, user, password, target, service]):
        return "Error: host, domain, user, password, target, and service are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.rbcd, conn, target=target, service=service)

@mcp.tool()
async def bloodyad_add_shadowCredentials(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", path: str = "") -> str:
    """Adds Key Credentials to target via bloodyAD."""
    if not all([host, domain, user, password, target]):
        return "Error: host, domain, user, password, and target are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.shadowCredentials, conn, target=target, path=path if path else "CurrentPath")

@mcp.tool()
async def bloodyad_add_uac(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", flags: list[str] = []) -> str:
    """Adds property flags altering user/computer object behavior via bloodyAD."""
    if not all([host, domain, user, password, target, flags]):
        return "Error: host, domain, user, password, target, and flags are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.uac, conn, target=target, f=flags)

@mcp.tool()
async def bloodyad_add_user(host: str = "", domain: str = "", user: str = "", password: str = "", samAccountName: str = "", newpass: str = "", ou: str = "", lifetime: str = "") -> str:
    """Adds a new user via bloodyAD."""
    if not all([host, domain, user, password, samAccountName, newpass]):
        return "Error: host, domain, user, password, samAccountName, and newpass are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(add.user, conn, sAMAccountName=samAccountName, newpass=newpass, ou=ou if ou else "DefaultOU", lifetime=int(lifetime) if lifetime else 0)

@mcp.tool()
async def bloodyad_remove_dcsync(host: str = "", domain: str = "", user: str = "", password: str = "", trustee: str = "") -> str:
    """Removes DCSync right for provided trustee via bloodyAD."""
    if not all([host, domain, user, password, trustee]):
        return "Error: host, domain, user, password, and trustee are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(remove.dcsync, conn, trustee=trustee)

@mcp.tool()
async def bloodyad_remove_dnsRecord(host: str = "", domain: str = "", user: str = "", password: str = "", name: str = "", data: str = "", dnstype: str = "", zone: str = "", ttl: str = "", preference: str = "", port: str = "", priority: str = "", weight: str = "", forest: str = "") -> str:
    """Removes a DNS record of an AD environment via bloodyAD."""
    if not all([host, domain, user, password, name, data]):
        return "Error: host, domain, user, password, name, and data are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(remove.dnsRecord, conn, name=name, data=data, dnstype=dnstype if dnstype else "A", zone=zone if zone else "CurrentDomain", ttl=int(ttl) if ttl else None, preference=int(preference) if preference else None, port=int(port) if port else None, priority=int(priority) if priority else None, weight=int(weight) if weight else None, forest=_parse_bool(forest))

@mcp.tool()
async def bloodyad_remove_genericAll(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", trustee: str = "") -> str:
    """Removes full control of trustee on target via bloodyAD."""
    if not all([host, domain, user, password, target, trustee]):
        return "Error: host, domain, user, password, target, and trustee are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(remove.genericAll, conn, target=target, trustee=trustee)

@mcp.tool()
async def bloodyad_remove_groupMember(host: str = "", domain: str = "", user: str = "", password: str = "", group: str = "", member: str = "") -> str:
    """Removes member (user, group, computer) from group via bloodyAD."""
    if not all([host, domain, user, password, group, member]):
        return "Error: host, domain, user, password, group, and member are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(remove.groupMember, conn, group=group, member=member)

@mcp.tool()
async def bloodyad_remove_object(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "") -> str:
    """Removes object (user, group, computer, organizational unit, etc) via bloodyAD."""
    if not all([host, domain, user, password, target]):
        return "Error: host, domain, user, password, and target are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(remove.object, conn, target=target)

@mcp.tool()
async def bloodyad_remove_rbcd(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", service: str = "") -> str:
    """Removes Resource Based Constraint Delegation for service on target via bloodyAD."""
    if not all([host, domain, user, password, target, service]):
        return "Error: host, domain, user, password, target, and service are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(remove.rbcd, conn, target=target, service=service)

@mcp.tool()
async def bloodyad_remove_shadowCredentials(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", key: str = "") -> str:
    """Removes Key Credentials from target via bloodyAD."""
    if not all([host, domain, user, password, target]):
        return "Error: host, domain, user, password, and target are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(remove.shadowCredentials, conn, target=target, key=key if key else None)

@mcp.tool()
async def bloodyad_remove_uac(host: str = "", domain: str = "", user: str = "", password: str = "", target: str = "", flags: list[str] = []) -> str:
    """Removes property flags altering user/computer object behavior via bloodyAD."""
    if not all([host, domain, user, password, target, flags]):
        return "Error: host, domain, user, password, target, and flags are required."
    conn = get_connection(host, domain, user, password, [], "", "", "")
    return run_safely(remove.uac, conn, target=target, f=flags)

if __name__ == "__main__":
    logger.info("Starting bloodyad-mcp server...")
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)

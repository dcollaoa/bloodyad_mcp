<p align="center">
  <img alt="bloodyAD_MCP" src="media/logo.png" height="30%" width="30%">
</p>


[README (English)](README.md) | [中文文档 (Chinese)](README_zh.md) | [README en Español](README_es.md)


# bloodyad-mcp

一个模型上下文协议 (MCP) 服务器，作为 bloodyAD 的包装器，允许从 Claude Desktop、Gemini-CLI 或其他 MCP 前端灵活自动化地进行 Active Directory 枚举和滥用。

---

## 目的

该服务器通过简单的 Python 函数公开 bloodyAD 命令，方便您直接从 AI 助手或 MCP 环境中枚举、提取和滥用 Active Directory 对象，而无需手动执行 bloodyAD CLI。

---

## 功能

### 获取操作 (Get Operations)
- **`bloodyad_raw`** — 执行任何 bloodyAD CLI 命令字符串（最大灵活性，高级模式）。
- **`bloodyad_get_object`** — 检索 LDAP 对象属性，可选择解析 SD。
- **`bloodyad_get_children`** — 列出目标对象的子对象（用户、组、计算机、OU）。
- **`bloodyad_get_dnsdump`** — 提取 AD 集成 DNS 区域。
- **`bloodyad_get_membership`** — 获取目标所属的组。
- **`bloodyad_get_writable`** — 列出经过身份验证的用户具有写入权限的对象。
- **`bloodyad_get_search`** — 在 LDAP 数据库中执行高级搜索。
- **`bloodyad_get_trusts`** — 以 ASCII 树形式显示域信任。

### 设置操作 (Set Operations)
- **`bloodyad_set_object`** — 添加/替换/删除对象的属性。
- **`bloodyad_set_owner`** — 更改对象的所有权。
- **`bloodyad_set_password`** — 更改用户/计算机的密码。
- **`bloodyad_set_restore`** — 恢复已删除的对象。

### 添加操作 (Add Operations)
- **`bloodyad_add_computer`** — 添加新计算机。
- **`bloodyad_add_dcsync`** — 将 DCSync 权限添加到域中的受托人。
- **`bloodyad_add_dnsRecord`** — 添加新的 DNS 记录。
- **`bloodyad_add_genericAll`** — 授予受托人对对象的完全控制权 (GenericAll)。
- **`bloodyad_add_groupMember`** — 将成员（用户、组、计算机）添加到组。
- **`bloodyad_add_rbcd`** — 为对象上的服务添加基于资源的约束委派 (RBCD)。
- **`bloodyad_add_shadowCredentials`** — 将密钥凭据（Shadow Credentials）添加到对象。
- **`bloodyad_add_uac`** — 将用户帐户控制 (UAC) 标志添加到对象。
- **`bloodyad_add_user`** — 添加新用户。

### 删除操作 (Remove Operations)
- **`bloodyad_remove_dcsync`** — 删除受托人的 DCSync 权限。
- **`bloodyad_remove_dnsRecord`** — 从 AD 环境中删除 DNS 记录。
- **`bloodyad_remove_genericAll`** — 删除受托人对对象的完全控制权 (GenericAll)。
- **`bloodyad_remove_groupMember`** — 从组中删除成员。
- **`bloodyad_remove_object`** — 删除对象（用户、组、计算机、组织单位等）。
- **`bloodyad_remove_rbcd`** — 删除服务的基于资源的约束委派 (RBCD)。
- **`bloodyad_remove_shadowCredentials`** — 从对象中删除密钥凭据（Shadow Credentials）。
- **`bloodyad_remove_uac`** — 从对象中删除用户帐户控制 (UAC) 标志。

---

## 先决条件

- 启用 MCP 工具包的 Docker Desktop
- Docker MCP CLI 插件 (`docker mcp`)
- 构建期间需要互联网（克隆 bloodyAD）
- 对目标 DC 的 VPN/网络访问

---

## 安装

请遵循官方指南中的详细步骤（参见第 2 节：安装）。
构建 Docker 镜像并将其配置为自定义 MCP 服务器。

---

## 使用示例

您可以在 Claude Desktop、Gemini-CLI 等中启动：

```python
# 获取 bloodyAD 帮助
print(default_api.bloodyad_raw(cli_args="-h"))

# 获取对象属性（例如，域的 objectSid）
print(default_api.bloodyad_get_object(target='DC=fluffy,DC=htb', attr='objectSid', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# 列出域的子对象
print(default_api.bloodyad_get_children(target='DC=fluffy,DC=htb', otype='domain', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# 转储区域的 DNS 记录
print(default_api.bloodyad_get_dnsdump(zone='fluffy.htb', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# 获取用户的组成员资格
print(default_api.bloodyad_get_membership(target='svc_mssql', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# 列出经过身份验证的用户可写入的对象
print(default_api.bloodyad_get_writable(user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# 执行高级 LDAP 搜索
print(default_api.bloodyad_get_search(base='DC=fluffy,DC=htb', filter='(objectClass=user)', attr='sAMAccountName', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# 更改用户密码
# print(default_api.bloodyad_set_password(target='CN=TestUser,CN=Users,DC=fluffy,DC=htb', newpass='NewSecurePassword123!', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))

# 添加新用户
# print(default_api.bloodyad_add_user(samAccountName='NewUser', newpass='NewUserPass123!', user='fluffy.htb\\svc_mssql', password='MssqlService01!', host='dc01.fluffy.htb'))
```

---

## 架构

```
Gemini-CLI → MCP Gateway → bloodyad-mcp → bloodyAD CLI (Kali)
```

---

## 故障排除

- 如果工具未显示：检查构建、日志、YAML 文件（`custom.yaml`、`registry.yaml`），并重新启动 Claude Desktop / Gemini-CLI。
- 如果 bloodyAD 命令失败：检查参数（主机、域、用户、密码）、VPN、目标机器的可达性以及 bloodyAD 版本。

---

## 安全注意事项

- 凭据随每个命令传递，不存储或记录。
- 服务器在 Docker 中以非 root 用户身份运行。
- 输出是纯文本，与 bloodyAD 的输出相同，没有表情符号或额外的 Markdown 格式。

---

## 许可证

MIT License

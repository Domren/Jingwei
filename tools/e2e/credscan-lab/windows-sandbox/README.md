# WinRM 真机验证：Windows 沙箱方案

WinRM 只有 Windows 有原生实现，Linux 上无论用什么容器都验不了（WinRM 服务端是
`WinRM` 服务 + `Microsoft-HTTPAPI/2.0`，WSMan 的 SOAP 与 Kerberos/NTLM 绑定在
Windows 安全子系统上）。所以这条只能用 Windows 沙箱。

## 为什么沙箱不是「开箱即用」

Windows Sandbox 的网络是 **NAT 单向**：

- 沙箱能出网（经宿主 NAT），
- 宿主能连沙箱（宿主是 NAT 网关），
- **但沙箱 IP 每次启动都变**，且沙箱内防火墙默认拦截全部入向。

再加上 kali 在 WSL2 里，是第二层 NAT，直接连沙箱网段会被 Windows 防火墙挡住。
所以要串一条：`kali → 宿主端口 → portproxy → 沙箱 5985`。

## 需要的文件

1. `winrm-lab.wsb` —— 沙箱配置（开网络、挂载脚本目录、登录后自动执行 setup.ps1）
2. `setup.ps1` —— 沙箱内：关防火墙、开 WinRM、把本机 IP 写到共享目录
3. `host-forward.ps1` —— 宿主：读沙箱 IP，建 portproxy 转发

## 用法

```powershell
# 1) 建共享目录，放入本目录的三个文件
mkdir C:\jw-winrm-lab
copy .\* C:\jw-winrm-lab\

# 2) 启动沙箱（会弹一个窗口，别关）
C:\jw-winrm-lab\winrm-lab.wsb

# 3) 等 20~30 秒让 setup.ps1 跑完，然后在宿主建转发
powershell -ExecutionPolicy Bypass -File C:\jw-winrm-lab\host-forward.ps1

# 4) 在 kali 里验证（宿主 IP 从 WSL 的默认网关取）
HOST_IP=$(ip route | awk '/^default/{print $3}')
cd /root/1/jingwei-dev
cat > /tmp/winrm-lab.json <<JSON
{"cases":[{"protocol":"winrm","label":"windows sandbox winrm","host":"$HOST_IP","port":15985,
 "username":"jwlab","password":"JwLab!Pass2026","wrong_password":"wrong-pw",
 "expect_good":"inconclusive"}]}
JSON
JW_CRED_LAB=1 JW_CRED_LAB_MANIFEST=/tmp/winrm-lab.json \
  go test ./scanner -run TestCredLabProtocols -count=1 -v
```

## 预期结论（重要）

**这条不会给出 hit/deny**。Windows 的 WinRM 默认只允许 Negotiate/NTLM/Kerberos，
我们的适配器不实现 SPNEGO，所以正确口令也会落 `inconclusive`，reason 会写
「服务端只给 Negotiate/NTLM/Kerberos」。

能验证的是这三件事：

1. `Identify` 认得出 WinRM（`Server: Microsoft-HTTPAPI/2.0` + `WWW-Authenticate: Negotiate`）；
2. 适配器**没有**把 401 当成「口令被拒绝」——这是最容易写错的地方；
3. 空凭据对照不会误判命中。

如果想让这条变成真正的 hit/deny，需要实现 NTLM over HTTP（SPNEGO 或裸 NTLMSSP 的
`Negotiate <base64>` 形态）。SMB 那条的 NTLMv2 计算可以直接复用，缺的只是
HTTP 承载与 SPNEGO 包装——这是下一步的活，不是现在能「起个服务就验」的。

## 沙箱的三个坑

- 沙箱关掉即销毁，每次都要重跑 setup 与 portproxy；
- `Enable-PSRemoting` 在沙箱里可能报「网络位置为公用」，要带 `-SkipNetworkProfileCheck`；
- 用户必须是管理员且已设密码，`Enable-PSRemoting` 才会创建监听器；
  沙箱里的默认账号 `WDAGUtilityAccount` 需要先 `net user WDAGUtilityAccount JwLab!Pass2026`。

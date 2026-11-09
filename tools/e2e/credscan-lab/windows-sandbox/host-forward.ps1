# 宿主执行：读沙箱 IP，把宿主 15985 转发到沙箱 5985。
# kali 在 WSL2 里，连宿主用 WSL 的默认网关地址，所以监听 0.0.0.0。

$ErrorActionPreference = 'Stop'
$ipFile = 'C:\jw-winrm-lab\sandbox-ip.txt'
$listenPort = 15985
$targetPort = 5985

if (-not (Test-Path $ipFile)) {
    throw "找不到 $ipFile —— 沙箱里的 setup.ps1 还没跑完，或共享目录没挂上"
}

$sandboxIp = (Get-Content $ipFile | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
if (-not $sandboxIp) { throw "$ipFile 里没有 IPv4 地址" }

Write-Host "sandbox ip = $sandboxIp"

# 清掉旧规则，避免沙箱 IP 变了之后还指向旧地址。
netsh interface portproxy delete v4tov4 listenport=$listenPort listenaddress=0.0.0.0 2>$null | Out-Null
netsh interface portproxy add v4tov4 listenport=$listenPort listenaddress=0.0.0.0 `
    connectport=$targetPort connectaddress=$sandboxIp | Out-Null

netsh interface portproxy show v4tov4

# 宿主的 15985 也要放行（WSL 过来的流量被 Windows 防火墙当外部流量）。
New-NetFirewallRule -DisplayName "JW WinRM Lab 15985" -Direction Inbound -Protocol TCP `
    -LocalPort $listenPort -Action Allow -ErrorAction SilentlyContinue | Out-Null

Test-NetConnection -ComputerName $sandboxIp -Port $targetPort -InformationLevel Quiet |
    ForEach-Object { Write-Host "sandbox:$targetPort reachable = $_" }

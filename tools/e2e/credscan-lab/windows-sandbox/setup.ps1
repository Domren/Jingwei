# 沙箱内执行：开 WinRM、关防火墙、把本机 IP 写到共享目录供宿主建 portproxy。
$ErrorActionPreference = 'Continue'
$log = 'C:\lab\setup.log'
"=== setup start $(Get-Date -Format o)" | Out-File $log

# 沙箱默认账号没有密码，Enable-PSRemoting 要求账号有口令。
$pw = 'JwLab!Pass2026'
try {
    net user WDAGUtilityAccount $pw | Out-File $log -Append
} catch {
    "net user failed: $_" | Out-File $log -Append
}

# 入向全拦是沙箱默认，不关掉宿主根本连不进来。
Set-NetFirewallProfile -All -Enabled False -ErrorAction Continue

Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Continue
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force -ErrorAction Continue

# WinRM 服务端本来就在 5985 上听，这里确认一下。
$listening = (Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue | Measure-Object).Count
"listening_5985=$listening" | Out-File $log -Append

# 把沙箱 IP 交给宿主：宿主要用它建 portproxy。
$ips = Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike '127.*' } |
       Select-Object -ExpandProperty IPAddress
$ips | Out-File C:\lab\sandbox-ip.txt
$ips | Out-File $log -Append
"=== setup done" | Out-File $log -Append

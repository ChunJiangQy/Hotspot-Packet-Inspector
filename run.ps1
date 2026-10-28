# packet_compare/run.ps1 v2.0 - Generic WinDivert-based packet capture + byte comparison tool
#
# 通用化: 支持任意目标进程(通过 --pname 或 --pid 参数)
# 完全可移植: 所有路径基于脚本所在目录($PSScriptRoot), 不依赖任何硬编码路径
#
# Usage (in Admin PowerShell):
#   .\run.ps1 setup                 # 安装 WinDivert 驱动(一次)
#   .\run.ps1 status                # 显示驱动状态、当前所有候选进程
#   .\run.ps1 listproc <pname>      # 列出所有匹配 pname 的进程及连接数
#   .\run.ps1 listpid  <pid|pname>  # 显示指定 PID/进程名的所有 TCP+UDP 连接
#   .\run.ps1 capture  <out.pcap> [opts]  # 通用抓包
#       opts: --pname <name> | --pid <pid> | --port <p1,p2> | --ip <addr>
#             --duration <sec>(默认0=无限) --full --hotspot --stats <sec> --filter "<expr>"
#   .\run.ps1 compare  <f1.pcap> <f2.pcap> [opts]  # 字节级对比
#       opts: --report <out.txt> --port <p> --detail --flow <key> --bin <prefix>
#   .\run.ps1 dumpflow <pcap> <ip> <port> [--out <base>]
#
# Examples:
#   .\run.ps1 listproc chrome               # 列所有 chrome 进程
#   .\run.ps1 listpid chrome                # 显示所有 chrome 进程的连接
#   .\run.ps1 capture cap1.pcap --pname chrome --stats 5
#   .\run.ps1 capture cap2.pcap --pname chrome --duration 60
#   .\run.ps1 compare cap1.pcap cap2.pcap --report diff.txt --detail --bin diff
#   .\run.ps1 dumpflow cap1.pcap 142.250.80.46 443

param(
    [Parameter(Position=0)][string]$Action = 'status',
    [Parameter(Position=1, ValueFromRemainingArguments=$true)][string[]]$Rest = @()
)

$ErrorActionPreference = 'Stop'
# 脚本所在目录(用于定位同目录的 windivert\...\x64\PacketTool.exe)
$here  = Split-Path -Parent $MyInvocation.MyCommand.Path

# ===== 定位 PacketTool.exe (只在脚本同目录下的 windivert 子目录查找) =====
$exe = Join-Path $here 'windivert\WinDivert-2.2.2-A\x64\PacketTool.exe'
if (-not (Test-Path $exe)) {
    # 兜底: 在脚本同目录下搜索任何 PacketTool.exe
    $found = Get-ChildItem -Path $here -Recurse -Filter 'PacketTool.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $exe = $found.FullName }
}
if (-not (Test-Path $exe)) {
    Write-Host '[!] PacketTool.exe not found.' -ForegroundColor Red
    Write-Host '    Expected location:' -ForegroundColor Yellow
    Write-Host "      $here\windivert\WinDivert-2.2.2-A\x64\PacketTool.exe"
    Write-Host '    Ensure windivert\WinDivert-2.2.2-A\x64\ contains PacketTool.exe + WinDivert.dll + WinDivert64.sys'
    exit 1
}

function Write-Title($t) {
    Write-Host ''
    Write-Host ('=' + ('=' * 60)) -ForegroundColor Cyan
    Write-Host (' ' + $t) -ForegroundColor Cyan
    Write-Host ('=' + ('=' * 60)) -ForegroundColor Cyan
}

function Ensure-Admin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[!] Admin privilege required. Run PowerShell as Administrator.' -ForegroundColor Red
        exit 1
    }
}

function Get-DriverPath {
    return (Join-Path (Split-Path $exe) 'WinDivert64.sys')
}

switch ($Action.ToLower()) {
    'setup' {
        Write-Title 'Install WinDivert Driver'
        Ensure-Admin
        $sys = Get-DriverPath
        if (-not (Test-Path $sys)) { Write-Host "[!] Missing $sys" -ForegroundColor Red; exit 1 }
        $exists = Get-Service -Name WinDivert -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Host '[*] Service exists, status: ' -NoNewline
            if ($exists.Status -ne 'Running') {
                Write-Host 'starting...' -ForegroundColor Yellow
                sc.exe start WinDivert | Out-Null
                Start-Sleep -Seconds 1
            }
        } else {
            Write-Host '[*] Creating and starting WinDivert service...'
            sc.exe create WinDivert type= kernel binPath= "`"$sys`"" | Out-Null
            sc.exe start WinDivert | Out-Null
            Start-Sleep -Seconds 1
        }
        $svc = Get-Service -Name WinDivert -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Host '[OK] WinDivert driver is running' -ForegroundColor Green
        } else {
            Write-Host '[!] Driver not running' -ForegroundColor Red
        }
    }

    'status' {
        Write-Title 'PacketTool v2.0 Status'
        Write-Host ('Exe path: ' + $exe)
        Write-Host ('Driver sys: ' + (Get-DriverPath))
        $svc = Get-Service -Name WinDivert -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host ('WinDivert driver: ' + $svc.Status)
        } else {
            Write-Host 'WinDivert driver: not installed (run: .\run.ps1 setup)' -ForegroundColor Yellow
        }
        Write-Host ''
        Write-Host 'Common target processes (browsers/emulators/etc):' -ForegroundColor Cyan
        $common = @('chrome','msedge','firefox','dnplayer*','LdVBoxHeadless','QQPlayer*','GameLoop*','Nox*','MuMu*')
        foreach ($name in $common) {
            $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like $name }
            if ($procs) {
                foreach ($p in $procs) {
                    Write-Host ('  PID {0,6}  {1}' -f $p.Id, $p.ProcessName)
                }
            }
        }
        Write-Host ''
        Write-Host 'Available commands:' -ForegroundColor Cyan
        Write-Host '  .\run.ps1 setup                                Install driver'
        Write-Host '  .\run.ps1 status                               Show status'
        Write-Host '  .\run.ps1 listproc <pname>                     List matching processes'
        Write-Host '  .\run.ps1 listpid  <pid|pname>                 Show TCP+UDP connections'
        Write-Host '  .\run.ps1 capture  <out.pcap> [opts]           Generic capture (Ctrl+C to stop)'
        Write-Host '  .\run.ps1 compare  <f1.pcap> <f2.pcap> [opts]  Byte-level compare'
        Write-Host '  .\run.ps1 dumpflow <pcap> <ip> <port> [opts]   Export single flow'
    }

    'listproc' {
        if ($Rest.Count -lt 1) { Write-Host 'Usage: listproc <pname>'; exit 1 }
        Ensure-Admin
        & $exe listproc $Rest[0]
    }

    'listpid' {
        if ($Rest.Count -lt 1) { Write-Host 'Usage: listpid <pid|pname>'; exit 1 }
        Ensure-Admin
        & $exe listpid $Rest[0]
    }

    'capture' {
        Write-Title 'Generic Packet Capture'
        Ensure-Admin
        if ($Rest.Count -lt 1) {
            Write-Host 'Usage: capture <out.pcap> [--hotspot] [--pname <name>] [--pid <pid>] [--port <p1,p2>] [--ip <addr>] [--duration <sec>] [--full] [--stats <sec>] [--filter "<expr>"]'
            Write-Host '  --duration 0 = unlimited (default, Ctrl+C to stop)'
            exit 1
        }
        Write-Host ('[*] Exe: ' + $exe)
        & $exe capture $Rest
    }

    'compare' {
        Write-Title 'Byte-Level Compare'
        if ($Rest.Count -lt 2) {
            Write-Host 'Usage: compare <f1.pcap> <f2.pcap> [--report <out.txt>] [--port <p>] [--detail] [--flow <key>] [--bin <prefix>]'
            exit 1
        }
        & $exe compare $Rest
    }

    'dumpflow' {
        Write-Title 'Dump Single Flow'
        if ($Rest.Count -lt 3) {
            Write-Host 'Usage: dumpflow <pcap> <ip> <port> [--out <base>]'
            exit 1
        }
        & $exe dumpflow $Rest
    }

    default {
        Write-Host "Usage: .\run.ps1 <setup|status|listproc|listpid|capture|compare|dumpflow>"
        Write-Host "Run .\run.ps1 status for details."
    }
}

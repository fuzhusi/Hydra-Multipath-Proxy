#!/usr/bin/env pwsh
<#
.SYNOPSIS
    生成嵌入式 GeoIP-CN 段表 hydra-core/assets/geoip_cn.dat（智能分流 v1.1 §3.3）。
.DESCRIPTION
    数据源（依次回退）：
      1. APNIC delegated 列表 https://ftp.apnic.net/stats/apnic/delegated-apnic-latest
         （行格式 apnic|CN|ipv4|start|count / apnic|CN|ipv6|prefix|bits）
      2. GitHub 镜像 mzack9/chnroute（chnroute.txt，CIDR 列表，v4+v6）
      3. GitHub 镜像 gaoyifan/china-operator-ip（chnroute.txt v4 + chnroute6.txt v6）
    聚合：解析全部 CN IPv4/IPv6 段 → (start,end) 闭区间 → 排序 → 相邻/重叠合并。
    输出格式（大端）：
      magic "HGI1" | u32 v4 段数 | v4 段 (start,end) 各 8B 排序数组
                   | u32 v6 段数 | v6 段 (start,end) 各 32B 排序数组（u128）
    产物提交入 git（CI 不联网也能构建）；数据时效以运行本脚本的日期为准。
#>
param(
    [string]$OutFile = (Join-Path $PSScriptRoot "..\hydra-core\assets\geoip_cn.dat")
)
$ErrorActionPreference = 'Stop'

# ── 1. 下载（多源回退）───────────────────────────────────────────────────────
$urls = @(
    'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest',
    'https://raw.githubusercontent.com/mzack9/chnroute/master/chnroute.txt',
    'https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chnroute.txt',
    'https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chnroute6.txt'
)
$lines = New-Object System.Collections.Generic.List[string]
$usedSources = @()
foreach ($u in $urls) {
    try {
        Write-Host "下载 $u ..."
        $resp = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 60
        $text = if ($resp.Content -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($resp.Content)
        } else { $resp.Content }
        $n = 0
        foreach ($l in ($text -split "`n")) { $t = $l.Trim(); if ($t) { $lines.Add($t); $n++ } }
        $usedSources += "$u ($n 行)"
        Write-Host "  ✓ $n 行"
    } catch {
        Write-Warning "源不可用（跳过）: $u — $($_.Exception.Message)"
    }
}
if ($usedSources.Count -eq 0) { throw "所有数据源均不可用，无法生成 GeoIP 表" }

# ── 2. 解析为 (start,end) 区间（v6 用 BigInteger 处理 128 位）───────────────
$v4 = New-Object System.Collections.Generic.List[object]   # @{s=[uint32];e=[uint32]}
$v6 = New-Object System.Collections.Generic.List[object]   # @{s=[BigInteger];e=[BigInteger]}
$cidrRe = [regex]'^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$'
$cidr6Re = [regex]'^([0-9a-fA-F:]+)/(\d{1,3})$'
$delegRe = [regex]'^apnic\|CN\|ipv4\|([^|]+)\|(\d+)(?:\|.*)?$'
$deleg6Re = [regex]'^apnic\|CN\|ipv6\|([^|]+)\|(\d+)(?:\|.*)?$'

function To-Big([byte[]]$be16) {
    # 16 字节大端 → BigInteger（内部小端二补数 + 正数符号字节）
    $le = [byte[]]::new(17); for ($i = 0; $i -lt 16; $i++) { $le[$i] = $be16[15 - $i] }
    [System.Numerics.BigInteger]::new($le)
}
function From-Big([System.Numerics.BigInteger]$b) {
    # BigInteger → 16 字节大端
    $bytes = $b.ToByteArray()
    $be = [byte[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) { $be[15 - $i] = if ($i -lt $bytes.Length) { $bytes[$i] } else { 0 } }
    , $be
}
function Ipv4-To-U32([System.Net.IPAddress]$ip) {
    $o = $ip.GetAddressBytes()
    ([uint32]$o[0] -shl 24) -bor ([uint32]$o[1] -shl 16) -bor ([uint32]$o[2] -shl 8) -bor [uint32]$o[3]
}

foreach ($line in $lines) {
    if ($line.StartsWith('#')) { continue }
    $m = $delegRe.Match($line)
    if ($m.Success) {
        $start = Ipv4-To-U32 ([System.Net.IPAddress]::Parse($m.Groups[1].Value))
        $count = [uint64]$m.Groups[2].Value
        if ($count -eq 0) { continue }
        $end = [uint64]$start + $count - 1
        if ($end -gt [uint32]::MaxValue) { $end = [uint32]::MaxValue }
        $v4.Add([pscustomobject]@{ s = $start; e = [uint32]$end })
        continue
    }
    $m = $deleg6Re.Match($line)
    if ($m.Success) {
        $ip = [System.Net.IPAddress]::Parse($m.Groups[1].Value)
        $prefix = [int]$m.Groups[2].Value
        if ($prefix -lt 0 -or $prefix -gt 128) { continue }
        $start = To-Big $ip.GetAddressBytes()
        $span = [System.Numerics.BigInteger]::Pow(2, 128 - $prefix)
        $v6.Add([pscustomobject]@{ s = $start; e = $start + $span - [System.Numerics.BigInteger]::One })
        continue
    }
    $m = $cidrRe.Match($line)
    if ($m.Success) {
        $p = [int]$m.Groups[2].Value
        if ($p -lt 0 -or $p -gt 32) { continue }
        $start = Ipv4-To-U32 ([System.Net.IPAddress]::Parse($m.Groups[1].Value))
        $mask = if ($p -eq 0) { [uint32]::MaxValue } else { [uint32]::MaxValue -shl (32 - $p) }
        $net = $start -band $mask
        $v4.Add([pscustomobject]@{ s = $net; e = $net -bor (-bnot $mask) })
        continue
    }
    $m = $cidr6Re.Match($line)
    if ($m.Success -and $line.Contains(':')) {
        $p = [int]$m.Groups[2].Value
        if ($p -lt 0 -or $p -gt 128) { continue }
        $base = To-Big ([System.Net.IPAddress]::Parse($m.Groups[1].Value).GetAddressBytes())
        $mask = [System.Numerics.BigInteger]::Pow(2, 128 - $p) - [System.Numerics.BigInteger]::One
        $net = $base -band (-bnot $mask)
        $v6.Add([pscustomobject]@{ s = $net; e = $net -bor $mask })
        continue
    }
}

Write-Host ("解析完成：IPv4 段 {0} 条，IPv6 段 {1} 条" -f $v4.Count, $v6.Count)
if ($v4.Count -eq 0) { throw "未解析到任何 CN IPv4 段（数据源格式变化？）" }

# ── 3. 排序 + 相邻/重叠合并 ──────────────────────────────────────────────────
function Merge-Ranges([System.Collections.IEnumerable]$ranges) {
    $sorted = @($ranges | Sort-Object s, e)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $sorted) {
        if ($out.Count -gt 0 -and $r.s -le [System.Numerics.BigInteger]::Add(([object]$out[$out.Count - 1]).e, 1)) {
            $last = $out[$out.Count - 1]
            if ($r.e -gt $last.e) { $out[$out.Count - 1] = [pscustomobject]@{ s = $last.s; e = $r.e } }
        } else {
            $out.Add($r)
        }
    }
    $out
}
$v4m = Merge-Ranges $v4
$v6m = Merge-Ranges $v6
Write-Host ("合并后：IPv4 段 {0} 条，IPv6 段 {1} 条" -f $v4m.Count, $v6m.Count)

# ── 4. 写 dat（大端）────────────────────────────────────────────────────────
$outDir = Split-Path $OutFile -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

function Write-BE32([System.IO.BinaryWriter]$w, [uint32]$v) {
    $b = [BitConverter]::GetBytes($v); [array]::Reverse($b); $w.Write($b)
}

$fs = [System.IO.File]::Create($OutFile)
$bw = New-Object System.IO.BinaryWriter($fs)
try {
    $bw.Write([byte[]]([byte][char]'H', [byte][char]'G', [byte][char]'I', [byte][char]'1'))
    Write-BE32 $bw ([uint32]$v4m.Count)
    foreach ($r in $v4m) { Write-BE32 $bw ([uint32]$r.s); Write-BE32 $bw ([uint32]$r.e) }
    Write-BE32 $bw ([uint32]$v6m.Count)
    foreach ($r in $v6m) { $bw.Write((From-Big $r.s)); $bw.Write((From-Big $r.e)) }
} finally {
    $bw.Close(); $fs.Close()
}
$size = (Get-Item $OutFile).Length
Write-Host "✓ 已生成 $OutFile（$size 字节）"
Write-Host "数据源：$($usedSources -join '；')"
Write-Host "生成时间：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"

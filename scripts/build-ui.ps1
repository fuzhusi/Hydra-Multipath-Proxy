# 一键构建本地 UI 测试包（hydra-client-gui.exe + wintun.dll → local-dist/）
# 用法：右键"使用 PowerShell 运行"，或在仓库根执行 .\scripts\build-ui.ps1
# TUN 模式需以管理员身份运行 local-dist\hydra-client-gui.exe（wintun.dll 已就位）
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[1/3] cargo build --release -p hydra-client-gui ..."
cargo build --release -p hydra-client-gui
if ($LASTEXITCODE -ne 0) { Write-Error "构建失败"; exit 1 }

Write-Host "[2/3] 汇集到 local-dist/ ..."
New-Item -ItemType Directory -Force -Path local-dist | Out-Null
Copy-Item target/release/hydra-client-gui.exe local-dist/ -Force

Write-Host "[3/3] wintun.dll（缺才下载，0.14.1 官方签名版）..."
if (-not (Test-Path local-dist/wintun.dll)) {
    $zip = Join-Path $env:TEMP "wintun-0.14.1.zip"
    curl.exe -sL --connect-timeout 30 --max-time 300 -o $zip https://www.wintun.net/builds/wintun-0.14.1.zip
    $ex = Join-Path $env:TEMP "wintun-extracted"
    Expand-Archive -Path $zip -DestinationPath $ex -Force
    Copy-Item "$ex/wintun/bin/amd64/wintun.dll" local-dist/wintun.dll -Force
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    Remove-Item $ex -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "完成 → local-dist/hydra-client-gui.exe（双击运行；TUN 需管理员）"

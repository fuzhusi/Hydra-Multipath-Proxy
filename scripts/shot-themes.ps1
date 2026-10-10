# Three-theme screenshots (DPI-aware + PrintWindow full-content render).
# ASCII-only: Windows PowerShell 5.1 reads BOM-less files as ANSI.
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32Shot {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@

[void][Win32Shot]::SetProcessDPIAware()
$cfgPath = Join-Path "$env:APPDATA\hydra" "config.json"

function Set-Theme([string]$theme) {
    $json = Get-Content $cfgPath -Encoding UTF8 -Raw | ConvertFrom-Json
    if ($json.PSObject.Properties.Name -contains 'ui_theme') {
        $json.ui_theme = $theme
    } else {
        $json | Add-Member -NotePropertyName ui_theme -NotePropertyValue $theme
    }
    [System.IO.File]::WriteAllText($cfgPath, ($json | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
    Start-Sleep -Milliseconds 300
    Start-Process -FilePath "target\debug\hydra-client-gui.exe" | Out-Null
    Start-Sleep -Seconds 9
    $proc = Get-Process hydra-client-gui -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if (-not $proc) { Write-Host "[shot] $theme : no GUI window, skipped"; return }
    $h = $proc.MainWindowHandle
    $r = New-Object Win32Shot+RECT
    [void][Win32Shot]::GetWindowRect($h, [ref]$r)
    $w = $r.Right - $r.Left; $ht = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $ht)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    [void][Win32Shot]::PrintWindow($h, $hdc, 2)
    $g.ReleaseHdc($hdc)
    $g.Dispose()
    $out = "$env:TEMP\ui-$theme.png"
    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "[shot] $theme -> $out (${w}x${ht})"
    Get-Process hydra-client-gui -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
}

foreach ($t in @("dark", "light", "abyss")) { Set-Theme $t }
Write-Host "[shot] done"

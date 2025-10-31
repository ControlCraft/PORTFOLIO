# VPN KillSwitch Audit and Hardening (AmneziaVPN Case)

## Overview
This case documents a reproducible privacy flaw in **AmneziaVPN for Windows** (versions 4.8–4.9), where the built-in Kill Switch fails to block outbound traffic from Chrome after either a normal Disconnect or forced app termination. The result is a direct **public IP leak** through the physical network interface.

## Findings
- The Kill Switch does not enforce persistent system-level firewall rules.  
- When the VPN tunnel (WireGuard or X-Ray) is disconnected, Chrome automatically falls back to the Ethernet adapter.  
- Tests confirmed IP leaks even under normal Disconnect (via the orange “Connected” button).  
- Windows Firewall can reliably enforce zero-leak behavior when properly configured.

## Mitigation
A **PowerShell-based persistent Kill Switch** was developed to block Chrome on all physical interfaces and allow traffic only through:
- The **WireGuard** tunnel interface `AmneziaVPN`.
- The **local X-Ray proxy** at `127.0.0.1:<port>` (e.g., `10777`).

```powershell
# Core principle: allow Chrome only via secure tunnel interfaces

$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $chrome)) {
  $chrome = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
}

# Clean previous rules
Get-NetFirewallRule -Group "Chrome KillSwitch" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# ALLOW — X-Ray local proxy (adjust port if needed)
$xrayPort = 10777
New-NetFirewallRule -Group "Chrome KillSwitch" -DisplayName "Chrome KillSwitch X-Ray" `
  -Direction Outbound -Program $chrome -Action Allow -Profile Any `
  -Protocol TCP -RemoteAddress 127.0.0.1 -RemotePort $xrayPort | Out-Null

# ALLOW — AmneziaWG (WireGuard interface)
if (Get-NetAdapter -Name "AmneziaVPN" -ErrorAction SilentlyContinue) {
  New-NetFirewallRule -Group "Chrome KillSwitch" -DisplayName "Chrome KillSwitch AmneziaWG" `
    -Direction Outbound -Program $chrome -Action Allow -Profile Any `
    -InterfaceAlias "AmneziaVPN" | Out-Null
}

# BLOCK — all Chrome traffic on physical interface (Ethernet)
New-NetFirewallRule -Group "Chrome KillSwitch" -DisplayName "Chrome block on Ethernet" `
  -Direction Outbound -Program $chrome -Action Block -Profile Any -InterfaceAlias "Ethernet" | Out-Null

# BLOCK — QUIC (UDP/443) to prevent HTTP/3 bypass
New-NetFirewallRule -Group "Chrome KillSwitch" -DisplayName "Chrome block UDP443 on Ethernet" `
  -Direction Outbound -Program $chrome -Action Block -Profile Any `
  -Protocol UDP -RemotePort 443 -InterfaceAlias "Ethernet" | Out-Null

Write-Host "Chrome KillSwitch installed: X-Ray + AmneziaWG allowed, Ethernet blocked."
```

## Verification
Testing confirmed:
- Immediate Chrome disconnection after VPN loss (no IP fallback).  
- Proper operation under both **WireGuard** and **X-Ray**.  
- No delay, no background polling required.  
- Full persistence across reboots.

## Contribution
A detailed GitHub issue was filed in the **AmneziaVPN desktop-client** repository describing the defect, reproduction steps, and a suggested implementation using the Windows Filtering Platform (WFP).

Focus: system integration, network security, and process hardening.

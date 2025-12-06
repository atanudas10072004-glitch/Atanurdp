name: RDP

on:
  workflow_dispatch:

jobs:
  secure-rdp:
    runs-on: windows-latest   # Use a self-hosted Windows runner for persistence
    timeout-minutes: 3600

    env:
      TAILSCALE_AUTH_KEY: ${{ secrets.TAILSCALE_AUTH_KEY }}

    steps:
      - name: Configure Core RDP Settings
        shell: pwsh
        run: |
          Write-Host "=== Configure Core RDP Settings ==="

          # Enable Remote Desktop
          Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
            -Name "fDenyTSConnections" -Value 0 -Force -ErrorAction Stop
          Write-Host "Enabled Remote Desktop (fDenyTSConnections = 0)"

          # OPTIONAL: Disable NLA (UserAuthentication = 0). Comment out to keep NLA enabled (recommended).
          # Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
          #   -Name "UserAuthentication" -Value 0 -Force -ErrorAction Continue

          # Optional: set SecurityLayer (0 = RDP, 1 = Negotiate, 2 = SSL)
          Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name "SecurityLayer" -Value 0 -Force -ErrorAction Continue

          # Ensure TermService is automatic and restart to apply changes
          Try {
            Set-Service -Name TermService -StartupType Automatic -ErrorAction Stop
            Restart-Service -Name TermService -Force -ErrorAction Stop
            Write-Host "TermService restarted."
          } Catch {
            Write-Warning "Could not restart TermService: $_"
          }

          # Manage firewall: remove old rule if present, allow TCP 3389
          netsh advfirewall firewall delete rule name="RDP-Tailscale" | Out-Null
          netsh advfirewall firewall add rule name="RDP-Tailscale" dir=in action=allow protocol=TCP localport=3389 | Out-Null
          Write-Host "Firewall rule RDP-Tailscale added (TCP 3389 allowed)."

      - name: Create RDP User with Secure Password
        shell: pwsh
        id: create_user
        run: |
          Write-Host "=== Create local RDP user ==="

          # Build a random strong password
          $charSet = @{
              Upper   = [char[]](65..90)      # A-Z
              Lower   = [char[]](97..122)     # a-z
              Number  = [char[]](48..57)      # 0-9
              Special = ([char[]](33..47) + [char[]](58..64) + [char[]](91..96) + [char[]](123..126))
          }

          $rawPassword = @()
          $rawPassword += $charSet.Upper | Get-Random -Count 4
          $rawPassword += $charSet.Lower | Get-Random -Count 4
          $rawPassword += $charSet.Number | Get-Random -Count 4
          $rawPassword += $charSet.Special | Get-Random -Count 4
          $password = -join ($rawPassword | Sort-Object { Get-Random })

          $username = "RDP"
          $securePass = ConvertTo-SecureString $password -AsPlainText -Force

          # Create or update user
          if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
            Write-Host "User '$username' exists — updating password."
            try {
              $acct = Get-LocalUser -Name $username
              $acct | Set-LocalUser -Password $securePass -ErrorAction Stop
            } catch {
              Write-Warning "Failed to update password for ${username}: $($_)"
            }
          } else {
            try {
              New-LocalUser -Name $username -Password $securePass -AccountNeverExpires:$true -UserMayNotChangePassword:$false -ErrorAction Stop
              Write-Host "Created user: $username"
            } catch {
              Write-Error "Failed to create user $username: $_"
              exit 1
            }
          }

          # Add to groups
          try {
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $username -ErrorAction Stop
            Add-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction Stop
            Write-Host "Added $username to Remote Desktop Users and Administrators."
          } catch {
            Write-Warning "Could not add user to one or more groups: $_"
          }

          # Save credentials to GITHUB_ENV for later steps
          # WARNING: This writes the cleartext password to environment — treat carefully (do not print it).
          Add-Content -Path $env:GITHUB_ENV -Value "RDP_USER=$username"
          Add-Content -Path $env:GITHUB_ENV -Value "RDP_PASSWORD=$password"

          Write-Host "Local RDP user created and credentials stored to GITHUB_ENV."

      - name: Install Tailscale
        shell: pwsh
        run: |
          Write-Host "=== Install Tailscale ==="
          $tsUrl = "https://pkgs.tailscale.com/stable/tailscale-setup-1.82.0-amd64.msi"
          $installerPath = Join-Path $env:TEMP "tailscale.msi"

          Invoke-WebRequest -Uri $tsUrl -OutFile $installerPath -UseBasicParsing
          Start-Process msiexec.exe -ArgumentList "/i", "`"$installerPath`"", "/quiet", "/norestart" -Wait
          Remove-Item $installerPath -Force
          Write-Host "Tailscale installed."

      - name: Establish Tailscale Connection
        shell: pwsh
        env:
          TAILSCALE_AUTH_KEY: ${{ secrets.TAILSCALE_AUTH_KEY }}
        run: |
          if (-not $env:TAILSCALE_AUTH_KEY -or $env:TAILSCALE_AUTH_KEY.Trim() -eq "") {
            Write-Error "Missing TAILSCALE_AUTH_KEY secret."
            exit 1
          }

          Write-Host "=== Bring up Tailscale ==="
          $exe = Join-Path $env:ProgramFiles "Tailscale\tailscale.exe"

          if (-not (Test-Path $exe)) {
            Write-Error "tailscale.exe not found at $exe"
            exit 1
          }

          & $exe up --authkey="$($env:TAILSCALE_AUTH_KEY)" --hostname="gh-runner-$($env:GITHUB_RUN_ID)" | Out-Null

          # Wait for an IPv4 address to be assigned
          $tsIP = $null
          $retries = 0
          while (-not $tsIP -and $retries -lt 20) {
            Start-Sleep -Seconds 3
            $ips = & $exe ip -4 2>$null
            if ($ips) {
              $tsIP = ($ips -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })[0]
            }
            $retries++
          }

          if (-not $tsIP) {
            Write-Error "Tailscale IP not assigned after retries."
            exit 1
          }

          Write-Host "Tailscale IP: $tsIP"
          Add-Content -Path $env:GITHUB_ENV -Value "TAILSCALE_IP=$tsIP"

      - name: Verify RDP Accessibility
        shell: pwsh
        run: |
          Write-Host "=== Verify RDP Accessibility ==="
          $ip = $env:TAILSCALE_IP
          if (-not $ip) {
            Write-Error "No Tailscale IP available."
            exit 1
          }

          $test = Test-NetConnection -ComputerName $ip -Port 3389 -WarningAction SilentlyContinue
          if ($test.TcpTestSucceeded) {
            Write-Host "TCP connectivity to RDP port confirmed."
          } else {
            Write-Warning "TCP test to $ip:3389 failed. It may still work depending on timing and firewall rules."
          }

      - name: Show connection info (short-lived)
        shell: pwsh
        run: |
          Write-Host "=== RDP ACCESS INFO (use immediately) ==="
          Write-Host "Tailscale IP: $env:TAILSCALE_IP"
          Write-Host "Username: $env:RDP_USER"
          Write-Host "Password: (stored in environment variable RDP_PASSWORD; not printed for safety)"
          Write-Host ""
          Write-Host "Note: This runner is ephemeral. For a persistent RDP host use a self-hosted Windows runner or configure a permanent machine."

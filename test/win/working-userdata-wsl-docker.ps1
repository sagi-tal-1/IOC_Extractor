<powershell>
Start-Transcript "C:\wsl-install.log" -Append
$ErrorActionPreference = "Stop"

if (-not (Test-Path "C:\wsl-phase2.flag")) {
    Write-Host "Phase 2 flag not found. Exiting."
    Stop-Transcript
    exit
}

# Remove flag so this only runs once
Remove-Item "C:\wsl-phase2.flag" -Force

Write-Host "Downloading Ubuntu 22.04 rootfs..."
$ubuntuUrl = "https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-amd64-rootfs.tar.gz"
Invoke-WebRequest -Uri $ubuntuUrl -OutFile "C:\ubuntu.tar.gz" -UseBasicParsing

Write-Host "Importing Ubuntu 22.04..."
New-Item -Path "C:\Ubuntu-22.04" -ItemType Directory -Force
wsl --import Ubuntu-22.04 "C:\Ubuntu-22.04" "C:\ubuntu.tar.gz"

Write-Host "Configuring default user..."
wsl -d Ubuntu-22.04 -- useradd -m -G sudo -s /bin/bash ubuntu
wsl -d Ubuntu-22.04 -- bash -c "echo 'ubuntu:ubuntu' | chpasswd"
wsl -d Ubuntu-22.04 -- bash -c "echo '[user]\ndefault=ubuntu' > /etc/wsl.conf"

Write-Host "Installing Docker inside Ubuntu..."
$dockerCmd = @"
#!/bin/bash
set -e
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo service docker start
sudo usermod -aG docker ubuntu
"@
wsl -d Ubuntu-22.04 -u root -- bash -c "$dockerCmd"

Write-Host "Cleaning up..."
Remove-Item "C:\ubuntu.tar.gz" -Force -ErrorAction SilentlyContinue

Write-Host "Installation complete! Use: wsl -d Ubuntu-22.04"
Stop-Transcript
</powershell>
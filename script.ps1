#Hostname
#Ipconfig /all
#Whoami /all
#wmic path softwareLicensingService get OA3xOriginalProductKey

Add-Type -AssemblyName System.Windows.Forms

# Vytvoření okna s textovým polem
$inputBox = New-Object System.Windows.Forms.Form
$inputBox.Text = "Zadejte hodnotu"
$inputBox.Size = New-Object System.Drawing.Size(300,150)
$inputBox.StartPosition = "CenterScreen"

# Textové pole
$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Size = New-Object System.Drawing.Size(260,20)
$textBox.Location = New-Object System.Drawing.Point(10,10)
$inputBox.Controls.Add($textBox)

# Tlačítko OK
$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = "OK"
$okButton.Location = New-Object System.Drawing.Point(110,40)
$okButton.Add_Click({ $inputBox.DialogResult = [System.Windows.Forms.DialogResult]::OK })
$inputBox.Controls.Add($okButton)

# Zobrazit okno a získat hodnotu
if ($inputBox.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $userInput = $textBox.Text
    Write-Host "Uživatel zadal: $userInput"
} else {
    Write-Host "Uživatel zrušil zadání."
}

#Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='subdomain.25plrp.cz' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Test_Doma' 
#Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='007.25plrp.cz' WAZUH_REGISTRATION_PASSWORD='' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='test' 
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='008.25plrp.cz' WAZUH_REGISTRATION_SERVER='007.25plrp.cz' WAZUH_REGISTRATION_PORT='1515'  WAZUH_REGISTRATION_PASSWORD='' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='test' 

NET START WazuhSvc
PAUSE

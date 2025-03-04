Hostname
Ipconfig /all
Whoami /all
wmic path softwareLicensingService get OA3xOriginalProductKey
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='subdomain.25plrp.cz' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Test_Doma' 
NET START WazuhSvc

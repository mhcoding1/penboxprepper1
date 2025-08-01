#!/bin/bash

# This script loads every repository and installs every application that can be useful for my Penetraion Testing process.

###### Creating the ressources folder ######

mkdir -p ~/Documents/Ressources/{'1.Recon'/{'1.Linux','2.Windows','3.Web','4.Active Directory'},'2.Exploits'/{'1.Linux','2.Windows','3.Web','4.Active Directory'},'3.Privesc'/{'1.Linux','2.Windows','3.Web'},'4.SystemTools'/{'1.Linux','2.Windows','3.Web','4.Pivoting'}}

# Install pipx
sudo apt install pipx -y

# Install go
sudo snap install go --classic


###### REPOS ######


# Download Mimikatz
cd ~/Documents/Ressources/3.Privesc/2.Windows && git clone https://github.com/ParrotSec/mimikatz.git

# Download Pypykatz
cd ~/Documents/Ressources/3.Privesc/2.Windows && git clone https://github.com/skelsec/pypykatz.git

# Download smtp-user-enum
cd ~/Documents/Ressources/1.Recon/2.Windows && git clone https://github.com/pentestmonkey/smtp-user-enum.git

# Download LaZagne
cd ~/Documents/Ressources/1.Recon/2.Windows && git clone https://github.com/AlessandroZ/LaZagne.git

# Download LaZagne Standalone
cd ~/Documents/Ressources/1.Recon/2.Windows/LaZagne && mkdir Standalone && cd Standalone && wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe

# Download ReconSpider
cd ~/Documents/Ressources/1.Recon/3.Web && wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip && unzip ReconSpider.zip && pip install scrapy

# Download FinalRecon
cd ~/Documents/Ressources/1.Recon/3.Web && git clone https://github.com/thewhiteh4t/FinalRecon.git

# Download (Win- / Lin-) PEASS
cd ~/Documents/Ressources/3.Privesc/2.Windows && git clone https://github.com/peass-ng/PEASS-ng.git

# Download PEAS Metasploit Modul
sudo wget https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/metasploit/peass.rb -O /usr/share/metasploit-framework/modules/post/multi/gather/peass.rb

# Download CrackMapExec
cd ~/Documents/Ressources/2.Exploits/2.Windows && git clone https://github.com/byt3bl33d3r/CrackMapExec.git

# Download DNS2Cat
cd ~/Documents/Ressources/2.Exploit/2.Windows && git clone https://github.com/iagox86/dnscat2.git

# Download FFuF
cd ~/Documents/Ressources/1.Recon/3.Web && git clone https://github.com/ffuf/ffuf.git

# Download o365spray
cd ~/Documents/Ressources/1.Recon/2.Windows && git clone https://github.com/0xZDH/o365spray.git

# Download Invoke-TheHash
cd ~/Documents/Ressources/2.Exploits/2.Windows/ && git clone https://github.com/Kevin-Robertson/Invoke-TheHash.git

# Download Impacket
cd ~/Documents/Ressources/2.Exploits/2.Windows && git clone https://github.com/fortra/impacket.git

# Download Rubeus
cd ~/Documents/Ressources/2.Exploits/2.Windows && git clone https://github.com/GhostPack/Rubeus.git

# Download Rubeus Binaries
cd ~/Documents/Ressources/2.Exploits/2.Windows && cd Rubeus && mkdir CompiledBinaries && cd CompiledBinaries && git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git

# Download Crowbar
cd ~/Documents/Ressources/2.Exploits/2.Windows && git clone https://github.com/galkan/crowbar.git

# Download Statistically-Likely-Usernames
cd /usr/share/wordlists && git clone https://github.com/insidetrust/statistically-likely-usernames.git

# Download DomainSpray
cd ~/Documents/Ressources/2.Exploits/4.Active\ Directory/ && git clone https://github.com/dafthack/DomainPasswordSpray.git

# Download Bloodhound
cd ~/Documents/Ressources/2.Exploits/4.Active\ Directory/ && git clone git clone https://github.com/dirkjanm/BloodHound.py.git

# Download Sharphound
cd ~/Documents/Ressources/2.Exploits/4.Active\ Directory/ && git clone https://github.com/SpecterOps/BloodHound-Legacy.git

# Download mRemoteNG
cd ~/Documents/Ressources/2.Exploits/2.Windows && git clone https://github.com/haseebT/mRemoteNG-Decrypt.git

# Download Sharpup
cd ~/Documents/Ressources/2.Exploits/2.Windows && git clone https://github.com/GhostPack/SharpUp.git

# Download SysInternals
mkdir ~/Documents/Ressources/4.SystemTools/2.Windows/Sysinternals && cd ~/Documents/Ressources/4.SystemTools/2.Windows/Sysinternals && wget https://download.sysinternals.com/files/SysinternalsSuite.zip && unzip SysinternalsSuite.zip && rm SysinternalsSuite.zip

# Download nc.exe
mkdir ~/Documents/Ressources/4.SystemTools/2.Windows/Netcat && cd ~/Documents/Ressources/4.SystemTools/2.Windows/Netcat && git clone https://github.com/int0x33/nc.exe

# Download JuicyPotato
cd ~/Documents/Ressources/3.Privesc/2.Windows && mkdir JuicyPotato && cd JuicyPotato && wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe

# Download PrintSpoofer
cd ~/Documents/Ressources/3.Privesc/2.Windows && git clone https://github.com/itm4n/PrintSpoofer.git && cd PrintSpoofer && wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe

# Download PowerUp
cd ~/Documents/Ressources/3.Privesc/2.Windows && mkdir PowerUp && cd PowerUp && curl https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 > PowerUp.ps1

# Download LinEnum
cd ~/Documents/Ressources/1.Recon/1.Linux && git clone https://github.com/rebootuser/LinEnum.git

# Download PowerSploit
cd ~/Documents/Ressources/3.Privesc/2.Windows && git clone https://github.com/PowerShellMafia/PowerSploit.git

# Download GTFOBins
cd ~/Documents/Ressources/3.Privesc/1.Linux && git clone https://github.com/GTFOBins/GTFOBins.github.io.git

# Download LOLBas
cd ~/Documents/Ressources/3.Privesc/2.Windows && git clone https://github.com/LOLBAS-Project/LOLBAS-Project.github.io.git

# Download Username-Anarchy
cd ~/Documents/Ressources/1.Recon/1.Linux && git clone https://github.com/urbanadventurer/username-anarchy.git

# Download JoomScan
cd ~/Documents/Ressources/1.Recon/3.Web && git clone https://github.com/rezasp/joomscan.git

# Prepare Rockyou.txt
cd /usr/share/wordlists && tar -xzvf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz

# Download SharpView
cd ~/Documents/Ressources/1.Recon/2.Windows && git clone https://github.com/dmchell/SharpView.git

# Download DroopeScan
cd ~/Documents/Ressources/1.Recon/3.Web && git clone https://github.com/droope/droopescan.git

# Download Sherlock
cd ~/Documents/Ressources/1.Recon/2.Windows && git clone https://github.com/rasta-mouse/Sherlock.git

# Download PayloadsAllTheThings
cd ~/Documents/Ressources/2.Exploits && mkdir 0.Overview && cd 0.Overview && git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# Download Enum4Linux
cd ~/Documents/Ressources/1.Recon/1.Linux && git clone https://github.com/cddmp/enum4linux-ng.git

# Download Keepass2John
cd ~/Documents/Ressources/4.SystemTools && mkdir keepass2john && cd keepass2john && wget https://gist.githubusercontent.com/HarmJ0y/116fa1b559372804877e604d7d367bbc/raw/c0c6f45ad89310e61ec0363a69913e966fe17633/keepass2john.py

# Download KeyTabExtract
cd ~/Documents/Ressources/2.Exploits/4.Active\ Directory/ && git clone https://github.com/sosdave/KeyTabExtract.git

# Download Responder
cd ~/Documents/Ressources/2.Exploits/4.Active\ Directory/ && git clone https://github.com/lgandx/Responder-Windows.git

# Download Kerbrute
cd ~/Documents/Ressources/2.Exploits/4.Active\ Directory/ && git clone https://github.com/ropnop/kerbrute.git && cd kerbrute && make help && make all

# Download KubeletCTL
cd ~/Documents/Ressources/3.Privesc/2.Windows && mkdir KubeletCTL && cd KubeletCTL && wget https://github.com/cyberark/kubeletctl/releases/download/v1.12/kubeletctl_linux_amd64

# Download UACMe
cd ~/Documents/Ressources/3.Privesc/2.Windows && git clone https://github.com/hfiref0x/UACME.git

# Download IIS-Shortname-Scanner
cd ~/Documents/Ressources/1.Recon/2.Windows && git clone https://github.com/irsdl/IIS-ShortName-Scanner.git

# Download RPivot
cd ~/Documents/Ressources/4.SystemTools/4.Pivoting/ && mkdir rpivot && cd rpivot && git clone https://github.com/klsecservices/rpivot.git && wget https://github.com/klsecservices/rpivot/releases/download/v1.0/client.exe

# Download Laudanum
cd ~/Documents/Ressources/2.Exploits/3.Web && git clone https://github.com/jbarcia/Web-Shells.git Laudanum

# Download Orangedefense AD-Template
cd ~/Documents/1.Recon/4.Active\ Directory/ && wget https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg

# Download Nmap Grep Cheatsheet
cd ~/Documents/Ressources/1.Recon/ && git clone https://github.com/leonjza/awesome-nmap-grep.git

# Download Blackeye
cd ~/Documents/Ressources/2.Exploits && git clone https://github.com/shuvo-halder/blackeye.git

# Download LFI-RCE-Sheet-Cheat
cd ~/Documents/Ressources/2.Exploits/3.Web && git clone https://github.com/RoqueNight/LFI---RCE-Cheat-Sheet.git

# Download Snaffler
cd ~/Documents/Ressources/1.Recon/2.Windows && git clone https://github.com/SnaffCon/Snaffler.git && wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.184/Snaffler.exe

# Download Windows Priv Enabler Script
cd ~/Documents/Ressources/3.Privesc/2.Windows && mkdir EnableAllTokenPrivs && cd EnableAllTokenPrivs && wget https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1

# Download Windapsearch
cd ~/Documents/Ressources/1.Recon/4.Active\ Directory/ && git clone https://github.com/ropnop/windapsearch.git && sudo sudo apt-get install python3-ldap && sudo ln -s /home/parrot/Documents/Ressources/1.Recon/4.Active\ Directory/windapsearch/windapsearch.py /usr/bin/windapsearch.py

# Download Chisel Server & Client
cd ~/Documents/Ressources/4.SystemTools/4.Pivoting && mkdir SocksOverRDP && cd SocksOverRDP && wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip && wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x86.zip

# Download Proxifier
cd ~/Documents/Ressources/4.SystemTools/4.Pivoting && mkdir Proxifier && cd Proxifier && wget https://www.proxifier.com/download/ProxifierPE.zip







###### INSTALLATIONS ######

# Install Chisel
curl https://i.jpillora.com/chisel! | bash

# Install CrackMapExec
pipx install git+https://github.com/byt3bl33d3r/CrackMapExec

# Install NetExec
sudo apt install netexec

# Install DNSCat2
cd ~/Documents/Ressources/4.SystemTools/2.Windows && git clone https://github.com/iagox86/dnscat2.git && cd dnscat2/client/ && make

# Install FFuF
go install github.com/ffuf/ffuf/v2@latest || git clone https://github.com/ffuf/ffuf ; cd ffuf ; go get ; go build

# Install SubFinder
sudo go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Impacket
python3 -m pipx install impacket

# Install Crowbar
sudo apt install -y crowbar

# Install neo4j
sudo apt install neo4j -y

# Install Bloodhound
pipx install bloodhound

# Install Bloodhound GUI
sudo apt install bloodhound

# Install DroopeScan
pipx install droopescan

# Install EyeWitness
sudo apt install eyewitness -y

# Install Impacket
pipx install impacket

# Install LibreOffice
sudo apt install libreoffice

# Install Tree
sudo apt install tree -y

# Install CUPP
sudo apt install cupp -y

# Install ExifTool
sudo apt install exiftool -y

# Install XSSTrike
cd ~/Documents/Ressources/2.Exploits/3.Web && git clone https://github.com/s0md3v/XSStrike.git && cd ~/Documents/Ressources/2.Exploits/3.Web/XSStrike && pip install -r requirements.txt

# Install SQLMap
sudo apt install sqlmap -y

# Install Redis
sudo apt install redis-tools -y

# Install WafWoof
sudo apt install wafw00f -y

# Install FinalRecon
cd ~/Documents/Ressources/1.Recon/3.Web/FinalRecon && pip install -r requirements.txt && chmod +x finalrecon.py

# Install WPScan
sudo gem install wpscan

# Install UploadServer
pipx install uploadserver

# Install FTPBench
pipx install pyftpdlib

# Install NFS-Common & RPCBind
sudo apt install rpcbind nfs-common -y

# Install FileZilla
sudo apt install filezilla -y

# Install Evil-WinRM
sudo apt install evil-winrm -y

# Install Responder
sudo apt install responder -y

# Install KubeletCTL
cd ~/Documents/Ressources/3.Privesc/2.Windows/KubeletCTL && chmod a+x ./kubeletctl_linux_amd64 && mv ./kubeletctl_linux_amd64 /usr/local/bin/kubeletctl

# Install Obsidian
cd ~/Desktop && wget https://github.com/obsidianmd/obsidian-releases/releases/download/v1.8.4/obsidian_1.8.4_amd64.deb && ./obsidian_1.8.4_amd64.deb

# Install Seclists
sudo apt install seclists -y

# Install FTP
sudo apt install ftp -y

# Install pipx
sudo apt install pipx -y

# Install Hash-Identifier
sudo apt install hash-identifier

# Install Proxychains-NG (Next Gen)
sudo apt install proxychains-ng

# Install Social-Engineer-Toolkit
sudo apt install set -y

# Install Python 2.7
cd /usr/src
sudo wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz
sudo tar xzf Python-2.7.18.tgz
cd Python-2.7.18
sudo ./configure --enable-optimizations
sudo make altinstall

# Install CTFR
cd ~/Documents/Ressources/1.Recon/ && git clone https://github.com/UnaPibaGeek/ctfr.git && cd ctfr && pip3 install -r requirements.txt

# Install hexedit
sudo apt install hexedit

# Install sherlock
pipx install sherlock-project





    

###### Mint Specific Installs and Downloads ######
# Careful! These Installs and Downloads are not yet tested...

# Install VirtualBox
sudo apt-get install virtualbox-7.1 -y

# Install Burp Suite
cd /opt && wget https://portswigger.net/burp/releases/download?product=community&version=2022.5.2&type=Linux && unzip 2022.5.2.zip && rm -rf 2022.5.2.zip

# Install Nmap
sudo apt install nmap -y

# Install Gobuster
sudo apt install gobuster


# Download Caido
cd ~/Documents/Ressources/4.SystemTools && mkdir Caido && cd Caido && wget https://caido.download/releases/v0.48.1/caido-desktop-v0.48.1-linux-x86_64.deb      

# Download Seclists
cd ~/Documents/Ressources/4.SystemTools && mkdir SecLists && cd SecLists && git clone https://github.com/danielmiessler/SecLists.git 








###### Tree Installs ######

cd ~/Documents/Ressources && tree -d -L 3

##### Update Repos #####

sudo apt update && sudo apt full-upgrade

###### Addtional Notes ######

RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "\n${RED}Remember to add the Cookie Editor Addon!!${NC}"
echo -e "URL: https://addons.mozilla.org/addon/cookie-editor?utm_campaign=external-github-readme\n"
echo -e "\n${RED}Remember to also add:${NC}\n-OnionShare\n-Wappalyzer\n-Update ZAP"


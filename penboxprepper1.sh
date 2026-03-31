#!/usr/bin/env bash
# =============================================================================
#  Pentest VM Setup Script
#  Tested on: Kali Linux / Parrot OS (Debian-based)
# =============================================================================

set -uo pipefail   # unset-variable & pipeline strictness (no -e: we handle errors manually)

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Logging helpers ───────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*" >&2; }

# =============================================================================
#  TRACKING – every task is registered before execution
# =============================================================================
declare -a TASK_NAMES=()     # human-readable label
declare -a TASK_STATUS=()    # "ok" | "skip" | "fail"
declare -A FAILED_LOGS=()    # idx -> log file path for failed tasks
TOTAL_TASKS=0
DONE_TASKS=0

register_task() {            # register_task <label>
    TASK_NAMES+=("$1")
    TASK_STATUS+=("pending")
    TOTAL_TASKS=$(( TOTAL_TASKS + 1 ))
}

# ── Progress bar ──────────────────────────────────────────────────────────────
_draw_progress() {           # _draw_progress <done> <total> <label> <status>
    local done=$1 total=$2 label="$3" status="$4"
    local width=42
    local filled=$(( done * width / total ))
    local empty=$(( width - filled ))
    local pct=$(( done * 100 / total ))

    # build bar string
    local bar_filled bar_empty
    bar_filled=$(printf '%0.s█' $(seq 1 $filled 2>/dev/null) 2>/dev/null || true)
    bar_empty=$(printf '%0.s░' $(seq 1 $empty 2>/dev/null) 2>/dev/null || true)

    local icon
    case "$status" in
        ok)   icon="${GREEN}✔${NC}" ;;
        skip) icon="${CYAN}↷${NC}" ;;
        fail) icon="${RED}✘${NC}" ;;
        *)    icon="${YELLOW}…${NC}" ;;
    esac

    # overwrite previous two lines after first draw
    [[ $done -gt 0 ]] && echo -ne "\033[2A\033[0J"

    echo -e "${GREEN}${bar_filled}${DIM}${bar_empty}${NC} ${BOLD}${pct}%${NC}  (${done}/${total})"
    printf "  %b  %-55s\n" "$icon" "$label"
}

_finish_task() {             # _finish_task <index> <ok|skip|fail>
    TASK_STATUS[$1]="$2"
    DONE_TASKS=$(( DONE_TASKS + 1 ))
    _draw_progress "$DONE_TASKS" "$TOTAL_TASKS" "${TASK_NAMES[$1]}" "$2"
}

# ── Generic task runner ───────────────────────────────────────────────────────
run_task() {                 # run_task <index> <label> <cmd> [args…]
    local idx=$1 label=$2
    shift 2
    local log_file
    log_file=$(mktemp /tmp/pts_XXXXXX.log)

    if "$@" >"$log_file" 2>&1; then
        _finish_task "$idx" "ok"
        rm -f "$log_file"
    else
        _finish_task "$idx" "fail"
        FAILED_LOGS[$idx]="$log_file"
    fi
}

# Like run_task but exit code 42 means "already present → skip"
run_task_s() {               # run_task_s <index> <label> <cmd> [args…]
    local idx=$1 label=$2
    shift 2
    local log_file
    log_file=$(mktemp /tmp/pts_XXXXXX.log)

    "$@" >"$log_file" 2>&1
    local ec=$?

    if   [[ $ec -eq 0  ]]; then _finish_task "$idx" "ok";   rm -f "$log_file"
    elif [[ $ec -eq 42 ]]; then _finish_task "$idx" "skip"; rm -f "$log_file"
    else                        _finish_task "$idx" "fail";  FAILED_LOGS[$idx]="$log_file"
    fi
}

# ── Helpers ───────────────────────────────────────────────────────────────────
git_clone() {                # git_clone <url> <dest>
    local url=$1 dest=$2
    [[ -d "$dest/.git" ]] && return 42
    git clone --depth=1 "$url" "$dest"
}

safe_wget() {                # safe_wget <url> <outfile>
    local url=$1 out=$2
    [[ -f "$out" ]] && return 42
    wget -q -O "$out" "$url"
}

apt_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
}

pipx_install() {
    sudo -u "$REAL_USER" pipx install "$@"
}

# ── Privilege check ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "Run this script as root (sudo $0)"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~${REAL_USER}")
BASE="${REAL_HOME}/Documents/Ressources"

# =============================================================================
#  TASK REGISTRATION  (sets TOTAL_TASKS — must all appear before any run_task)
# =============================================================================

# System
register_task "Create directory structure"               # 0
register_task "apt-get update"                           # 1
register_task "Install base apt packages"                # 2
register_task "Install / verify Go"                      # 3
register_task "pipx ensurepath"                          # 4
# Recon clones
register_task "Clone LinEnum"                            # 5
register_task "Clone username-anarchy"                   # 6
register_task "Clone enum4linux-ng"                      # 7
register_task "Clone smtp-user-enum"                     # 8
register_task "Clone LaZagne"                            # 9
register_task "Clone o365spray"                          # 10
register_task "Clone SharpView"                          # 11
register_task "Clone Sherlock"                           # 12
register_task "Clone Snaffler"                           # 13
register_task "Clone IIS-ShortName-Scanner"              # 14
register_task "Clone FinalRecon"                         # 15
register_task "Clone ffuf"                               # 16
register_task "Clone JoomScan"                           # 17
register_task "Clone DroopeScan"                         # 18
register_task "Clone windapsearch"                       # 19
register_task "Clone awesome-nmap-grep"                  # 20
# Exploit clones
register_task "Clone PayloadsAllTheThings"               # 21
register_task "Clone CrackMapExec"                       # 22
register_task "Clone dnscat2"                            # 23
register_task "Clone Invoke-TheHash"                     # 24
register_task "Clone impacket"                           # 25
register_task "Clone Rubeus"                             # 26
register_task "Clone Ghostpack CompiledBinaries"         # 27
register_task "Clone crowbar"                            # 28
register_task "Clone mRemoteNG-Decrypt"                  # 29
register_task "Clone SharpUp"                            # 30
register_task "Clone XSStrike"                           # 31
register_task "Clone Laudanum (Web-Shells)"              # 32
register_task "Clone Blackeye"                           # 33
register_task "Clone LFI-RCE-Cheat-Sheet"                # 34
register_task "Clone BloodHound.py"                      # 35
register_task "Clone SharpHound (BH Legacy)"             # 36
register_task "Clone DomainPasswordSpray"                # 37
register_task "Clone KeyTabExtract"                      # 38
register_task "Clone Responder-Windows"                  # 39
register_task "Clone kerbrute"                           # 40
# Privesc clones
register_task "Clone GTFOBins"                           # 41
register_task "Clone pypykatz"                           # 42
register_task "Clone mimikatz"                           # 43
register_task "Clone PEASS-ng"                           # 44
register_task "Clone PowerSploit"                        # 45
register_task "Clone LOLBAS"                             # 46
register_task "Clone PrintSpoofer"                       # 47
register_task "Clone UACME"                              # 48
# System-tool clones
register_task "Clone rpivot"                             # 49
register_task "Clone CredMaster"                         # 50
register_task "Clone statistically-likely-usernames"     # 51
register_task "Clone CTFR"                               # 52
register_task "Clone nc.exe"                             # 53
# Binary downloads
register_task "Download LaZagne.exe"                     # 54
register_task "Download ReconSpider"                     # 55
register_task "Download PEASS Metasploit module"         # 56
register_task "Download SysinternalsSuite"               # 57
register_task "Download JuicyPotato.exe"                 # 58
register_task "Download PrintSpoofer32.exe"              # 59
register_task "Download PrintSpoofer64.exe"              # 60
register_task "Download PowerUp.ps1"                     # 61
register_task "Download EnableAllTokenPrivs.ps1"         # 62
register_task "Download keepass2john.py"                 # 63
register_task "Download kubeletctl"                      # 64
register_task "Download Snaffler.exe"                    # 65
register_task "Download rpivot client.exe"               # 66
register_task "Download SocksOverRDP x64"                # 67
register_task "Download SocksOverRDP x86"                # 68
register_task "Download OCD AD mindmap"                  # 69
register_task "Download Caido .deb"                      # 70
register_task "Download Obsidian .deb"                   # 71
# Python / pipx
register_task "pipx: impacket"                           # 72
register_task "pipx: bloodhound"                         # 73
register_task "pipx: droopescan"                         # 74
register_task "pipx: uploadserver"                       # 75
register_task "pipx: pyftpdlib"                          # 76
register_task "pipx: sherlock-project"                   # 77
register_task "pipx: CrackMapExec"                       # 78
register_task "pip: FinalRecon requirements"             # 79
register_task "pip: XSStrike requirements"               # 80
register_task "pip: CTFR requirements"                   # 81
register_task "pip: scrapy (ReconSpider)"                # 82
register_task "venv: CredMaster"                         # 83
register_task "Build: dnscat2 client"                    # 84
register_task "Build: kerbrute"                          # 85
# Go / Ruby / Other
register_task "go install ffuf"                          # 86
register_task "go install subfinder"                     # 87
register_task "gem install wpscan"                       # 88
register_task "Install Chisel"                           # 89
register_task "Extract rockyou.txt"                      # 90
register_task "Install Obsidian"                         # 91
register_task "Install kubeletctl (system)"              # 92
register_task "Fix permissions"                          # 93
# Mint-specific / extras
register_task "Install VirtualBox 7.1"                   # 94
register_task "Download & install Burp Suite Community"  # 95
register_task "Compile Python 2.7 from source"          # 96
register_task "Download Proxifier"                       # 97
register_task "Clone SecLists to Ressources"             # 98

# =============================================================================
#  KICK OFF
# =============================================================================
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗"
printf  "║       Pentest VM Setup  –  %d tasks to run          ║\n" "$TOTAL_TASKS"
echo -e "╚══════════════════════════════════════════════════════╝${NC}"
echo ""
# Prime display (two blank lines the cursor-up will overwrite)
printf '\n\n'
_draw_progress 0 "$TOTAL_TASKS" "Initialising …" "pending"

# =============================================================================
#  1. DIRECTORIES & SYSTEM UPDATE
# =============================================================================
run_task 0 "Create directory structure" bash -c "
    for d in \
        \"$BASE/1.Recon/1.Linux\" \
        \"$BASE/1.Recon/2.Windows\" \
        \"$BASE/1.Recon/3.Web\" \
        \"$BASE/1.Recon/4.Active Directory\" \
        \"$BASE/2.Exploits/0.Overview\" \
        \"$BASE/2.Exploits/1.Linux\" \
        \"$BASE/2.Exploits/2.Windows\" \
        \"$BASE/2.Exploits/3.Web\" \
        \"$BASE/2.Exploits/4.Active Directory\" \
        \"$BASE/3.Privesc/1.Linux\" \
        \"$BASE/3.Privesc/2.Windows\" \
        \"$BASE/3.Privesc/3.Web\" \
        \"$BASE/4.SystemTools/1.Linux\" \
        \"$BASE/4.SystemTools/2.Windows/Sysinternals\" \
        \"$BASE/4.SystemTools/2.Windows/Netcat\" \
        \"$BASE/4.SystemTools/3.Web\" \
        \"$BASE/4.SystemTools/4.Pivoting/SocksOverRDP\" \
        \"$BASE/4.SystemTools/5.Phishing\" \
        \"$BASE/4.SystemTools/Caido\" \
        \"$BASE/4.SystemTools/keepass2john\" \
        \"$BASE/3.Privesc/2.Windows/JuicyPotato\" \
        \"$BASE/3.Privesc/2.Windows/PowerUp\" \
        \"$BASE/3.Privesc/2.Windows/EnableAllTokenPrivs\" \
        \"$BASE/3.Privesc/2.Windows/KubeletCTL\" \
        \"${REAL_HOME}/Desktop\"
    do mkdir -p \"\$d\"; done
    chown -R ${REAL_USER}:${REAL_USER} \"$BASE\"
"

run_task 1 "apt-get update" apt-get update -qq

run_task 2 "Install base apt packages" bash -c "
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        git wget curl unzip tar build-essential \
        python3 python3-pip python3-venv pipx golang-go ruby ruby-dev \
        nmap gobuster sqlmap wafw00f eyewitness responder evil-winrm netexec \
        crowbar neo4j bloodhound seclists cupp exiftool \
        rpcbind nfs-common filezilla ftp redis-tools libreoffice tree \
        hash-identifier proxychains-ng hexedit python3-ldap \
        set
"

run_task 3 "Install / verify Go" bash -c "
    command -v go &>/dev/null || snap install go --classic
"

run_task 4 "pipx ensurepath" sudo -u "$REAL_USER" pipx ensurepath

# =============================================================================
#  3. REPOSITORY CLONES
# =============================================================================

# Recon / Linux
run_task_s  5 "Clone LinEnum"            git_clone https://github.com/rebootuser/LinEnum.git              "$BASE/1.Recon/1.Linux/LinEnum"
run_task_s  6 "Clone username-anarchy"   git_clone https://github.com/urbanadventurer/username-anarchy.git "$BASE/1.Recon/1.Linux/username-anarchy"
run_task_s  7 "Clone enum4linux-ng"      git_clone https://github.com/cddmp/enum4linux-ng.git             "$BASE/1.Recon/1.Linux/enum4linux-ng"
# Recon / Windows
run_task_s  8 "Clone smtp-user-enum"     git_clone https://github.com/pentestmonkey/smtp-user-enum.git    "$BASE/1.Recon/2.Windows/smtp-user-enum"
run_task_s  9 "Clone LaZagne"            git_clone https://github.com/AlessandroZ/LaZagne.git              "$BASE/1.Recon/2.Windows/LaZagne"
run_task_s 10 "Clone o365spray"          git_clone https://github.com/0xZDH/o365spray.git                 "$BASE/1.Recon/2.Windows/o365spray"
run_task_s 11 "Clone SharpView"          git_clone https://github.com/dmchell/SharpView.git               "$BASE/1.Recon/2.Windows/SharpView"
run_task_s 12 "Clone Sherlock"           git_clone https://github.com/rasta-mouse/Sherlock.git            "$BASE/1.Recon/2.Windows/Sherlock"
run_task_s 13 "Clone Snaffler"           git_clone https://github.com/SnaffCon/Snaffler.git               "$BASE/1.Recon/2.Windows/Snaffler"
run_task_s 14 "Clone IIS-ShortName-Scanner" git_clone https://github.com/irsdl/IIS-ShortName-Scanner.git "$BASE/1.Recon/2.Windows/IIS-ShortName-Scanner"
# Recon / Web
run_task_s 15 "Clone FinalRecon"         git_clone https://github.com/thewhiteh4t/FinalRecon.git          "$BASE/1.Recon/3.Web/FinalRecon"
run_task_s 16 "Clone ffuf"               git_clone https://github.com/ffuf/ffuf.git                       "$BASE/1.Recon/3.Web/ffuf"
run_task_s 17 "Clone JoomScan"           git_clone https://github.com/rezasp/joomscan.git                 "$BASE/1.Recon/3.Web/joomscan"
run_task_s 18 "Clone DroopeScan"         git_clone https://github.com/droope/droopescan.git               "$BASE/1.Recon/3.Web/droopescan"
# Recon / AD
run_task_s 19 "Clone windapsearch"       git_clone https://github.com/ropnop/windapsearch.git             "$BASE/1.Recon/4.Active Directory/windapsearch"
run_task_s 20 "Clone awesome-nmap-grep"  git_clone https://github.com/leonjza/awesome-nmap-grep.git       "$BASE/1.Recon/awesome-nmap-grep"
ln -sf "$BASE/1.Recon/4.Active Directory/windapsearch/windapsearch.py" /usr/local/bin/windapsearch.py 2>/dev/null || true
# Exploits
run_task_s 21 "Clone PayloadsAllTheThings"       git_clone https://github.com/swisskyrepo/PayloadsAllTheThings.git          "$BASE/2.Exploits/0.Overview/PayloadsAllTheThings"
run_task_s 22 "Clone CrackMapExec"               git_clone https://github.com/byt3bl33d3r/CrackMapExec.git                  "$BASE/2.Exploits/2.Windows/CrackMapExec"
run_task_s 23 "Clone dnscat2"                    git_clone https://github.com/iagox86/dnscat2.git                           "$BASE/2.Exploits/2.Windows/dnscat2"
run_task_s 24 "Clone Invoke-TheHash"             git_clone https://github.com/Kevin-Robertson/Invoke-TheHash.git            "$BASE/2.Exploits/2.Windows/Invoke-TheHash"
run_task_s 25 "Clone impacket"                   git_clone https://github.com/fortra/impacket.git                           "$BASE/2.Exploits/2.Windows/impacket"
run_task_s 26 "Clone Rubeus"                     git_clone https://github.com/GhostPack/Rubeus.git                          "$BASE/2.Exploits/2.Windows/Rubeus"
run_task_s 27 "Clone Ghostpack CompiledBinaries" git_clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git  "$BASE/2.Exploits/2.Windows/Rubeus/CompiledBinaries"
run_task_s 28 "Clone crowbar"                    git_clone https://github.com/galkan/crowbar.git                            "$BASE/2.Exploits/2.Windows/crowbar"
run_task_s 29 "Clone mRemoteNG-Decrypt"          git_clone https://github.com/haseebT/mRemoteNG-Decrypt.git                 "$BASE/2.Exploits/2.Windows/mRemoteNG-Decrypt"
run_task_s 30 "Clone SharpUp"                    git_clone https://github.com/GhostPack/SharpUp.git                         "$BASE/2.Exploits/2.Windows/SharpUp"
run_task_s 31 "Clone XSStrike"                   git_clone https://github.com/s0md3v/XSStrike.git                           "$BASE/2.Exploits/3.Web/XSStrike"
run_task_s 32 "Clone Laudanum (Web-Shells)"      git_clone https://github.com/jbarcia/Web-Shells.git                        "$BASE/2.Exploits/3.Web/Laudanum"
run_task_s 33 "Clone Blackeye"                   git_clone https://github.com/shuvo-halder/blackeye.git                     "$BASE/2.Exploits/3.Web/blackeye"
run_task_s 34 "Clone LFI-RCE-Cheat-Sheet"        git_clone https://github.com/RoqueNight/LFI---RCE-Cheat-Sheet.git          "$BASE/2.Exploits/3.Web/LFI-RCE-Cheat-Sheet"
run_task_s 35 "Clone BloodHound.py"              git_clone https://github.com/dirkjanm/BloodHound.py.git                    "$BASE/2.Exploits/4.Active Directory/BloodHound.py"
run_task_s 36 "Clone SharpHound (BH Legacy)"     git_clone https://github.com/SpecterOps/BloodHound-Legacy.git              "$BASE/2.Exploits/4.Active Directory/SharpHound"
run_task_s 37 "Clone DomainPasswordSpray"        git_clone https://github.com/dafthack/DomainPasswordSpray.git              "$BASE/2.Exploits/4.Active Directory/DomainPasswordSpray"
run_task_s 38 "Clone KeyTabExtract"              git_clone https://github.com/sosdave/KeyTabExtract.git                     "$BASE/2.Exploits/4.Active Directory/KeyTabExtract"
run_task_s 39 "Clone Responder-Windows"          git_clone https://github.com/lgandx/Responder-Windows.git                  "$BASE/2.Exploits/4.Active Directory/Responder-Windows"
run_task_s 40 "Clone kerbrute"                   git_clone https://github.com/ropnop/kerbrute.git                           "$BASE/2.Exploits/4.Active Directory/kerbrute"
# Privesc
run_task_s 41 "Clone GTFOBins"    git_clone https://github.com/GTFOBins/GTFOBins.github.io.git                "$BASE/3.Privesc/1.Linux/GTFOBins"
run_task_s 42 "Clone pypykatz"    git_clone https://github.com/skelsec/pypykatz.git                           "$BASE/3.Privesc/2.Windows/pypykatz"
run_task_s 43 "Clone mimikatz"    git_clone https://github.com/ParrotSec/mimikatz.git                         "$BASE/3.Privesc/2.Windows/mimikatz"
run_task_s 44 "Clone PEASS-ng"    git_clone https://github.com/peass-ng/PEASS-ng.git                          "$BASE/3.Privesc/2.Windows/PEASS-ng"
run_task_s 45 "Clone PowerSploit" git_clone https://github.com/PowerShellMafia/PowerSploit.git                "$BASE/3.Privesc/2.Windows/PowerSploit"
run_task_s 46 "Clone LOLBAS"      git_clone https://github.com/LOLBAS-Project/LOLBAS-Project.github.io.git   "$BASE/3.Privesc/2.Windows/LOLBAS"
run_task_s 47 "Clone PrintSpoofer" git_clone https://github.com/itm4n/PrintSpoofer.git                        "$BASE/3.Privesc/2.Windows/PrintSpoofer"
run_task_s 48 "Clone UACME"       git_clone https://github.com/hfiref0x/UACME.git                             "$BASE/3.Privesc/2.Windows/UACME"
# System Tools
run_task_s 49 "Clone rpivot"                      git_clone https://github.com/klsecservices/rpivot.git                  "$BASE/4.SystemTools/4.Pivoting/rpivot"
run_task_s 50 "Clone CredMaster"                  git_clone https://github.com/knavesec/CredMaster.git                  "$BASE/4.SystemTools/5.Phishing/CredMaster"
run_task_s 51 "Clone statistically-likely-usernames" git_clone https://github.com/insidetrust/statistically-likely-usernames.git /usr/share/wordlists/statistically-likely-usernames
run_task_s 52 "Clone CTFR"                        git_clone https://github.com/UnaPibaGeek/ctfr.git                     "$BASE/1.Recon/ctfr"
run_task_s 53 "Clone nc.exe"                      git_clone https://github.com/int0x33/nc.exe.git                       "$BASE/4.SystemTools/2.Windows/Netcat/nc.exe"

# =============================================================================
#  4. BINARY DOWNLOADS
# =============================================================================
run_task_s 54 "Download LaZagne.exe"             safe_wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe                                                                 "$BASE/1.Recon/2.Windows/LaZagne/Standalone/LaZagne.exe"
run_task_s 55 "Download ReconSpider"             bash -c "[[ -f \"$BASE/1.Recon/3.Web/ReconSpider.zip\" ]] && exit 42; wget -q -O \"$BASE/1.Recon/3.Web/ReconSpider.zip\" 'https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip' && unzip -qo \"$BASE/1.Recon/3.Web/ReconSpider.zip\" -d \"$BASE/1.Recon/3.Web/\""
run_task_s 56 "Download PEASS Metasploit module" safe_wget https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/metasploit/peass.rb                                                               /usr/share/metasploit-framework/modules/post/multi/gather/peass.rb
run_task_s 57 "Download SysinternalsSuite"       bash -c "[[ -f \"$BASE/4.SystemTools/2.Windows/Sysinternals/procexp.exe\" ]] && exit 42; wget -q -O \"$BASE/4.SystemTools/2.Windows/Sysinternals/suite.zip\" https://download.sysinternals.com/files/SysinternalsSuite.zip && unzip -qo \"$BASE/4.SystemTools/2.Windows/Sysinternals/suite.zip\" -d \"$BASE/4.SystemTools/2.Windows/Sysinternals/\" && rm -f \"$BASE/4.SystemTools/2.Windows/Sysinternals/suite.zip\""
run_task_s 58 "Download JuicyPotato.exe"         safe_wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe                                                                 "$BASE/3.Privesc/2.Windows/JuicyPotato/JuicyPotato.exe"
run_task_s 59 "Download PrintSpoofer32.exe"      safe_wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe                                                             "$BASE/3.Privesc/2.Windows/PrintSpoofer/PrintSpoofer32.exe"
run_task_s 60 "Download PrintSpoofer64.exe"      safe_wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe                                                             "$BASE/3.Privesc/2.Windows/PrintSpoofer/PrintSpoofer64.exe"
run_task_s 61 "Download PowerUp.ps1"             safe_wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1                                                    "$BASE/3.Privesc/2.Windows/PowerUp/PowerUp.ps1"
run_task_s 62 "Download EnableAllTokenPrivs.ps1" safe_wget https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1                                           "$BASE/3.Privesc/2.Windows/EnableAllTokenPrivs/EnableAllTokenPrivs.ps1"
run_task_s 63 "Download keepass2john.py"         safe_wget "https://gist.githubusercontent.com/HarmJ0y/116fa1b559372804877e604d7d367bbc/raw/c0c6f45ad89310e61ec0363a69913e966fe17633/keepass2john.py" "$BASE/4.SystemTools/keepass2john/keepass2john.py"
run_task_s 64 "Download kubeletctl"              safe_wget https://github.com/cyberark/kubeletctl/releases/download/v1.12/kubeletctl_linux_amd64                                                        "$BASE/3.Privesc/2.Windows/KubeletCTL/kubeletctl_linux_amd64"
run_task_s 65 "Download Snaffler.exe"            safe_wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.184/Snaffler.exe                                                                 "$BASE/1.Recon/2.Windows/Snaffler/Snaffler.exe"
run_task_s 66 "Download rpivot client.exe"       safe_wget https://github.com/klsecservices/rpivot/releases/download/v1.0/client.exe                                                                   "$BASE/4.SystemTools/4.Pivoting/rpivot/client.exe"
run_task_s 67 "Download SocksOverRDP x64"        safe_wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip                                                        "$BASE/4.SystemTools/4.Pivoting/SocksOverRDP/SocksOverRDP-x64.zip"
run_task_s 68 "Download SocksOverRDP x86"        safe_wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x86.zip                                                        "$BASE/4.SystemTools/4.Pivoting/SocksOverRDP/SocksOverRDP-x86.zip"
run_task_s 69 "Download OCD AD mindmap"          safe_wget https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg                                                          "$BASE/1.Recon/4.Active Directory/pentest_ad_mindmap.svg"
run_task_s 70 "Download Caido .deb"              safe_wget https://caido.download/releases/v0.48.1/caido-desktop-v0.48.1-linux-x86_64.deb                                                              "$BASE/4.SystemTools/Caido/caido-desktop.deb"
run_task_s 71 "Download Obsidian .deb"           safe_wget https://github.com/obsidianmd/obsidian-releases/releases/download/v1.8.4/obsidian_1.8.4_amd64.deb                                          "${REAL_HOME}/Desktop/obsidian_1.8.4_amd64.deb"

# =============================================================================
#  5. PYTHON / PIPX
# =============================================================================
run_task 72 "pipx: impacket"         pipx_install impacket
run_task 73 "pipx: bloodhound"       pipx_install bloodhound
run_task 74 "pipx: droopescan"       pipx_install droopescan
run_task 75 "pipx: uploadserver"     pipx_install uploadserver
run_task 76 "pipx: pyftpdlib"        pipx_install pyftpdlib
run_task 77 "pipx: sherlock-project" pipx_install sherlock-project
run_task 78 "pipx: CrackMapExec"     pipx_install "git+https://github.com/byt3bl33d3r/CrackMapExec"

_pip_req() {
    local req="$1/requirements.txt"
    [[ -f "$req" ]] || return 0
    sudo -u "$REAL_USER" pip3 install -q --user -r "$req"
}
run_task 79 "pip: FinalRecon requirements" _pip_req "$BASE/1.Recon/3.Web/FinalRecon"
run_task 80 "pip: XSStrike requirements"   _pip_req "$BASE/2.Exploits/3.Web/XSStrike"
run_task 81 "pip: CTFR requirements"       _pip_req "$BASE/1.Recon/ctfr"
run_task 82 "pip: scrapy"                  sudo -u "$REAL_USER" pip3 install -q --user scrapy

[[ -f "$BASE/1.Recon/3.Web/FinalRecon/finalrecon.py" ]] && chmod +x "$BASE/1.Recon/3.Web/FinalRecon/finalrecon.py" 2>/dev/null || true

run_task 83 "venv: CredMaster" bash -c "
    d=\"$BASE/4.SystemTools/5.Phishing/CredMaster\"
    [[ -f \"\$d/requirements.txt\" ]] || exit 0
    sudo -u \"$REAL_USER\" python3 -m venv \"\$d/venv\"
    sudo -u \"$REAL_USER\" \"\$d/venv/bin/pip\" install -q -r \"\$d/requirements.txt\"
"
run_task 84 "Build: dnscat2 client" bash -c "
    cd \"$BASE/2.Exploits/2.Windows/dnscat2/client\" && make
"
run_task 85 "Build: kerbrute" bash -c "
    [[ -d \"$BASE/2.Exploits/4.Active Directory/kerbrute\" ]] || exit 0
    cd \"$BASE/2.Exploits/4.Active Directory/kerbrute\" && make all
"

# =============================================================================
#  6. GO TOOLS
# =============================================================================
export GOPATH="/usr/local/go_tools"
export PATH="$PATH:$GOPATH/bin"

run_task 86 "go install ffuf"      go install github.com/ffuf/ffuf/v2@latest
run_task 87 "go install subfinder" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# =============================================================================
#  7. RUBY / OTHER
# =============================================================================
run_task 88 "gem install wpscan" gem install wpscan --quiet

run_task 89 "Install Chisel" bash -c "curl -fsSL https://i.jpillora.com/chisel! | bash"

run_task_s 90 "Extract rockyou.txt" bash -c "
    src='/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz'
    dst='/usr/share/wordlists/rockyou.txt'
    [[ -f \"\$dst\" ]] && exit 42
    [[ -f \"\$src\" ]] || exit 1
    tar -xzf \"\$src\" -C /usr/share/wordlists/
"

run_task 91 "Install Obsidian" bash -c "
    deb=\"${REAL_HOME}/Desktop/obsidian_1.8.4_amd64.deb\"
    [[ -f \"\$deb\" ]] && dpkg -i \"\$deb\" || apt-get install -f -y -qq
"

run_task 92 "Install kubeletctl (system)" bash -c "
    bin=\"$BASE/3.Privesc/2.Windows/KubeletCTL/kubeletctl_linux_amd64\"
    [[ -f \"\$bin\" ]] || exit 1
    chmod a+x \"\$bin\"
    ln -sf \"\$bin\" /usr/local/bin/kubeletctl
"

run_task 93 "Fix permissions" chown -R "${REAL_USER}:${REAL_USER}" "$BASE"

# =============================================================================
#  8. MINT-SPECIFIC / EXTRAS
#  (marked with a note in the original – install at own discretion)
# =============================================================================

run_task 94 "Install VirtualBox 7.1" \
    apt_install virtualbox-7.1

run_task 95 "Download & install Burp Suite Community" bash -c "
    dest=\"/opt/burpsuite_community.sh\"
    [[ -f \"\$dest\" ]] && exit 0
    wget -q -O \"\$dest\" \
        'https://portswigger.net/burp/releases/download?product=community&type=Linux'
    chmod +x \"\$dest\"
    # Silent headless install
    \"\$dest\" -q
"

run_task 96 "Compile Python 2.7 from source" bash -c "
    command -v python2.7 &>/dev/null && exit 0
    cd /usr/src
    wget -q https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz
    tar xzf Python-2.7.18.tgz
    cd Python-2.7.18
    ./configure --enable-optimizations -q
    make altinstall -j\$(nproc)
"

run_task_s 97 "Download Proxifier" bash -c "
    dest=\"$BASE/4.SystemTools/4.Pivoting/Proxifier\"
    mkdir -p \"\$dest\"
    out=\"\$dest/ProxifierPE.zip\"
    [[ -f \"\$out\" ]] && exit 42
    wget -q -O \"\$out\" https://www.proxifier.com/download/ProxifierPE.zip
"

run_task_s 98 "Clone SecLists to Ressources" bash -c "
    dest=\"$BASE/4.SystemTools/SecLists\"
    mkdir -p \"\$dest\"
    [[ -d \"\$dest/.git\" ]] && exit 42
    git clone --depth=1 https://github.com/danielmiessler/SecLists.git \"\$dest\"
"

# =============================================================================
#  FINAL SUMMARY
# =============================================================================
echo ""
echo ""

COUNT_OK=0; COUNT_SKIP=0; COUNT_FAIL=0
for s in "${TASK_STATUS[@]}"; do
    case "$s" in
        ok)   (( COUNT_OK   += 1 )) ;;
        skip) (( COUNT_SKIP += 1 )) ;;
        fail) (( COUNT_FAIL += 1 )) ;;
    esac
done

echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗"
echo -e "║                   SETUP SUMMARY                     ║"
echo -e "╚══════════════════════════════════════════════════════╝${NC}"
printf "  ${GREEN}✔  Succeeded : %d${NC}\n"  "$COUNT_OK"
printf "  ${CYAN}↷  Skipped   : %d${NC}  (already present)\n" "$COUNT_SKIP"
printf "  ${RED}✘  Failed    : %d${NC}\n"  "$COUNT_FAIL"
echo ""

if [[ $COUNT_FAIL -gt 0 ]]; then
    echo -e "${BOLD}${RED}── Failed Tasks ─────────────────────────────────────────${NC}"
    for idx in "${!TASK_STATUS[@]}"; do
        if [[ "${TASK_STATUS[$idx]}" == "fail" ]]; then
            printf "  ${RED}✘${NC}  %s\n" "${TASK_NAMES[$idx]}"
            local_log="${FAILED_LOGS[$idx]:-}"
            if [[ -n "$local_log" && -f "$local_log" ]]; then
                echo -e "${DIM}     ── last 5 lines of output ──────────────────────────"
                tail -5 "$local_log" | sed 's/^/     /'
                echo -e "${NC}"
                rm -f "$local_log"
            fi
        fi
    done
    echo ""
fi

if [[ $COUNT_SKIP -gt 0 ]]; then
    echo -e "${BOLD}${CYAN}── Skipped (already installed) ──────────────────────────${NC}"
    for idx in "${!TASK_STATUS[@]}"; do
        [[ "${TASK_STATUS[$idx]}" == "skip" ]] && \
            printf "  ${CYAN}↷${NC}  %s\n" "${TASK_NAMES[$idx]}"
    done
    echo ""
fi

echo -e "${BOLD}── Directory Overview ───────────────────────────────────${NC}"
tree -d -L 3 "$BASE" 2>/dev/null || find "$BASE" -maxdepth 3 -type d
echo ""

echo -e "${BOLD}${RED}── Post-Setup Reminders ─────────────────────────────────${NC}"
echo -e "${YELLOW}Browser extensions (install manually):${NC}"
echo -e "  • Cookie Editor  → https://addons.mozilla.org/addon/cookie-editor"
echo -e "  • Wappalyzer     → https://www.wappalyzer.com"
echo -e "\n${YELLOW}Tools requiring manual steps:${NC}"
echo -e "  • OnionShare   – install via Tor Project PPA"
echo -e "  • OWASP ZAP    – update via GUI after launch"
echo -e "  • Obsidian     – .deb saved to ~/Desktop"
echo -e "  • Caido        – .deb saved to $BASE/4.SystemTools/Caido/"
echo -e "  • Proxifier    – commercial licence required"
echo ""

if [[ $COUNT_FAIL -eq 0 ]]; then
    success "All tasks completed! Log out and back in so pipx PATH changes take effect."
else
    warn "${COUNT_FAIL} task(s) failed – see details above. Re-run to retry."
fi

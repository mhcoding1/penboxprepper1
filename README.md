
# Pentesting VM Setup Script

This script automates the installation and configuration of various tools and utilities commonly used in my penetration testing. 

## Features

* **Creates necessary directories:**
	* Organizes tools and resources into well-defined folders for better management
* **Downloads and Installs:** 
    * Popular penetration testing tools like ffuf, XSStrike, Enum4Linux, ... 
    * Privilege escalation tools like WinPEAS, LinPEAS, and PowerSploit, ...
    * Various other utilities like exiftool, nc.exe, keepass2john, ... 
* **Installs essential packages:**
	* Installs required dependencies and packages for the smooth functioning of several tools

## Usage

1. Clone this repo:
~~~bash
git clone https://github.com/mhcoding1/pwnboxprepper1
~~~
2. Navigate to the script:
~~~bash
cd pwnboxprepper1
~~~
3. Change its perissions:
~~~bash
chmod +x pwnboxprepper1.sh
~~~
4. Run the script:
~~~bash
./pwnboxprepper1.sh
~~~

## Note

- This script may require root privileges for some installations.
- The script assumes a Debian/Ubuntu-based Linux distribution.
- Some tools may require additional configuration or dependencies.
- This script is provided as-is and without any warranty. Use it responsibly and ethically.

## Disclaimer

This script is for educational and research purposes only. Use it responsibly and ethically. Unauthorized access to computer systems is illegal and may have serious consequences.
This Readme provides a basic overview. Please refer to the individual tool documentation for specific usage instructions and legal considerations.
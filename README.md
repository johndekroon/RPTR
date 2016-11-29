# RPTR framework
The RPTR framework is used to automate penetration testing. The goal is to cherry-pick frequently discovered findings.

#Usage
That's simple! Just `python rptr.py [TARGET]`

More advanced usage:
```
-b [file] Select specific bullet file (must be in bullets dir)
-r [id] Get results from a scan by ID
--list-tests [TARGET] Get all scans by target. Target can be a domain name or a IP address.
```

#Installation
##Packages
First: install Packages
```
pip install sslyze
pip install pythonwhois
pip install lxml
(for Ubuntu you can do: apt-get install python-lxml)

apt-get install nmap
```
CD to plugins
`git clone https://github.com/drwetter/testssl.sh.git`

Nikto is in this repo because we use an alternative scan database

##Database
Just deploy RPTR_DB.sql

##Configuration
Edit conf.py
 - Set DB credentials and DB (currently only localhost is supported as database)
To check if a target is marked as malicious by VirusTotal, supply your API key in `plugins/domaincheck.py`

#License
RPTR is supplied with a "do whatever you want with it, but don't hold us liable"-license. To be more specific, see the LICENSE file.  
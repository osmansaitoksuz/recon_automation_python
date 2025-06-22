Recon Automation Python

Required Tools(Must be added to PATH):

*subfinder

*assetfinder

*amass

*httpx(it defined as "gohttpx" in go directory. Because there is another package named httpx which a Python library.)

*nmap

*gobuster

*aquatone or wkhtmltoimage

*whatweb



Python libraries:

*requests


A wordlist must.

default wordlist: /usr/share/wordlists/dirb/common.txt

if not downloaded;

  "sudo apt install wordlists"

-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*

./recon.py -h                                                                 
usage: newrecon.py [-h] [-d DOMAIN] [-l LIST] [-o OUTPUT] [--threads THREADS] [--wordlist WORDLIST] [--subdomain] [--live] [--ports] [--dirs] [--screenshots] [--tech]
                   [--all]

Modüler Recon Aracı

options:
  -h, --help           show this help message and exit
  
  -d, --domain DOMAIN  Hedef domain
  
  -l, --list LIST      Domain listesi içeren dosya (her satırda bir domain)
  
  -o, --output OUTPUT  Çıktı dizini
  
  --threads THREADS    Thread sayısı (varsayılan: 50)
  
  --wordlist WORDLIST  Directory brute-force için wordlist yolu
  
  --subdomain          Sadece subdomain enumeration
  
  --live               Sadece live host detection
  
  --ports              Sadece port scanning
  
  --dirs               Sadece directory bruteforce
  
  --screenshots        Sadece screenshot alma
  
  --tech               Sadece teknoloji tespiti
  
  --all                Tüm aşamaları çalıştır

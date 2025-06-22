#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import subprocess
import requests
import threading
import time
import os
import re
import warnings
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import sys
import shutil

# SSL uyarılarını kapat
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
requests.packages.urllib3.disable_warnings()

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class ReconTool:
    def __init__(self, domain, output_dir="recon_results", threads=50, wordlist=None):
        self.threads = threads
        self.domain = domain
        self.output_dir = output_dir
        self.subdomains_file = f"{output_dir}/subdomains.txt"
        self.live_hosts_file = f"{output_dir}/live_hosts.txt"
        self.ports_file = f"{output_dir}/open_ports.txt"
        self.directories_file = f"{output_dir}/directories.txt"
        self.screenshots_dir = f"{output_dir}/screenshots"
        self.nmap_dir = f"{output_dir}/nmap_scans"
        self.wordlist = wordlist or '/usr/share/wordlists/dirb/common.txt'
        self.log_file = os.path.join(self.output_dir, 'recon.log')

        # Output dizinini oluştur
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(self.screenshots_dir, exist_ok=True)
        os.makedirs(self.nmap_dir, exist_ok=True)
        
        with open(self.log_file, 'w') as f:
            f.write(f"[+] Recon başlatıldı: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")



    def log(self, message, color=Colors.WHITE):
        timestamp = time.strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        # Ekrana renkli yaz
        print(f"{Colors.BLUE}[{timestamp}]{Colors.END} {color}{message}{Colors.END}")
        
        # Log dosyasına renksiz yaz
        with open(self.log_file, 'a') as f:
            f.write(formatted_message + "\n")

    
    def clean_domain(self, domain_line):
        """Domain satırından temiz domain çıkar"""
        domain_line = domain_line.strip()
        
        if domain_line.startswith(('http://', 'https://')):
            parsed = urlparse(domain_line)
            domain = parsed.hostname or domain_line
        else:
            domain = domain_line
        
        if ':' in domain and not domain.count(':') > 1:
            domain = domain.split(':')[0]
        
        domain = re.sub(r'\s*[\[\(]\d+[\]\)].*$', '', domain)
        domain = re.sub(r'\s+\d+\s*$', '', domain)
        domain = re.sub(r'\s+.*$', '', domain)
        domain = re.sub(r'[^\w\.\-]', '', domain)
        
        return domain.lower().strip()
    
    def subdomain_enumeration(self):
        """1. Aşama: Subdomain Enumeration"""
        self.log("Subdomain enumeration başlatılıyor...", Colors.GREEN)
        
        all_subdomains = set()
        
        # Subfinder
        self.log("Subfinder çalıştırılıyor...")
        try:
            result = subprocess.run(['subfinder', '-d', self.domain, '-silent'], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        clean_sub = self.clean_domain(line)
                        if clean_sub and clean_sub.endswith(self.domain):
                            all_subdomains.add(clean_sub)
                self.log(f"Subfinder: {len(result.stdout.strip().split())} subdomain bulundu")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.log("Subfinder bulunamadı veya timeout", Colors.YELLOW)
        
        # Assetfinder
        self.log("Assetfinder çalıştırılıyor...")
        try:
            result = subprocess.run(['assetfinder', self.domain], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        clean_sub = self.clean_domain(line)
                        if clean_sub and clean_sub.endswith(self.domain):
                            all_subdomains.add(clean_sub)
                self.log(f"Assetfinder: yeni subdomainler eklendi")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.log("Assetfinder bulunamadı veya timeout", Colors.YELLOW)
        
       # Amass

        self.log("Amass çalıştırılıyor...")
        try:
            result = subprocess.run(['amass', 'enum', '-d', self.domain, '-passive'], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        clean_sub = self.clean_domain(line)
                        if clean_sub and clean_sub.endswith(self.domain):
                            all_subdomains.add(clean_sub)
                self.log(f"Amass: yeni subdomainler eklendi")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.log("Amass bulunamadı veya timeout", Colors.YELLOW)

        
        # crt.sh API
        self.log("crt.sh sorgulanıyor...")
        try:
            response = requests.get(f'https://crt.sh/?q=%.{self.domain}&output=json', 
                                  timeout=30, verify=False)
            if response.status_code in [200, 301, 302, 403, 401]:
                data = response.json()
                for cert in data:
                    name = cert.get('name_value', '')
                    for subdomain in name.split('\n'):
                        clean_sub = self.clean_domain(subdomain)
                        if clean_sub and clean_sub.endswith(self.domain) and '*' not in clean_sub:
                            all_subdomains.add(clean_sub)
                self.log(f"crt.sh: yeni subdomainler eklendi")
        except Exception as e:
            self.log(f"crt.sh hatası: {str(e)}", Colors.YELLOW)
        
        # Sonuçları dosyaya yaz
        if all_subdomains:
            with open(self.subdomains_file, 'w') as f:
                for subdomain in sorted(all_subdomains):
                    f.write(f"{subdomain}\n")
            
            self.log(f"Toplam {len(all_subdomains)} benzersiz subdomain bulundu", Colors.GREEN)
            self.log(f"Sonuçlar kaydedildi: {self.subdomains_file}", Colors.GREEN)
        else:
            self.log("Hiç subdomain bulunamadı", Colors.RED)
        
        return list(all_subdomains)
    
    def live_host_detection(self, subdomains_list=None):
        """2. Aşama: Live Host Detection - httpx ile"""
        self.log("Live host kontrolü httpx ile başlatılıyor...", Colors.GREEN)

        if subdomains_list is None:
            if not os.path.exists(self.subdomains_file):
                self.log("Subdomain dosyası bulunamadı! Önce subdomain enumeration yapın.", Colors.RED)
                return []

            with open(self.subdomains_file, 'r') as f:
                subdomains_list = [line.strip() for line in f if line.strip()]

        temp_input = f"/tmp/httpx_input_{int(time.time())}.txt"
        with open(temp_input, 'w') as f:
            for sub in subdomains_list:
                f.write(sub + "\n")

        try:
            result = subprocess.run([
                'gohttpx',
                '-silent',
                '-timeout', '5',
                '-threads', str(self.threads),
                '-no-color',
                '-status-code',
                '-title',
                '-tech-detect',
                '-json'
            ],
            stdin=open(temp_input, 'r'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600)

            os.remove(temp_input)

            live_hosts = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        if 'url' in data:
                            live_hosts.append(data['url'])
                            self.log(f"Live: {data['url']} - {data.get('status_code', '')} - {data.get('title', '')}", Colors.GREEN)
                    except Exception as e:
                        self.log(f"httpx çıktısı işlenemedi: {str(e)}", Colors.YELLOW)

            if live_hosts:
                with open(self.live_hosts_file, 'w') as f:
                    for host in sorted(set(live_hosts)):
                        f.write(f"{host}\n")

                self.log(f"Toplam {len(live_hosts)} canlı host bulundu", Colors.GREEN)
                self.log(f"Sonuçlar kaydedildi: {self.live_hosts_file}", Colors.GREEN)
            else:
                self.log("Hiç canlı host bulunamadı", Colors.RED)

            return live_hosts

        except subprocess.TimeoutExpired:
            self.log("httpx zaman aşımına uğradı", Colors.RED)
            return []
        except FileNotFoundError:
            self.log("httpx bulunamadı. Kurulu olduğundan emin olun.", Colors.RED)
            return []

    
    def advanced_nmap_scan(self, hosts):
        """Gelişmiş Nmap Taraması"""
        self.log("Gelişmiş Nmap taraması başlatılıyor...", Colors.GREEN)
        
        for host in hosts:
            host_clean = host.replace('https://', '').replace('http://', '').split(':')[0]
            
            # 1. Hızlı port taraması
            self.log(f"Hızlı tarama: {host_clean}")
            try:
                result = subprocess.run([
                    'nmap', '-T4', '-F', '--open', '-sV', '-Pn', host_clean
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    with open(f"{self.nmap_dir}/{host_clean}_fast.txt", 'w') as f:
                        f.write(result.stdout)
                    self.log(f"Hızlı tarama tamamlandı: {host_clean}")
            except:
                self.log(f"Nmap hatası: {host_clean}", Colors.YELLOW)
            
            # 2. Yaygın portlar
            self.log(f"Yaygın port taraması: {host_clean}")
            try:
                result = subprocess.run([
                    'nmap', '-T4', '-p', '80,443,8080,8443,21,22,23,25,53,110,993,995,1433,3306,5432',
                    '-sV', '-Pn', host_clean
                ], capture_output=True, text=True, timeout=400)
                
                if result.returncode == 0:
                    with open(f"{self.nmap_dir}/{host_clean}_common.txt", 'w') as f:
                        f.write(result.stdout)
                    
                    # Açık portları logla
                    for line in result.stdout.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            self.log(f"Açık port: {host_clean} - {line.strip()}", Colors.GREEN)
            except:
                pass
    
    def port_scanning(self, live_hosts_list=None):
        """3. Aşama: Port Scanning"""
        self.log("Port taraması başlatılıyor...", Colors.GREEN)
        
        if live_hosts_list is None:
            if not os.path.exists(self.live_hosts_file):
                self.log("Live hosts dosyası bulunamadı! Önce live host detection yapın.", Colors.RED)
                return
            
            with open(self.live_hosts_file, 'r') as f:
                live_hosts_list = [line.strip() for line in f if line.strip()]
        
        hosts = []
        for url in live_hosts_list:
            if url.startswith(('http://', 'https://')):
                parsed = urlparse(url)
                hosts.append(parsed.netloc.split(':')[0])
            else:
                hosts.append(url.split(':')[0])
        
        hosts = list(set(hosts))
        all_results = []
        
        for host in hosts:
            self.log(f"Taranıyor: {host}")
            try:
                result = subprocess.run([
                    'nmap', '-T4', '-F', '--open', '-Pn', host
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '/tcp' in line and 'open' in line:
                            port_info = f"{host}: {line.strip()}"
                            all_results.append(port_info)
                            self.log(f"Açık port: {port_info}", Colors.GREEN)
            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.log(f"Nmap hatası: {host}", Colors.YELLOW)
        
        if all_results:
            with open(self.ports_file, 'w') as f:
                for result in all_results:
                    f.write(f"{result}\n")
            
            self.log(f"Port taraması tamamlandı: {self.ports_file}", Colors.GREEN)
            
            # Gelişmiş nmap taraması
            self.advanced_nmap_scan(hosts[:3])  # İlk 3 host için
        else:
            self.log("Açık port bulunamadı", Colors.YELLOW)
    

    def directory_bruteforce(self, live_hosts_list=None):
        """4. Aşama: Directory Bruteforce"""
        self.log("Directory bruteforce başlatılıyor...", Colors.GREEN)
        
        if live_hosts_list is None:
            if not os.path.exists(self.live_hosts_file):
                self.log("Live hosts dosyası bulunamadı!", Colors.RED)
                return
            
            with open(self.live_hosts_file, 'r') as f:
                live_hosts_list = [line.strip() for line in f if line.strip()]
        
        all_directories = []
        
        for host in live_hosts_list[:5]:
            self.log(f"Directory taraması: {host}")
            try:
                result = subprocess.run([
                    'gobuster', 'dir', '-u', host, 
                    '-w', self.wordlist,
                    '-t', '50', '-q', '--no-error'
                ], capture_output=True, text=True, timeout=600)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip() and 'Status:' in line:
                            dir_info = f"{host} - {line.strip()}"
                            all_directories.append(dir_info)
                            self.log(f"Directory: {line.strip()}", Colors.GREEN)
            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.log(f"Gobuster hatası: {host}", Colors.YELLOW)
        
        if all_directories:
            with open(self.directories_file, 'w') as f:
                for directory in all_directories:
                    f.write(f"{directory}\n")
            
            self.log(f"Directory taraması tamamlandı: {self.directories_file}", Colors.GREEN)
        else:
            self.log("Directory bulunamadı", Colors.YELLOW)

    
    def take_screenshots(self, live_hosts_list=None):
        """5. Aşama: Screenshot Alma"""
        self.log("Screenshot alma başlatılıyor...", Colors.GREEN)

        if live_hosts_list is None:
            if not os.path.exists(self.live_hosts_file):
                self.log("Live hosts dosyası bulunamadı!", Colors.RED)
                return

            with open(self.live_hosts_file, 'r') as f:
                live_hosts_list = [line.strip() for line in f if line.strip()]

        # Aquatone girişi hazırlığı
        temp_input_path = '/tmp/aquatone_input.txt'
        with open(temp_input_path, 'w') as f:
            for host in live_hosts_list:
                f.write(f"{host}\n")

        self.log("Aquatone ile toplu screenshot alınıyor...")
        try:
            subprocess.run(
                ['aquatone', '-out', self.screenshots_dir],
                input="\n".join(live_hosts_list),
                text=True,
                capture_output=True,
                timeout=180
            )
            self.log(f"Aquatone çıktısı: {self.screenshots_dir}", Colors.GREEN)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.log("Aquatone başarısız oldu, wkhtmltoimage ile devam ediliyor...", Colors.YELLOW)
            # Alternatif olarak wkhtmltoimage kullan
            for host in live_hosts_list:
                try:
                    safe_name = re.sub(r'[^\w\-_.]', '_', host.replace('://', '_'))
                    screenshot_path = f"{self.screenshots_dir}/{safe_name}.png"

                    subprocess.run([
                        'wkhtmltoimage', '--width', '1024', '--height', '768',
                        host, screenshot_path
                    ], timeout=30, check=True)

                    self.log(f"Screenshot kaydedildi: {screenshot_path}", Colors.GREEN)

                except Exception as e:
                    self.log(f"Screenshot alınamadı ({host}): {str(e)}", Colors.YELLOW)
         
    
    def technology_detection(self, live_hosts_list=None):
        """Ek Aşama: Teknoloji Tespiti"""
        self.log("Teknoloji tespiti başlatılıyor...", Colors.GREEN)
        
        if live_hosts_list is None:
            if not os.path.exists(self.live_hosts_file):
                self.log("Live hosts dosyası bulunamadı!", Colors.RED)
                return
            
            with open(self.live_hosts_file, 'r') as f:
                live_hosts_list = [line.strip() for line in f if line.strip()]
        
        tech_results = []
        
        for host in live_hosts_list:
            try:
                result = subprocess.run([
                    'whatweb', '--color=never', '--quiet', host
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and result.stdout.strip():
                    tech_info = f"{host}: {result.stdout.strip()}"
                    tech_results.append(tech_info)
                    self.log(f"Teknoloji: {result.stdout.strip()}", Colors.CYAN)
            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.log(f"Whatweb hatası: {host}", Colors.YELLOW)
        
        if tech_results:
            tech_file = f"{self.output_dir}/technologies.txt"
            with open(tech_file, 'w') as f:
                for tech in tech_results:
                    f.write(f"{tech}\n")
            
            self.log(f"Teknoloji tespiti tamamlandı: {tech_file}", Colors.GREEN)

def main():
    parser = argparse.ArgumentParser(description='Modüler Recon Aracı')
    parser.add_argument('-d', '--domain', help='Hedef domain')
    parser.add_argument('-l', '--list', help='Domain listesi içeren dosya (her satırda bir domain)')
    parser.add_argument('-o', '--output', default='recon_results', help='Çıktı dizini')
    parser.add_argument('--threads', type=int, default=50, help='Thread sayısı (varsayılan: 50)')
    parser.add_argument('--wordlist', help='Directory brute-force için wordlist yolu')
    parser.add_argument('--subdomain', action='store_true', help='Sadece subdomain enumeration')
    parser.add_argument('--live', action='store_true', help='Sadece live host detection')
    parser.add_argument('--ports', action='store_true', help='Sadece port scanning')
    parser.add_argument('--dirs', action='store_true', help='Sadece directory bruteforce')
    parser.add_argument('--screenshots', action='store_true', help='Sadece screenshot alma')
    parser.add_argument('--tech', action='store_true', help='Sadece teknoloji tespiti')
    parser.add_argument('--all', action='store_true', help='Tüm aşamaları çalıştır')

    args = parser.parse_args()
    
    domains = []

# Tek domain mi, çoklu domain mi?
    if args.list:
        if not os.path.exists(args.list):
            print(f"[!] Hata: {args.list} dosyası bulunamadı!")
            sys.exit(1)
        with open(args.list, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    elif args.domain:
        domains = [args.domain]
    else:
        print("[!] Domain veya domain listesi belirtmelisiniz. -d veya -l kullanın.")
        sys.exit(1)

    # Her domain için recon işlemi
    for domain in domains:
        print(f"\n{'='*40}\n[+] {domain} için işlem başlatılıyor\n{'='*40}")
        output_path = os.path.join(args.output, domain.replace("://", "").replace("/", ""))
        recon = ReconTool(domain, output_path, args.threads, args.wordlist)
        
        try:
            if args.all or (not any([args.subdomain, args.live, args.ports, args.dirs, args.screenshots, args.tech])):
                subdomains = recon.subdomain_enumeration()
                live_hosts = recon.live_host_detection(subdomains)
                recon.port_scanning(live_hosts)
                recon.directory_bruteforce(live_hosts)
                recon.take_screenshots(live_hosts)
                recon.technology_detection(live_hosts)
            else:
                if args.subdomain:
                    recon.subdomain_enumeration()
                if args.live:
                    recon.live_host_detection()
                if args.ports:
                    recon.port_scanning()
                if args.dirs:
                    recon.directory_bruteforce()
                if args.screenshots:
                    recon.take_screenshots()
                if args.tech:
                    recon.technology_detection()

            recon.log("Recon tamamlandı!", Colors.GREEN)
        except KeyboardInterrupt:
            recon.log("İşlem kullanıcı tarafından durduruldu", Colors.YELLOW)
        except Exception as e:
            recon.log(f"Hata: {str(e)}", Colors.RED)


if __name__ == "__main__":
    main()

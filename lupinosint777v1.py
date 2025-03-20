import requests
import threading
import os
import time
import hashlib
import socks
import socket
import subprocess
import json
import dns.resolver
import ssl
import platform
import re
from stem.control import Controller
from tqdm import tqdm
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import whois
import pyfiglet

init(autoreset=True)

POPULAR_SITES = [
    "instagram.com", "facebook.com", "twitter.com", "youtube.com", "linkedin.com",
    "github.com", "reddit.com", "tiktok.com", "pinterest.com", "snapchat.com",
    "steamcommunity.com", "twitch.tv", "medium.com", "deviantart.com", "quora.com",
]

# ------------------ Temel Fonksiyonlar ------------------
def start_tor():
    print(Fore.YELLOW + "[*] Tor ağı başlatılıyor...")
    subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)

def change_tor_ip():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(2)
        print(Fore.YELLOW + "[*] Yeni bir Tor IP alındı.")

def generate_hash(text, algo):
    algo_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    if algo not in algo_map:
        print(Fore.RED + "❌ Desteklenmeyen algoritma! Kullanılabilir: md5, sha1, sha256, sha512")
        return
    hashed = algo_map[algo](text.encode()).hexdigest()
    print(Fore.GREEN + f"[+] {algo.upper()} Hash: {hashed}")

def crack_hash(hash_value, wordlist, algo="md5"):
    algo_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    if algo not in algo_map:
        print(Fore.RED + "❌ Desteklenmeyen algoritma!")
        return
    with open(wordlist, "r", encoding="utf-8") as f:
        for password in tqdm(f.readlines(), desc="Hash kırma işlemi"):
            password = password.strip()
            hashed_password = algo_map[algo](password.encode()).hexdigest()
            if hashed_password == hash_value:
                print(Fore.GREEN + f"[+] Şifre bulundu: {password}")
                return
    print(Fore.RED + "[-] Şifre bulunamadı.")

def google_dorking(query, proxies=None, return_results=False):
    print(Fore.YELLOW + f"[*] Google Dorking başlatılıyor: {query}")
    search_url = f"https://www.google.com/search?q={query}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(search_url, headers=headers, proxies=proxies, timeout=10)
    except Exception as e:
        print(Fore.RED + f"[-] Arama hatası: {e}")
        return [] if return_results else None
    soup = BeautifulSoup(response.text, "html.parser")
    results = []
    for g in soup.find_all('a'):
        link = g.get('href')
        if link and "url?q=" in link and not "webcache" in link:
            results.append(link.split("?q=")[1].split("&sa=U")[0])
    return results if return_results else [print(Fore.GREEN + f"[+] {r}") for r in results]

def subdomain_enum(domain):
    print(Fore.YELLOW + f"[*] {domain} için alt alan adları aranıyor...")
    subdomains = ["www", "mail", "ftp", "api", "blog", "dev", "test"]
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            dns.resolver.resolve(subdomain, "A")
            print(Fore.GREEN + f"[+] {subdomain} aktif!")
        except dns.resolver.NXDOMAIN:
            print(Fore.RED + f"[-] {subdomain} bulunamadı.")

def whois_lookup(domain):
    print(Fore.YELLOW + f"[*] {domain} için WHOIS bilgisi alınıyor...")
    try:
        w = whois.whois(domain)
        print(Fore.GREEN + f"[+] WHOIS Bilgisi:\n{w}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def get_title(url):
    print(Fore.YELLOW + f"[*] {url} için başlık alınıyor...")
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "Başlık bulunamadı"
        print(Fore.GREEN + f"[+] Başlık: {title}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def get_banner(ip):
    print(Fore.YELLOW + f"[*] {ip} için banner alınmaya çalışılıyor...")
    try:
        socket.setdefaulttimeout(3)
        s = socket.socket()
        s.connect((ip, 80))
        s.send(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        banner = s.recv(1024).decode()
        print(Fore.GREEN + f"[+] Banner: {banner}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def get_http_headers(url):
    print(Fore.YELLOW + f"[*] {url} için HTTP başlıkları alınıyor...")
    try:
        response = requests.head(url, timeout=10)
        for header, value in response.headers.items():
            print(Fore.GREEN + f"{header}: {value}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def find_phone_numbers(text):
    print(Fore.YELLOW + "[*] Telefon numaraları aranıyor...")
    phone_pattern = r'\+?(\d{1,2})?[\s-]?(?\d{1,4}?[\s-]?\d{1,4}[\s-]?\d{1,4})'
    phones = re.findall(phone_pattern, text)
    for phone in phones:
        num = ''.join(phone)
        if num:
            print(Fore.GREEN + f"[+] Telefon: {num}")

def find_emails(text):
    print(Fore.YELLOW + "[*] Email adresleri aranıyor...")
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    for email in emails:
        print(Fore.GREEN + f"[+] Email: {email}")

def extract_urls(text):
    print(Fore.YELLOW + "[*] URL'ler çıkarılıyor...")
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    for url in urls:
        print(Fore.GREEN + f"[+] URL: {url}")

def dns_lookup(domain):
    print(Fore.YELLOW + f"[*] {domain} için DNS bilgileri alınıyor...")
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ip in result:
            print(Fore.GREEN + f"[+] {domain} IP: {ip}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def geoip_lookup(ip):
    print(Fore.YELLOW + f"[*] {ip} için coğrafi bilgi alınıyor...")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()
        if data["status"] == "fail":
            print(Fore.RED + "[-] Geolocation verisi bulunamadı.")
        else:
            print(Fore.GREEN + f"[+] {ip} Konum: {data['country']}, {data['city']}, {data['isp']}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def scan_open_ports(ip):
    print(Fore.YELLOW + f"[*] {ip} için açık portlar taranıyor...")
    open_ports = []
    for port in range(1, 1024):
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    if open_ports:
        print(Fore.GREEN + f"[+] Açık portlar: {', '.join(map(str, open_ports))}")
    else:
        print(Fore.RED + "[-] Açık port bulunamadı.")

def content(url):
    print(Fore.YELLOW + f"[*] {url} sayfası içeriği alınıyor...")
    try:
        response = requests.get(url, timeout=10)
        print(Fore.GREEN + f"[+] İçerik:\n{response.text[:500]}...")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def html_title(url):
    print(Fore.YELLOW + f"[*] {url} HTML başlığı alınıyor...")
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "Başlık bulunamadı"
        print(Fore.GREEN + f"[+] Başlık: {title}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def robots(url):
    print(Fore.YELLOW + f"[*] {url} robots.txt dosyası alınıyor...")
    try:
        response = requests.get(f"{url}/robots.txt", timeout=10)
        print(Fore.GREEN + f"[+] Robots.txt:\n{response.text}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def random_user_agent():
    print(Fore.YELLOW + "[*] Rastgele User-Agent başlığı alınıyor...")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/56.0.2924.87 Safari/537.36"
    ]
    import random
    print(Fore.GREEN + f"[+] User-Agent: {random.choice(user_agents)}")

def ping_target(target):
    print(Fore.YELLOW + f"[*] {target} için 10 saniyelik ping işlemi başlatılıyor...")
    system = platform.system().lower()
    try:
        if "windows" in system:
            process = subprocess.Popen(["ping", "-n", "10", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        else:
            process = subprocess.Popen(["ping", "-c", "10", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate(timeout=20)
        if stderr:
            print(Fore.RED + f"[-] Ping hatası: {stderr}")
            return
        if "windows" in system:
            match = re.search(r"Average = (\d+ms)", stdout)
            if match:
                avg = match.group(1)
                print(Fore.GREEN + f"[+] Ortalama Ping: {avg}")
            else:
                print(Fore.RED + "[-] Ortalama ping bulunamadı.")
        else:
            match = re.search(r"rtt [\w/]+ = [\d\.]+/([\d\.]+)/", stdout)
            if match:
                avg = match.group(1)
                print(Fore.GREEN + f"[+] Ortalama Ping: {avg} ms")
            else:
                print(Fore.RED + "[-] Ortalama ping bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"[-] Ping işlemi hatası: {e}")

# ------------------ Sosyal Profil Fonksiyonları ------------------
def social_details(site, username, tor_mode=False):
    proxies = None
    if tor_mode:
        start_tor()
        proxies = {'http': 'socks5://127.0.0.1:9050', 'https': 'socks5://127.0.0.1:9050'}
        print(Fore.YELLOW + "[*] Tor üzerinden sosyal profil sorgusu yapılıyor...")
    url = f"https://{site}/{username}"
    try:
        response = requests.get(url, proxies=proxies, timeout=10)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] {site} | {username} bulundu. URL: {url}")
            print(Fore.GREEN + f"[+] Özet: {response.text[:300]}...")
        else:
            print(Fore.RED + f"[-] {site} | {username} bulunamadı. (Status: {response.status_code})")
    except Exception as e:
        print(Fore.RED + f"[-] {site} | {username} sorgusunda hata: {e}")

def sd_command(username, tor_mode=False, sites=None):
    if not sites:
        sites = POPULAR_SITES
    for site in sites:
        social_details(site, username, tor_mode)

# ------------------ Sosyal Profil Komutları (Özel) ------------------
def insta(username, tor_mode=False):
    social_details("instagram.com", username, tor_mode)
def fb(username, tor_mode=False):
    social_details("facebook.com", username, tor_mode)
def twitter(username, tor_mode=False):
    social_details("twitter.com", username, tor_mode)
def linkedin(username, tor_mode=False):
    social_details("linkedin.com", username, tor_mode)
def github(username, tor_mode=False):
    social_details("github.com", username, tor_mode)
def reddit(username, tor_mode=False):
    social_details("reddit.com", username, tor_mode)
def tiktok(username, tor_mode=False):
    social_details("tiktok.com", username, tor_mode)
def pinterest(username, tor_mode=False):
    social_details("pinterest.com", username, tor_mode)
def snapchat(username, tor_mode=False):
    social_details("snapchat.com", username, tor_mode)
def youtube(username, tor_mode=False):
    social_details("youtube.com", username, tor_mode)

# ------------------ Ek Yeni Komutlar ------------------
def public_ip():
    print(Fore.YELLOW + "[*] Genel IP adresi alınıyor...")
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=10)
        ip = response.json().get("ip")
        print(Fore.GREEN + f"[+] Genel IP: {ip}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def os_info():
    info = f"OS: {platform.system()} {platform.release()} | İşlemci: {platform.processor()}"
    print(Fore.GREEN + f"[+] Sistem Bilgisi: {info}")

def traceroute(target):
    print(Fore.YELLOW + f"[*] {target} için traceroute başlatılıyor...")
    system = platform.system().lower()
    try:
        cmd = ["tracert", target] if "windows" in system else ["traceroute", target]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate(timeout=30)
        if stderr:
            print(Fore.RED + f"[-] Hata: {stderr}")
        else:
            print(Fore.GREEN + f"[+] Traceroute Sonucu:\n{stdout}")
    except Exception as e:
        print(Fore.RED + f"[-] Traceroute hatası: {e}")

def ssl_info(domain):
    print(Fore.YELLOW + f"[*] {domain} için SSL bilgileri alınıyor...")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(Fore.GREEN + f"[+] SSL Sertifika Bilgileri:\n{cert}")
    except Exception as e:
        print(Fore.RED + f"[-] SSL bilgisi alınamadı: {e}")

def reverse_dns(ip):
    print(Fore.YELLOW + f"[*] {ip} için ters DNS sorgusu yapılıyor...")
    try:
        host = socket.gethostbyaddr(ip)
        print(Fore.GREEN + f"[+] Ters DNS sonucu: {host[0]}")
    except Exception as e:
        print(Fore.RED + f"[-] Ters DNS hatası: {e}")

def current_time():
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(Fore.GREEN + f"[+] Şu anki tarih ve saat: {now}")

def weather(city):
    print(Fore.YELLOW + f"[*] {city} için hava durumu sorgulanıyor...")
    try:
        response = requests.get(f"http://wttr.in/{city}?format=3", timeout=10)
        print(Fore.GREEN + f"[+] Hava Durumu: {response.text}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def calc(expression):
    print(Fore.YELLOW + f"[*] Hesaplama yapılıyor: {expression}")
    try:
        if re.fullmatch(r'[\d\+\-\*\/\.\s]+', expression):
            result = eval(expression)
            print(Fore.GREEN + f"[+] Sonuç: {result}")
        else:
            print(Fore.RED + "[-] Geçersiz ifade!")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def shorten(url):
    print(Fore.YELLOW + f"[*] URL kısaltması alınıyor: {url}")
    try:
        response = requests.get(f"http://tinyurl.com/api-create.php?url={url}", timeout=10)
        print(Fore.GREEN + f"[+] Kısaltılmış URL: {response.text}")
    except Exception as e:
        print(Fore.RED + f"[-] Hata: {e}")

def whoami():
    try:
        user = os.getlogin() if hasattr(os, "getlogin") else "Bilinmiyor"
    except Exception:
        user = "Bilinmiyor"
    env = os.environ.get("USER", os.environ.get("USERNAME", "Bilinmiyor"))
    print(Fore.GREEN + f"[+] Kullanıcı: {user} | Ortam: {env}")

# ------------------ Ek Yeni Komutlar (Ekstra 10 Komut) ------------------
def full_portscan(ip, start_port=1, end_port=1024):
    print(Fore.YELLOW + f"[*] {ip} için full port scan başlatılıyor ({start_port}-{end_port})...")
    open_ports = []
    def scan_port(port):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    threads = []
    for port in range(int(start_port), int(end_port)+1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    if open_ports:
        print(Fore.GREEN + f"[+] Açık portlar: {', '.join(map(str, open_ports))}")
    else:
        print(Fore.RED + "[-] Açık port bulunamadı.")

def email_validate(email):
    print(Fore.YELLOW + f"[*] {email} doğrulanıyor...")
    if re.fullmatch(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email):
        domain = email.split('@')[1]
        try:
            records = dns.resolver.resolve(domain, 'MX')
            mx_records = ", ".join([str(r.exchange) for r in records])
            print(Fore.GREEN + f"[+] Email formatı geçerli. MX kayıtları: {mx_records}")
        except Exception as e:
            print(Fore.RED + f"[-] MX kaydı bulunamadı: {e}")
    else:
        print(Fore.RED + "[-] Email formatı geçersiz!")

def url_status(url):
    print(Fore.YELLOW + f"[*] {url} durumu kontrol ediliyor...")
    try:
        start = time.time()
        response = requests.get(url, timeout=10)
        elapsed = time.time() - start
        print(Fore.GREEN + f"[+] Durum: {response.status_code}, Yanıt süresi: {elapsed:.2f} saniye")
    except Exception as e:
        print(Fore.RED + f"[-] URL durumu alınamadı: {e}")

def whois_raw(domain):
    print(Fore.YELLOW + f"[*] {domain} için ham WHOIS bilgisi alınıyor...")
    try:
        raw = whois.whois(domain)
        print(Fore.GREEN + f"[+] Raw WHOIS:\n{raw}")
    except Exception as e:
        print(Fore.RED + f"[-] Raw WHOIS alınamadı: {e}")

def server_info(url):
    print(Fore.YELLOW + f"[*] {url} sunucu bilgisi alınıyor...")
    try:
        response = requests.get(url, timeout=10)
        server = response.headers.get("Server", "Bilinmiyor")
        print(Fore.GREEN + f"[+] Sunucu: {server}")
    except Exception as e:
        print(Fore.RED + f"[-] Sunucu bilgisi alınamadı: {e}")

def ssl_expiry(domain):
    print(Fore.YELLOW + f"[*] {domain} SSL sertifika geçerliliği kontrol ediliyor...")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expiry = cert.get('notAfter', 'Bilinmiyor')
            print(Fore.GREEN + f"[+] SSL Geçerlilik Tarihi: {expiry}")
    except Exception as e:
        print(Fore.RED + f"[-] SSL geçerlilik alınamadı: {e}")

def banner_grab(ip, port):
    print(Fore.YELLOW + f"[*] {ip}:{port} için banner grab yapılıyor...")
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, int(port)))
        s.send(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        banner = s.recv(1024).decode()
        print(Fore.GREEN + f"[+] Banner: {banner}")
        s.close()
    except Exception as e:
        print(Fore.RED + f"[-] Banner grab hatası: {e}")

def fetch_source(url):
    print(Fore.YELLOW + f"[*] {url} kaynağı alınıyor...")
    try:
        response = requests.get(url, timeout=10)
        print(Fore.GREEN + f"[+] Kaynak:\n{response.text[:500]}...")
    except Exception as e:
        print(Fore.RED + f"[-] Kaynak alınamadı: {e}")

def json_fetch(url):
    print(Fore.YELLOW + f"[*] {url} üzerinden JSON veri alınıyor...")
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        pretty = json.dumps(data, indent=4)
        print(Fore.GREEN + f"[+] JSON Veri:\n{pretty}")
    except Exception as e:
        print(Fore.RED + f"[-] JSON alınamadı: {e}")

def dns_records(domain):
    print(Fore.YELLOW + f"[*] {domain} için DNS kayıtları alınıyor...")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for rec in record_types:
        try:
            answers = dns.resolver.resolve(domain, rec)
            records = ", ".join([str(r) for r in answers])
            print(Fore.GREEN + f"[+] {rec} kayıtları: {records}")
        except Exception as e:
            print(Fore.RED + f"[-] {rec} kaydı alınamadı: {e}")

# ------------------ Ek Yeni Komut: Proxy Checker ------------------
def proxy_checker(proxy_type, target_site, proxy_str):
    print(Fore.YELLOW + f"[*] Proxy testi yapılıyor: {proxy_type} | Hedef: {target_site} | Proxy: {proxy_str}")
    proxies = {
        "http": f"{proxy_type}://{proxy_str}",
        "https": f"{proxy_type}://{proxy_str}"
    }
    try:
        response = requests.get(target_site, proxies=proxies, timeout=10)
        if response.status_code == 200:
            print(Fore.GREEN + f"[+] Proxy başarılı! {target_site} erişilebildi.")
        else:
            print(Fore.RED + f"[-] Proxy testinde hata: Status {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"[-] Proxy test hatası: {e}")

# ------------------ Ek Yeni Komut: IP Browser ------------------
def ip_browser(ip):
    print(Fore.YELLOW + f"[*] {ip} hakkında bilgiler getiriliyor...")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()
        if data["status"] == "fail":
            print(Fore.RED + f"[-] Bilgi alınamadı: {data.get('message', 'Bilinmiyor')}")
        else:
            info = f"Country: {data['country']}, City: {data['city']}, ISP: {data['isp']}, Timezone: {data['timezone']}"
            print(Fore.GREEN + f"[+] {ip} Hakkında Bilgiler: {info}")
    except Exception as e:
        print(Fore.RED + f"[-] IP Browser hatası: {e}")

# ------------------ Yardım Mesajı ------------------
def show_help():
    help_text = """
🛠️ KOMUT LİSTESİ:

/help                              -> Tüm komutları gösterir.
/find <kullanıcıadı> [--tor] [--site site1 site2 ...]
                                  -> Belirtilen kullanıcı adını Google dorking yöntemiyle arar.
/sd <kullanıcıadı> [--tor] [--site site1 site2 ...]
                                  -> Sosyal profil bilgilerini getirir.
/hash <md5|sha1|sha256|sha512> <text>
                                  -> Hash oluşturur.
/crack <hash> <wordlist.txt> <algo>
                                  -> Hash kırar.
/dork <query>                     -> Google Dorking yapar.
/subdomain <domain>               -> Alt alan adı taraması yapar.
/whois <domain>                   -> Whois sorgusu yapar.
/title <url>                      -> URL'nin başlığını alır.
/banner <ip>                      -> Hedef IP'den banner alır.
/http-headers <url>               -> HTTP başlıklarını alır.
/find-phones <text>               -> Metin içerisinden telefon numarası bulur.
/find-emails <text>               -> Metin içerisinden email adresi bulur.
/url-extract <text>               -> Metin içerisindeki URL'leri çıkarır.
/dns-lookup <domain>              -> DNS bilgisi sorgular.
/geoip <ip>                       -> IP'nin coğrafi bilgilerini alır.
/scan-open-ports <ip>             -> Açık portları tarar.
/content <url>                    -> Web sayfası içeriğini çeker.
/html-title <url>                 -> HTML sayfa başlığını alır.
/robots <url>                     -> Robots.txt dosyasını getirir.
/user-agents                      -> Rastgele User-Agent verir.
/ping <domain/ip>                 -> Hedefi 10 sn pingler ve ortalama ping değerini gösterir.

--- Sosyal Profil Komutları ---
/insta <kullanıcıadı> [--tor]     -> Instagram profil bilgilerini getirir.
/fb <kullanıcıadı> [--tor]        -> Facebook profil bilgilerini getirir.
/twitter <kullanıcıadı> [--tor]   -> Twitter profil bilgilerini getirir.
/linkedin <kullanıcıadı> [--tor]  -> LinkedIn profil bilgilerini getirir.
/github <kullanıcıadı> [--tor]    -> GitHub profil bilgilerini getirir.
/reddit <kullanıcıadı> [--tor]    -> Reddit profil bilgilerini getirir.
/tiktok <kullanıcıadı> [--tor]    -> TikTok profil bilgilerini getirir.
/pinterest <kullanıcıadı> [--tor] -> Pinterest profil bilgilerini getirir.
/snapchat <kullanıcıadı> [--tor]  -> Snapchat profil bilgilerini getirir.
/youtube <kullanıcıadı> [--tor]   -> YouTube kanal bilgilerini getirir.
/sd <kullanıcıadı> [--tor] [--site site1 site2 ...]
                                  -> Sosyal profil detaylarını getirir.

--- Ek Ekstra Komutlar ---
/proxychecker --proxytürü <tür> --site <hedef_site> --proxy <proxy_adresi>
                                  -> Proxy testi yapar.
/ipbrowser --ip <IP_adresi>       -> IP hakkında detaylı bilgi getirir.
/full-portscan <ip> [başlangıç] [bitiş]
                                  -> Belirtilen port aralığında tam port taraması yapar.
/email-validate <email>           -> Email formatını ve MX kayıtlarını kontrol eder.
/url-status <url>                 -> URL’nin durum kodu ve yanıt süresini gösterir.
/whois-raw <domain>               -> Ham WHOIS bilgisini getirir.
/server-info <url>                -> URL’nin sunucu bilgilerini gösterir.
/ssl-expiry <domain>              -> Domain’in SSL sertifika geçerlilik tarihini gösterir.
/banner-grab <ip> <port>          -> Belirtilen IP:Port'tan banner alır.
/fetch-source <url>               -> URL’nin ham HTML kaynağını getirir.
/json-fetch <url>                 -> URL’den JSON veri alır ve formatlar.
/dns-records <domain>             -> Domain için A, AAAA, MX, NS, TXT kayıtlarını getirir.

--- Diğer Komutlar ---
/public-ip                        -> Genel IP adresinizi gösterir.
/osinfo                           -> İşletim sistemi bilgilerini gösterir.
/trace <target>                   -> Traceroute işlemi yapar.
/ssl-info <domain>                -> SSL sertifika bilgilerini getirir.
/reverse-dns <ip>                 -> Ters DNS sorgusu yapar.
/time                             -> Güncel tarih ve saati gösterir.
/weather <şehir>                  -> Belirtilen şehir için hava durumunu getirir.
/calc <ifade>                     -> Basit aritmetik hesaplama yapar.
/shorten <url>                    -> URL'yi kısaltır.
/whoami                           -> Kullanıcı ve ortam bilgilerini gösterir.

/exit                             -> Programdan çıkar.

(Programdan çıkmak için /exit veya quit yazabilirsiniz.)
    """
    print(help_text)

# ------------------ İnteraktif Mod ------------------
def interactive_mode():
    print(Fore.MAGENTA + "contact instagram.com/lupin.reizzz | Dikkat, bu tool tamamı ile eğitim amaçlıdır.")
    while True:
        command = input(Fore.CYAN + "\nKomut Girin: ").strip()
        if not command:
            continue
        tokens = command.split()
        if tokens[0] == "/help":
            show_help()
        elif tokens[0] == "/find":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
                continue
            username = tokens[1]
            tor_mode = "--tor" in tokens
            sites = []
            if "--site" in tokens:
                try:
                    site_index = tokens.index("--site") + 1
                    sites = tokens[site_index:]
                except:
                    sites = []
            for site in sites if sites else POPULAR_SITES:
                query = f"site:{site} {username}"
                results = google_dorking(query, proxies={'http': 'socks5://127.0.0.1:9050', 'https': 'socks5://127.0.0.1:9050'} if tor_mode else None, return_results=True)
                if results and len(results) > 0:
                    print(Fore.GREEN + f"[+] Taranan site | {site} | İlk sonuç: {results[0]}")
                else:
                    print(Fore.RED + f"[-] Taranan site | {site} | Sonuç bulunamadı")
        elif tokens[0] == "/sd":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
                continue
            username = tokens[1]
            tor_mode = "--tor" in tokens
            sites = []
            if "--site" in tokens:
                try:
                    site_index = tokens.index("--site") + 1
                    sites = tokens[site_index:]
                except:
                    sites = []
            sd_command(username, tor_mode, sites if sites else None)
        elif tokens[0] == "/hash":
            if len(tokens) < 3:
                print(Fore.RED + "❌ Hash algoritması ve metin girin!")
            else:
                generate_hash(tokens[2], tokens[1])
        elif tokens[0] == "/crack":
            if len(tokens) < 4:
                print(Fore.RED + "❌ Hash değeri, wordlist dosyası ve algoritma girin!")
            else:
                crack_hash(tokens[1], tokens[2], tokens[3])
        elif tokens[0] == "/dork":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Google dork girin!")
            else:
                google_dorking(" ".join(tokens[1:]))
        elif tokens[0] == "/subdomain":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Alan adı girin!")
            else:
                subdomain_enum(tokens[1])
        elif tokens[0] == "/whois":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Alan adı girin!")
            else:
                whois_lookup(tokens[1])
        elif tokens[0] == "/title":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                get_title(tokens[1])
        elif tokens[0] == "/banner":
            if len(tokens) < 2:
                print(Fore.RED + "❌ IP girin!")
            else:
                get_banner(tokens[1])
        elif tokens[0] == "/http-headers":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                get_http_headers(tokens[1])
        elif tokens[0] == "/find-phones":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Metin girin!")
            else:
                find_phone_numbers(" ".join(tokens[1:]))
        elif tokens[0] == "/find-emails":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Metin girin!")
            else:
                find_emails(" ".join(tokens[1:]))
        elif tokens[0] == "/url-extract":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Metin girin!")
            else:
                extract_urls(" ".join(tokens[1:]))
        elif tokens[0] == "/dns-lookup":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Alan adı girin!")
            else:
                dns_lookup(tokens[1])
        elif tokens[0] == "/geoip":
            if len(tokens) < 2:
                print(Fore.RED + "❌ IP girin!")
            else:
                geoip_lookup(tokens[1])
        elif tokens[0] == "/scan-open-ports":
            if len(tokens) < 2:
                print(Fore.RED + "❌ IP girin!")
            else:
                scan_open_ports(tokens[1])
        elif tokens[0] == "/content":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                content(tokens[1])
        elif tokens[0] == "/html-title":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                html_title(tokens[1])
        elif tokens[0] == "/robots":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                robots(tokens[1])
        elif tokens[0] == "/user-agents":
            random_user_agent()
        elif tokens[0] == "/ping":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Hedef (domain/ip) girin!")
            else:
                ping_target(tokens[1])
        # Sosyal Profil Komutları
        elif tokens[0] == "/insta":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                insta(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/fb":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                fb(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/twitter":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                twitter(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/linkedin":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                linkedin(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/github":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                github(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/reddit":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                reddit(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/tiktok":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                tiktok(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/pinterest":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                pinterest(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/snapchat":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                snapchat(tokens[1], tor_mode="--tor" in tokens)
        elif tokens[0] == "/youtube":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Kullanıcı adı girin!")
            else:
                youtube(tokens[1], tor_mode="--tor" in tokens)
        # Ek Ekstra Komutlar
        elif tokens[0] == "/proxychecker":
            if "--proxytürü" not in tokens or "--site" not in tokens or "--proxy" not in tokens:
                print(Fore.RED + "❌ Lütfen: /proxychecker --proxytürü <tür> --site <hedef> --proxy <proxy_adresi> şeklinde kullanın!")
            else:
                try:
                    proxy_type = tokens[tokens.index("--proxytürü") + 1]
                    target_site = tokens[tokens.index("--site") + 1]
                    proxy_str = tokens[tokens.index("--proxy") + 1]
                    proxy_checker(proxy_type, target_site, proxy_str)
                except Exception as e:
                    print(Fore.RED + f"[-] Parametre hatası: {e}")
        elif tokens[0] == "/ipbrowser":
            if "--ip" not in tokens:
                print(Fore.RED + "❌ Lütfen: /ipbrowser --ip <IP_adresi> şeklinde kullanın!")
            else:
                try:
                    ip_value = tokens[tokens.index("--ip") + 1]
                    ip_browser(ip_value)
                except Exception as e:
                    print(Fore.RED + f"[-] Parametre hatası: {e}")
        # Ek Yeni Komutlar (Ekstra 10)
        elif tokens[0] == "/full-portscan":
            if len(tokens) < 2:
                print(Fore.RED + "❌ IP girin!")
            else:
                ip_addr = tokens[1]
                start_port = tokens[2] if len(tokens) > 2 else 1
                end_port = tokens[3] if len(tokens) > 3 else 1024
                full_portscan(ip_addr, start_port, end_port)
        elif tokens[0] == "/email-validate":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Email girin!")
            else:
                email_validate(tokens[1])
        elif tokens[0] == "/url-status":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                url_status(tokens[1])
        elif tokens[0] == "/whois-raw":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Domain girin!")
            else:
                whois_raw(tokens[1])
        elif tokens[0] == "/server-info":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                server_info(tokens[1])
        elif tokens[0] == "/ssl-expiry":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Domain girin!")
            else:
                ssl_expiry(tokens[1])
        elif tokens[0] == "/banner-grab":
            if len(tokens) < 3:
                print(Fore.RED + "❌ IP ve port girin!")
            else:
                banner_grab(tokens[1], tokens[2])
        elif tokens[0] == "/fetch-source":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                fetch_source(tokens[1])
        elif tokens[0] == "/json-fetch":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                json_fetch(tokens[1])
        elif tokens[0] == "/dns-records":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Domain girin!")
            else:
                dns_records(tokens[1])
        elif tokens[0] == "/public-ip":
            public_ip()
        elif tokens[0] == "/osinfo":
            os_info()
        elif tokens[0] == "/trace":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Hedef girin!")
            else:
                traceroute(tokens[1])
        elif tokens[0] == "/ssl-info":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Domain girin!")
            else:
                ssl_info(tokens[1])
        elif tokens[0] == "/reverse-dns":
            if len(tokens) < 2:
                print(Fore.RED + "❌ IP girin!")
            else:
                reverse_dns(tokens[1])
        elif tokens[0] == "/time":
            current_time()
        elif tokens[0] == "/weather":
            if len(tokens) < 2:
                print(Fore.RED + "❌ Şehir girin!")
            else:
                weather(tokens[1])
        elif tokens[0] == "/calc":
            if len(tokens) < 2:
                print(Fore.RED + "❌ İfade girin!")
            else:
                calc(" ".join(tokens[1:]))
        elif tokens[0] == "/shorten":
            if len(tokens) < 2:
                print(Fore.RED + "❌ URL girin!")
            else:
                shorten(tokens[1])
        elif tokens[0] == "/whoami":
            whoami()
        elif tokens[0] in ["/exit", "quit", "q"]:
            print(Fore.RED + "[*] Programdan çıkılıyor...")
            break
        else:
            print(Fore.RED + "❌ Bilinmeyen komut! /help ile yardım alabilirsiniz.")

if __name__ == "__main__":
    interactive_mode()
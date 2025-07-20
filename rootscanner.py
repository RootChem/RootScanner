import os
import time
import asyncio
import httpx
import dns.asyncresolver
import json
from urllib.parse import urlparse
from colorama import Fore, Style, init
import re
import ssl
import socket
from datetime import datetime

init(autoreset=True)

import os

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\033[1;32m")
    print(r"""
  _____             _         _____ _                     
 |  __ \           | |       / ____| |                    
 | |__) |___   ___ | |_ ___ | |    | |__   ___  _ __ ___  
 |  _  // _ \ / _ \| __/ _ \| |    | '_ \ / _ \| '_ ` _ \ 
 | | \ \ (_) | (_) | || (_) | |____| | | | (_) | | | | | |
 |_|  \_\___/ \___/ \__\___/ \_____|_| |_|\___/|_| |_| |_|
                                                         
                         RootChem v2.1
    """)
    print("\033[0m", end="")


def intro():
    banner()
    print("🔰 RootChem Advanced Web Scanner v2.1'e Hoşgeldiniz! 🔰\n")
    print("Bu araç, web sitelerinin güvenlik ve altyapı analizlerini yapmak için geliştirilmiştir.")
    print("İzin alınmadan kullanılmaması önemlidir. Eğitim ve araştırma amaçlıdır.\n")
    input("Devam etmek için Enter tuşuna basın...")
    target = input("🌐 Tarama yapılacak URL veya domaini girin (örn: example.com veya https://example.com): ").strip()
    return target

def normalize_url(input_url):
    if not input_url.startswith(("http://", "https://")):
        input_url = "http://" + input_url

    parsed = urlparse(input_url)
    scheme = parsed.scheme
    netloc = parsed.netloc

    if netloc.startswith("www."):
        netloc = netloc[4:]

    normalized_url = f"{scheme}://{netloc}"
    return normalized_url, netloc

async def fetch(session, url):
    headers = {"User-Agent": "Mozilla/5.0 (compatible; RootScanner/2.2)"}
    try:
        resp = await session.get(url, headers=headers, timeout=10)
        text = resp.text
        return resp.status_code, dict(resp.headers), text
    except httpx.RequestError as e:
        print(Fore.RED + f"[!] HTTP isteği başarısız: {e}")
        return None, None, None
    except Exception as e:
        print(Fore.RED + f"[!] Bilinmeyen hata: {e}")
        return None, None, None

async def dns_resolve(domain, record_type):
    resolver = dns.asyncresolver.Resolver()
    try:
        answers = await resolver.resolve(domain, record_type, lifetime=5)
        return [r.to_text() for r in answers]
    except (dns.asyncresolver.NoAnswer, dns.asyncresolver.NXDOMAIN):
        return []
    except Exception as e:
        print(Fore.RED + f"[!] DNS {record_type} kaydı alınamadı: {e}")
        return []

def extract_title(html):
    if not html:
        return "Başlık bulunamadı"
    match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else "Başlık bulunamadı"

def extract_meta(html):
    metas = {}
    if not html:
        return metas
    matches = re.findall(r'<meta\s+([^>]+)>', html, re.IGNORECASE)
    for tag in matches:
        name = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        content = re.search(r'content=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if name and content:
            metas[name.group(1).lower()] = content.group(1)
    return metas

async def get_robots(session, domain):
    try:
        url = f"http://{domain}/robots.txt"
        resp = await session.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return None

async def get_sitemap(session, domain):
    try:
        url = f"http://{domain}/sitemap.xml"
        resp = await session.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return None

def parse_ssl_date(date_str):
    try:
        return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return date_str

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                "subject": dict(x[0] for x in cert.get('subject', [])),
                "notBefore": parse_ssl_date(cert.get('notBefore')),
                "notAfter": parse_ssl_date(cert.get('notAfter')),
                "serialNumber": cert.get('serialNumber')
            }
    except Exception as e:
        print(Fore.YELLOW + f"[!] SSL bilgisi alınamadı: {e}")
        return {}

common_subdomains = [
    "www", "mail", "ftp", "webmail", "smtp", "docs", "blog",
    "dev", "test", "admin", "vpn", "m", "shop", "api", "staging",
    "beta", "portal", "support", "static", "secure"
]

async def resolve_ip(domain):
    try:
        answers = await dns.asyncresolver.resolve(domain, 'A', lifetime=5)
        return [r.to_text() for r in answers]
    except Exception:
        return []

async def subdomain_scan(domain):
    print(Fore.MAGENTA + "\n🔎 Alt Domain Taraması Başladı...\n")
    found_subdomains = {}

    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        ips = await resolve_ip(subdomain)
        if ips:
            found_subdomains[subdomain] = ips
            print(Fore.YELLOW + f"[+] {subdomain} => IP: {', '.join(ips)}")
        else:
            print(Fore.RED + f"[-] {subdomain} bulunamadı veya IP alınamadı.")
        await asyncio.sleep(0.2)

    if not found_subdomains:
        print(Fore.RED + "Alt domain bulunamadı.")
    return found_subdomains

async def port_scan(ip, port):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def port_scan_common(ips):
    common_ports = [21,22,25,53,80,110,143,443,465,587,993,995,3306,8080,8443]
    print(Fore.MAGENTA + "\n🔌 Yaygın Portlar Taraması Başlıyor...\n")
    for ip in ips:
        print(Fore.CYAN + f"IP: {ip}")
        for port in common_ports:
            is_open = await port_scan(ip, port)
            status = Fore.GREEN + "Açık" if is_open else Fore.RED + "Kapalı"
            print(f"  Port {port}: {status}")
        print()

def print_headers(headers):
    if not headers:
        print("  Header bilgisi yok.")
        return
    important_headers = ["server", "content-type", "x-powered-by", "set-cookie", "cache-control"]
    print("HTTP Başlıkları:")
    for h in important_headers:
        if h in headers:
            print(f"  {h}: {headers[h]}")

def save_results_to_json(filename, data):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(Fore.GREEN + f"[✓] Sonuçlar '{filename}' dosyasına kaydedildi.")
    except Exception as e:
        print(Fore.RED + f"[!] Sonuç dosyaya kaydedilirken hata: {e}")

async def main(raw_target):
    banner()
    start_time = time.time()
    target, domain = normalize_url(raw_target)
    print(f"\n📁 Hedef alındı: \033[1;36m{target}\033[0m\n")
    print("📡 Tarama başlatılıyor...\n")

    async with httpx.AsyncClient(timeout=10) as session:
        status, headers, html = await fetch(session, target)
        robots_txt = await get_robots(session, domain)
        sitemap_xml = await get_sitemap(session, domain)

    a_records = await dns_resolve(domain, "A")
    mx_records = await dns_resolve(domain, "MX")
    ns_records = await dns_resolve(domain, "NS")
    txt_records = await dns_resolve(domain, "TXT")

    ssl_info = get_ssl_info(domain)

    title = extract_title(html) if html else "Yok"
    metas = extract_meta(html) if html else {}

    print(Fore.GREEN + f"HTTP Durum Kodu: {status if status else 'Alınamadı'}")
    print_headers(headers)
    print(Fore.GREEN + f"Sayfa Başlığı: {title}")
    print(Fore.GREEN + f"Meta Etiketleri: {json.dumps(metas, indent=2, ensure_ascii=False)}\n")

    print(Fore.CYAN + "DNS Kayıtları:")
    print(f"  A: {a_records}")
    print(f"  MX: {mx_records}")
    print(f"  NS: {ns_records}")
    print(f"  TXT: {txt_records}\n")

    print(Fore.CYAN + "SSL Sertifika Bilgileri:")
    if ssl_info:
        for k, v in ssl_info.items():
            print(f"  {k}: {v}")
    else:
        print("  SSL bilgisi alınamadı veya sertifika yok.\n")

    print(Fore.CYAN + "Robots.txt İçeriği:")
    if robots_txt:
        print(robots_txt[:500] + "...\n")
    else:
        print("  robots.txt bulunamadı.\n")

    print(Fore.CYAN + "Sitemap.xml İçeriği:")
    if sitemap_xml:
        print(sitemap_xml[:500] + "...\n")
    else:
        print("  sitemap.xml bulunamadı.\n")

    found_subdomains = await subdomain_scan(domain)

    if found_subdomains:
        unique_sub_ips = set()
        for ips in found_subdomains.values():
            unique_sub_ips.update(ips)
        common_ips = set(a_records).intersection(unique_sub_ips)
        if common_ips:
            print(Fore.YELLOW + f"Alt domain ve ana domain IP çakışmaları: {', '.join(common_ips)}")
        else:
            print(Fore.CYAN + "Alt domain IP’leri ana domain IP’leri ile çakışmıyor.")
    else:
        print(Fore.RED + "Alt domain bulunamadı, port taraması yapılmayacak.")

    if a_records:
        await port_scan_common(list(set(a_records)))
    else:
        print(Fore.RED + "IP adresi bulunamadığı için port taraması yapılamıyor.")

    elapsed = time.time() - start_time
    print(Fore.GREEN + f"\n⏱ Tarama tamamlandı. Toplam süre: {elapsed:.2f} saniye.\n")

if __name__ == "__main__":
    target = intro()
    asyncio.run(main(target))

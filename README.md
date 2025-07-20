# RootScanner v2.1 🚀

RootScanner, web uygulamalarına yönelik kapsamlı bilgi toplama ve analiz aracı olarak geliştirilmiştir.
Bu araç özellikle siber güvenlik, pentest ve OSINT çalışmalarında kullanılmak üzere tasarlanmıştır.

## 👨‍💻 Geliştirici
**RootChem** tarafından geliştirilmiştir.

## 🔧 Özellikler
- HTTP durum kodu ve başlık analizi
- Sayfa başlığı ve meta etiket çekme
- DNS kayıtları (A, MX, NS, TXT)
- SSL sertifika bilgisi toplama
- robots.txt ve sitemap.xml içeriği görüntüleme
- Yaygın alt domain taraması
- IP üzerinden port taraması

## 🧱 Gereksinimler

Python 3.8+ sürümüne sahip olmanız önerilir. Aşağıdaki modüller gereklidir:

- httpx
- dnspython
- colorama

## ⚙️ Kurulum

```bash
git clone https://github.com/kullaniciadi/RootScanner.git
cd RootScanner
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate
pip install -r requirements.txt

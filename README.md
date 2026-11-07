# ReconKit

Tool recon automation sederhana: menjalankan nmap, mem-parsing hasilnya, dan membuat laporan otomatis.
Dibuat sebagai proyek belajar setelah kursus Junior Penetration Tester (CEH).

## ⚠️ Legal
Gunakan **hanya** pada sistem milik sendiri atau yang sudah memberi izin tertulis.
Target latihan yang aman: VM lab sendiri (Metasploitable, DVWA), `localhost`, atau `scanme.nmap.org` (disediakan resmi oleh Nmap untuk uji coba ringan).

## Instalasi (Kali Linux)
```bash
sudo apt install nmap
git clone <repo-kamu>
cd reconkit
```

## Pemakaian
```bash
python3 recon.py scanme.nmap.org
python3 recon.py 192.168.56.101 --top-ports 1000 --out hasil_lab
```

Output:
- `hasil/<target>.xml` — output mentah nmap
- `hasil/<target>.md`  — laporan Markdown

## Roadmap
- [x] v0.1 — nmap → parsing XML → tabel + laporan Markdown
- [ ] v0.2 — Struktur package + unit test (pytest) untuk parser
- [ ] v0.3 — Enumerasi web otomatis (whatweb / header HTTP) jika port 80/443 terbuka
- [ ] v0.4 — Laporan HTML dengan template (Jinja2)
- [ ] v0.5 — Cek versi service terhadap database CVE
- [ ] v0.6 — Scan banyak target paralel + config file

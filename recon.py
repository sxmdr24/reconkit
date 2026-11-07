#!/usr/bin/env python3
"""
ReconKit v0.1 - Recon automation sederhana (level junior)

Alur:
  1. Jalankan nmap ke target (service/version detection)
  2. Simpan output XML
  3. Parsing XML -> daftar host, port, service
  4. Tampilkan tabel di terminal + simpan laporan Markdown

PERINGATAN: Hanya scan target milik sendiri atau yang sudah memberi izin
(lab VM, Metasploitable, localhost, atau scanme.nmap.org).
"""

import argparse
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


def cek_nmap():
    """Pastikan nmap terpasang."""
    if shutil.which("nmap") is None:
        sys.exit("[!] nmap tidak ditemukan. Install dulu: sudo apt install nmap")


def jalankan_nmap(target, xml_path, top_ports):
    """Jalankan nmap dan simpan hasil dalam format XML."""
    cmd = ["nmap", "-sV", "--top-ports", str(top_ports), "-oX", str(xml_path), target]
    print(f"[*] Menjalankan: {' '.join(cmd)}")
    hasil = subprocess.run(cmd, capture_output=True, text=True)
    if hasil.returncode != 0:
        sys.exit(f"[!] nmap gagal:\n{hasil.stderr}")
    print(f"[+] Output XML tersimpan di {xml_path}")


def parse_nmap_xml(xml_path):
    """Ubah XML nmap jadi list of dict yang gampang diolah."""
    root = ET.parse(xml_path).getroot()
    temuan = []

    for host in root.findall("host"):
        status = host.find("status").get("state")
        if status != "up":
            continue

        alamat = host.find("address").get("addr")
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else "-"

        for port in host.findall("ports/port"):
            state = port.find("state").get("state")
            if state != "open":
                continue
            svc = port.find("service")
            temuan.append({
                "host": alamat,
                "hostname": hostname,
                "port": int(port.get("portid")),
                "proto": port.get("protocol"),
                "service": svc.get("name", "?") if svc is not None else "?",
                "versi": " ".join(filter(None, [
                    svc.get("product") if svc is not None else None,
                    svc.get("version") if svc is not None else None,
                ])) or "-",
            })
    return temuan


def cetak_tabel(temuan):
    """Tampilkan hasil di terminal."""
    if not temuan:
        print("[-] Tidak ada port terbuka yang ditemukan.")
        return
    print(f"\n{'HOST':<16}{'PORT':<10}{'SERVICE':<14}VERSI")
    print("-" * 60)
    for t in temuan:
        print(f"{t['host']:<16}{str(t['port']) + '/' + t['proto']:<10}{t['service']:<14}{t['versi']}")


def tulis_laporan(target, temuan, md_path):
    """Simpan laporan dalam format Markdown."""
    waktu = datetime.now().strftime("%Y-%m-%d %H:%M")
    baris = [
        f"# Laporan Recon: {target}",
        f"Waktu scan: {waktu}  ",
        f"Total port terbuka: {len(temuan)}",
        "",
        "| Host | Port | Service | Versi |",
        "|------|------|---------|-------|",
    ]
    for t in temuan:
        baris.append(f"| {t['host']} | {t['port']}/{t['proto']} | {t['service']} | {t['versi']} |")
    md_path.write_text("\n".join(baris) + "\n", encoding="utf-8")
    print(f"\n[+] Laporan tersimpan di {md_path}")


def main():
    parser = argparse.ArgumentParser(description="ReconKit v0.1 - nmap ke laporan Markdown")
    parser.add_argument("target", help="IP / hostname / range, contoh: 192.168.56.101")
    parser.add_argument("--top-ports", type=int, default=100, help="Jumlah port teratas (default 100)")
    parser.add_argument("--out", default="hasil", help="Folder output (default: hasil)")
    args = parser.parse_args()

    cek_nmap()
    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)
    nama = args.target.replace("/", "_")
    xml_path = out_dir / f"{nama}.xml"
    md_path = out_dir / f"{nama}.md"

    jalankan_nmap(args.target, xml_path, args.top_ports)
    temuan = parse_nmap_xml(xml_path)
    cetak_tabel(temuan)
    tulis_laporan(args.target, temuan, md_path)


if __name__ == "__main__":
    main()

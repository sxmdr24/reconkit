"""Parsing nmap XML output into findings."""

import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_path):
    """Turn nmap XML into a list of dicts that is easy to work with."""
    root = ET.parse(xml_path).getroot()
    findings = []

    for host in root.findall("host"):
        status = host.find("status").get("state")
        if status != "up":
            continue

        address = host.find("address").get("addr")
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else "-"

        for port in host.findall("ports/port"):
            state = port.find("state").get("state")
            if state not in ("open", "filtered"):
                continue
            svc = port.find("service")
            findings.append({
                "host": address,
                "hostname": hostname,
                "port": int(port.get("portid")),
                "proto": port.get("protocol"),
                "state": state,
                "service": svc.get("name", "?") if svc is not None else "?",
                "version": " ".join(filter(None, [
                    svc.get("product") if svc is not None else None,
                    svc.get("version") if svc is not None else None,
                ])) or "-",
                "extra": (svc.get("extrainfo") if svc is not None else None) or "-",
            })
    return findings


def count_states(findings):
    """Count the number of open and filtered ports."""
    open_count = sum(1 for f in findings if f["state"] == "open")
    filtered_count = sum(1 for f in findings if f["state"] == "filtered")
    return open_count, filtered_count

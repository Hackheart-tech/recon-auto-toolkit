import subprocess
from datetime import datetime
import argparse

def run_nmap_scan(ip):
    print(f"[*] Scan furtif en cours sur {ip}...")
    nmap_cmd = ["nmap", "-sS", "-T2", "-Pn", "--open", "-sV", ip]
    result = subprocess.run(nmap_cmd, capture_output=True, text=True)
    return result.stdout

def run_ftp_enum(ip):
    try:
        print("[*] Test FTP anonymous...")
        ftp_script = "user anonymous\npass anonymous\nls\nbye\n"
        result = subprocess.run(["ftp", "-inv", ip], input=ftp_script, text=True, capture_output=True)
        return result.stdout
    except Exception as e:
        return f"FTP scan failed: {e}"

def run_smb_enum(ip):
    try:
        print("[*] Enum SMB...")
        result = subprocess.run(["smbclient", "-L", f"//{ip}/", "-N"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"SMB scan failed: {e}"

def run_gobuster(ip, port, proto):
    try:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        url = f"{proto}://{ip}:{port}"
        gobuster_cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-q", "--no-error"
        ]
        result = subprocess.run(gobuster_cmd, capture_output=True, text=True, timeout=60)
        return result.stdout.strip().splitlines()
    except Exception as e:
        return [f"Erreur Gobuster : {e}"]

def main():
    parser = argparse.ArgumentParser(description="🔍 Reconnaissance Web & Réseau - Red Team Script")
    parser.add_argument("--ip", required=True, help="Adresse IP cible")
    parser.add_argument("--html", action="store_true", help="Générer un rapport HTML")
    args = parser.parse_args()

    ip = args.ip
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_md = f"# Rapport de Reconnaissance\n\n"
    report_md += f"**Cible :** `{ip}`\n\n"
    report_md += f"**Date :** {timestamp}\n\n"

    # === Scan Nmap
    nmap_output = run_nmap_scan(ip)
    report_md += "## 🔍 Résultat Nmap\n\n```text\n" + nmap_output + "\n```\n"

    # === Analyse des services
    report_md += "## ⚙️ Analyse des services détectés\n"
    web_ports = []
    lines = nmap_output.splitlines()
    for line in lines:
        if "/tcp" in line and "open" in line:
            port = line.split("/")[0].strip()
            service = line.lower()

            # FTP
            if "ftp" in service:
                report_md += f"\n### 🧪 FTP ({port})\n"
                ftp_result = run_ftp_enum(ip)
                report_md += f"```text\n{ftp_result}\n```\n"

            # SMB
            elif "microsoft-ds" in service or "netbios" in service or "smb" in service:
                report_md += f"\n### 🧪 SMB ({port})\n"
                smb_result = run_smb_enum(ip)
                report_md += f"```text\n{smb_result}\n```\n"

            # HTTP
            elif "http" in service or port in ["80", "8080", "8000", "443", "8443"]:
                proto = "https" if port == "443" else "http"
                report_md += f"\n### 🧪 HTTP Gobuster ({proto} port {port})\n"
                gobuster_output = run_gobuster(ip, port, proto)
                if gobuster_output:
                    for entry in gobuster_output:
                        report_md += f"- {entry}\n"
                else:
                    report_md += "_Aucun chemin détecté._\n"

    # === Enregistrement
    filename_md = f"rapport_recon_{ip.replace('.', '_')}_{timestamp}.md"
    with open(filename_md, "w") as f:
        f.write(report_md)

    if args.html:
        filename_html = filename_md.replace(".md", ".html")
        html_content = f"<html><body><pre>{report_md}</pre></body></html>"
        with open(filename_html, "w") as f:
            f.write(html_content)
        print(f"🌐 Rapport HTML généré : {filename_html}")

    print(f"✅ Rapport Markdown généré : {filename_md}")

if __name__ == "__main__":
    main()

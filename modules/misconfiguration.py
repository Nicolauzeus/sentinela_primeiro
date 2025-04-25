import requests
from termcolor import colored
import os

def scan_misconfiguration(domain):
    print(f"Scanning {domain} for security misconfigurations...")

    # Lista de testes comuns para misconfiguração
    misconfigurations = [
        ("test", "development environment exposed"),
        ("dev", "development environment exposed"),
        ("test123", "weak test credentials"),
        ("/backup", "backup directory exposed"),
        ("/.git", ".git directory exposed"),
        ("/phpmyadmin", "phpMyAdmin exposed"),
        ("intitle:phpinfo", "PHP Info exposed"),
        ("server", "Server header leakage detected"),
        ("X-Powered-By", "Framework/Technology header leakage"),
        ("file://", "File inclusion vulnerability"),
    ]

    vulnerable = False
    report = []
    checked_urls = set()  # Set to track URLs we've already checked to avoid duplicates

    # Check each misconfiguration pattern
    for keyword, description in misconfigurations:
        # Avoid checking the same URL multiple times
        full_query = f"site:{domain} inurl:{keyword}"
        if full_query in checked_urls:
            continue  # Skip this query if already checked
        checked_urls.add(full_query)
        
        try:
            response = requests.get(f"http://{domain}/{keyword}", timeout=5)
            if response.status_code == 200:
                print(colored(f"[!] Misconfiguration detected: {description} at {domain}/{keyword}", "red"))
                report.append(f"[ALTA] {domain}/{keyword} — {description}")
                vulnerable = True
        except requests.exceptions.RequestException:
            # Skip any errors caused by invalid requests (e.g., timeout, connection error)
            continue

        # Checking for headers like X-Powered-By or Server
        if response.status_code == 200:
            headers = response.headers
            if "X-Powered-By" in headers:
                header_value = headers["X-Powered-By"]
                if f"Exposed technology: {header_value}" not in [entry for entry in report]:
                    print(colored(f"[!] Misconfiguration detected: Exposed technology {header_value} at {domain}", "red"))
                    report.append(f"[ALTA] {domain} — Exposed technology: {header_value}")
                    vulnerable = True

            if "Server" in headers:
                header_value = headers["Server"]
                if f"Exposed Server: {header_value}" not in [entry for entry in report]:
                    print(colored(f"[!] Misconfiguration detected: Server information exposed {header_value} at {domain}", "red"))
                    report.append(f"[ALTA] {domain} — Exposed Server: {header_value}")
                    vulnerable = True

    # Saving the report if vulnerabilities are found
    if vulnerable:
        salvar_relatorio(domain, report, "security_misconfigurations")
    else:
        print(colored("[-] No security misconfigurations detected.", "green"))

def salvar_relatorio(domain, report_lines, tipo):
    path = "relatorios"
    if not os.path.exists(path):
        os.makedirs(path)

    filename = os.path.join(path, f"{tipo}_{domain.replace('.', '_')}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"Relatório de {tipo.replace('_', ' ').title()}\n")
        f.write("=" * 40 + "\n\n")
        for linha in report_lines:
            f.write(linha + "\n")
    print(colored(f"[+] Relatório salvo em {filename}", "cyan"))

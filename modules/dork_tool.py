import requests
import os
from termcolor import colored
from urllib.parse import quote

API_KEY = "2f6b8d971ea6a4718f67a45de90ae49553bf1ef1"
SEARCH_URL = "https://google.serper.dev/search"

dorks = [
    "inurl:admin",
    "intitle:index.of",
    "inurl:login",
    "inurl:signup",
    "filetype:env",
    "filetype:sql",
    "filetype:log",
    "inurl:wp-content",
    "inurl:config",
    "ext:php intitle:phpinfo \"published by the PHP Group\""
]

def query_dork(dork_query):
    headers = {
        "X-API-KEY": API_KEY,
        "Content-Type": "application/json"
    }
    data = {
        "q": dork_query
    }
    response = requests.post(SEARCH_URL, json=data, headers=headers)
    if response.status_code == 200:
        return response.json().get("organic", [])
    return []

def scan_dorks(domain):
    print(f"Scanning {domain} for Google Dorks...\n")
    report = []
    found = False

    for dork in dorks:
        full_query = f"site:{domain} {dork}"
        print(f"[+] Testing: {full_query}")
        results = query_dork(full_query)

        if results:
            found = True
            for result in results:
                title = result.get("title", "No title")
                link = result.get("link", "")
                snippet = result.get("snippet", "")
                gravidade = "ALTA" if any(x in dork for x in ["filetype", "config", "sql", "env"]) else "MÉDIA"
                linha = f" - {colored(gravidade, 'red')} {link} | {title}\n   -> {snippet}"
                print(linha)
                report.append(f"[{gravidade}] {link}\n    {title}\n    {snippet}\n")

    if found:
        print(colored("[+] Vulnerabilidades de Google Dork detectadas!", "yellow"))
        salvar_relatorio(domain, report)
    else:
        print(colored("[-] No Google Dork vulnerabilities detected.", "green"))

def salvar_relatorio(domain, report_lines):
    path = "relatorios"
    if not os.path.exists(path):
        os.makedirs(path)

    filename = os.path.join(path, f"google_dorks_{domain.replace('.', '_')}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("Relatório de Google Dorks\n")
        f.write("===========================\n\n")
        for linha in report_lines:
            f.write(linha + "\n")
    print(colored(f"[+] Relatório salvo em {filename}", "cyan"))

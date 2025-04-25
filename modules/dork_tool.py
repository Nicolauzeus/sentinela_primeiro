import requests
import os
from termcolor import colored
from urllib.parse import quote

API_KEY = "2f6b8d971ea6a4718f67a45de90ae49553bf1ef1"
SEARCH_URL = "https://google.serper.dev/search"

# Lista ampliada de Google Dorks
# Dorks com maior risco aparecem primeiro
# Alguns falsos positivos comuns foram evitados

dorks = [
    "filetype:env",
    "filetype:sql",
    "filetype:log",
    "ext:php intitle:phpinfo \"published by the PHP Group\"",
    "inurl:config",
    "inurl:.git",
    "intitle:index.of passwd",
    "inurl:wp-content",
    "inurl:admin",
    "inurl:login",
    "inurl:signup",
    "inurl:dashboard",
    "inurl:panel",
    "intitle:\"Index of /private\"",
    "intitle:\"Index of /backup\"",
    "intitle:\"Index of /db\"",
    "intitle:\"Index of /config\"",
    "inurl:phpmyadmin",
    "intitle:\"phpinfo()\" \"published by the PHP Group\"",
    "inurl:credentials",
    "inurl:auth"
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

def is_false_positive(snippet):
    snippet = snippet.lower()
    falsos_positivos = ["template", "documentation", "demo", "github"]
    return any(falso in snippet for falso in falsos_positivos)

def alerta_visual(texto):
    print(colored(f"[ALERTA CRÍTICO] {texto}", "red", attrs=["bold"]))

def scan_dorks(domain):
    print(f"Scanning {domain} for Google Dorks...\n")
    report = []
    found = False
    critico_detectado = False

    for dork in dorks:
        full_query = f"site:{domain} {dork}"
        print(f"[+] Testing: {full_query}")
        results = query_dork(full_query)

        if results:
            for result in results:
                title = result.get("title", "No title")
                link = result.get("link", "")
                snippet = result.get("snippet", "")

                if is_false_positive(snippet):
                    continue

                found = True
                gravidade = "ALTA" if any(x in dork for x in ["filetype", "config", "sql", "env", "auth", ".git", "phpinfo"]) else "MÉDIA"

                linha = f" - {colored(gravidade, 'red' if gravidade == 'ALTA' else 'yellow')} {link} | {title}\n   -> {snippet}"
                print(linha)
                report.append(f"[{gravidade}] {link}\n    {title}\n    {snippet}\n")

                if gravidade == "ALTA" and not critico_detectado:
                    alerta_visual(f"Possível vazamento crítico detectado: {link}")
                    critico_detectado = True

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

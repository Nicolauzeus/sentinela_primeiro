import socket
import requests

# Chave da API do VirusTotal
VT_API_KEY = "c11a3025cf915dd454113b580a13cb4ff7973f78c771bb3f7cb0f42624f19a01"

def scan_subdomains_and_ports(domain):
    print(f"\n[+] Iniciando varredura para o domínio: {domain}")

    if "." in domain:
        subdomains = find_subdomains_virustotal(domain)
        print(f"[+] Subdomínios encontrados: {subdomains if subdomains else 'Nenhum encontrado'}")

        open_ports = scan_common_ports(domain)
        print(f"[+] Portas comuns abertas: {open_ports if open_ports else 'Nenhuma encontrada'}")
    else:
        print("[-] O domínio inserido não é válido.")

# Busca subdomínios usando a API do VirusTotal
def find_subdomains_virustotal(domain):
    print(f"[>] Consultando subdomínios via VirusTotal para: {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "x-apikey": VT_API_KEY
    }

    subdomains = []
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for entry in data.get("data", []):
                subdomain = entry["id"]
                subdomains.append(subdomain)
        else:
            print(f"[-] Erro na requisição à VirusTotal: {response.status_code}")
    except Exception as e:
        print(f"[-] Falha ao buscar subdomínios: {e}")

    return subdomains

# Escaneia as portas mais comuns usadas por pentesters e bug hunters
def scan_common_ports(domain):
    print("[>] Iniciando varredura de portas comuns...")
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 3306, 3389, 5900, 8080, 8443, 9200, 27017
    ]
    open_ports = []
    for port in common_ports:
        if check_port(domain, port):
            open_ports.append(port)
    return open_ports

# Verifica se a porta está aberta
def check_port(domain, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((domain, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

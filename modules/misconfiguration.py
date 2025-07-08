"""
Módulo de detecção de misconfigurações de segurança

Funcionalidades:
- Verifica exposição de ambientes de desenvolvimento
- Detecta diretórios sensíveis expostos
- Identifica vazamento de informações em headers HTTP
- Gera relatórios detalhados
"""

import requests
import os
import logging
from urllib.parse import urlparse, urljoin
from typing import List, Tuple, Dict

# Configuração de logging
logging.basicConfig(
    filename='misconfig_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

# Timeout para requisições (em segundos)
REQUEST_TIMEOUT = 10

# Lista de testes para misconfigurações com classificação de gravidade
MISCONFIGURATIONS: List[Tuple[str, str, str]] = [
    ("test", "Ambiente de teste exposto", "Alta"),
    ("dev", "Ambiente de desenvolvimento exposto", "Alta"),
    ("test123", "Credenciais de teste fracas", "Alta"),
    ("/backup", "Diretório de backup exposto", "Alta"),
    ("/.git", "Diretório .git exposto (pode levar a vazamento de código)", "Crítica"),
    ("/phpmyadmin", "Interface phpMyAdmin exposta", "Crítica"),
    ("/admin", "Painel administrativo exposto", "Alta"),
    ("/wp-admin", "Painel do WordPress exposto", "Média"),
    ("/server-status", "Status do servidor exposto", "Média"),
    ("/console", "Console de administração exposto", "Alta"),
    ("/debug", "Página de debug exposta", "Alta"),
    ("/env", "Variáveis de ambiente expostas", "Crítica"),
    ("/config", "Arquivos de configuração expostos", "Crítica"),
]

# Headers sensíveis que podem vazar informações
SENSITIVE_HEADERS: List[Tuple[str, str, str]] = [
    ("X-Powered-By", "Tecnologia backend exposta", "Média"),
    ("Server", "Informação do servidor exposta", "Média"),
    ("X-AspNet-Version", "Versão do ASP.NET exposta", "Alta"),
    ("X-AspNetMvc-Version", "Versão do ASP.NET MVC exposta", "Alta"),
    ("X-Debug-Token", "Token de debug exposto", "Alta"),
]

def normalize_url(domain: str) -> str:
    """
    Normaliza a URL para garantir que tenha o esquema http/https
    :param domain: Domínio a ser normalizado
    :return: URL normalizada
    """
    if not domain.startswith(('http://', 'https://')):
        return 'https://' + domain  # Preferência por HTTPS
    return domain

def check_url_access(url: str) -> bool:
    """
    Verifica se uma URL está acessível
    :param url: URL a ser verificada
    :return: True se acessível, False caso contrário
    """
    try:
        response = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True  # Verificar certificado SSL
        )
        return response.status_code == 200
    except requests.exceptions.SSLError:
        try:
            # Tentar sem verificar SSL se falhar com verificação
            response = requests.head(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False
            )
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logging.warning(f"Erro ao acessar {url}: {str(e)}")
            return False
    except requests.exceptions.RequestException as e:
        logging.warning(f"Erro ao acessar {url}: {str(e)}")
        return False

def check_headers(url: str) -> List[Dict[str, str]]:
    """
    Verifica headers HTTP sensíveis
    :param url: URL a ser verificada
    :return: Lista de vulnerabilidades encontradas nos headers
    """
    vulnerabilities = []
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=True
        )
        
        for header, description, severity in SENSITIVE_HEADERS:
            if header in response.headers:
                vuln = {
                    "tipo": "Header Exposure",
                    "gravidade": severity,
                    "detalhes": f"{description}: {header}: {response.headers[header]}",
                    "url": url
                }
                vulnerabilities.append(vuln)
                logging.info(f"Vulnerabilidade encontrada: {vuln}")
                
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao verificar headers em {url}: {str(e)}")
    
    return vulnerabilities

def scan_misconfiguration(domain: str) -> List[Dict[str, str]]:
    """
    Executa o scan de misconfigurações de segurança
    :param domain: Domínio alvo do scan
    :return: Lista de vulnerabilidades encontradas
    """
    vulnerabilities = []
    base_url = normalize_url(domain)
    
    logging.info(f"Iniciando scan de misconfigurações em {domain}")
    
    try:
        # Verificar URLs sensíveis
        for path, description, severity in MISCONFIGURATIONS:
            url = urljoin(base_url, path)
            if check_url_access(url):
                vuln = {
                    "tipo": "Exposed Resource",
                    "gravidade": severity,
                    "detalhes": f"{description} encontrado em {url}",
                    "url": url
                }
                vulnerabilities.append(vuln)
                logging.info(f"Vulnerabilidade encontrada: {vuln}")
        
        # Verificar headers HTTP
        vulnerabilities.extend(check_headers(base_url))
        
        # Verificar URL base sem path
        if check_url_access(base_url):
            vulnerabilities.extend(check_headers(base_url))
        
    except Exception as e:
        logging.error(f"Erro durante o scan em {domain}: {str(e)}")
        vulnerabilities.append({
            "tipo": "Scan Error",
            "gravidade": "Erro",
            "detalhes": f"Falha durante o scan: {str(e)}",
            "url": base_url
        })
    
    logging.info(f"Scan concluído para {domain}. Vulnerabilidades encontradas: {len(vulnerabilities)}")
    return vulnerabilities

def save_report(domain: str, vulnerabilities: List[Dict[str, str]], report_type: str) -> str:
    """
    Salva o relatório de vulnerabilidades em arquivo
    :param domain: Domínio analisado
    :param vulnerabilities: Lista de vulnerabilidades
    :param report_type: Tipo de relatório
    :return: Caminho do arquivo gerado
    """
    report_dir = "relatorios"
    os.makedirs(report_dir, exist_ok=True)
    
    safe_domain = domain.replace('.', '_').replace(':', '_')
    filename = os.path.join(report_dir, f"{report_type}_{safe_domain}.txt")
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Relatório de {report_type.replace('_', ' ').title()}\n")
            f.write(f"Domínio: {domain}\n")
            f.write(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            if not vulnerabilities:
                f.write("Nenhuma vulnerabilidade encontrada.\n")
            else:
                # Agrupar por gravidade
                by_severity = {}
                for vuln in vulnerabilities:
                    by_severity.setdefault(vuln['gravidade'], []).append(vuln)
                
                # Ordenar por gravidade (Crítica, Alta, Média, Baixa)
                for severity in ["Crítica", "Alta", "Média", "Baixa", "Informação", "Erro"]:
                    if severity in by_severity:
                        f.write(f"\n=== {severity.upper()} ===\n\n")
                        for vuln in by_severity[severity]:
                            f.write(f"[{vuln['tipo']}] {vuln['detalhes']}\n")
                            f.write(f"URL: {vuln['url']}\n\n")
        
        logging.info(f"Relatório salvo em {filename}")
        return filename
    except Exception as e:
        logging.error(f"Erro ao salvar relatório: {str(e)}")
        raise

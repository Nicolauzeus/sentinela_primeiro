def scan_sensitive_data(domain):
    print(f"Scanning {domain} for sensitive data exposure...")
    # Lógica de detecção de Sensitive Data Exposure
    # Exemplo simples de verificação:
    if "password" in domain or "secret" in domain:
        print("Sensitive data exposure detected!")
    else:
        print("No sensitive data exposure detected.")

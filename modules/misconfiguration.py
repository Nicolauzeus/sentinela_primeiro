def scan_misconfiguration(domain):
    print(f"Scanning {domain} for security misconfigurations...")
    # Lógica de detecção de Security Misconfiguration
    # Exemplo simples de verificação:
    if "test" in domain or "dev" in domain:
        print("Possible Security Misconfiguration detected!")
    else:
        print("No Security Misconfiguration detected.")

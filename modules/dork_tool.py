def scan_dorks(domain):
    print(f"Scanning {domain} for Google Dorks...")
    # Lógica de detecção de Google Dork
    # Exemplo simples de verificação:
    if "admin" in domain:
        print("Possible Google Dork vulnerability detected!")
    else:
        print("No Google Dork vulnerabilities detected.")

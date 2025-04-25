def scan_traversal(domain):
    print(f"Scanning {domain} for directory traversal vulnerabilities...")
    # Lógica de detecção de Directory Traversal
    # Exemplo simples de verificação:
    if "../" in domain:
        print("Possible Directory Traversal vulnerability detected!")
    else:
        print("No Directory Traversal vulnerabilities detected.")

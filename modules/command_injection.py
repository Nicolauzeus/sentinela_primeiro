def scan_command_injection(domain):
    print(f"Scanning {domain} for command injection vulnerabilities...")
    # Lógica de detecção de Command Injection
    # Exemplo simples de verificação:
    if "&&" in domain or ";" in domain:
        print("Possible Command Injection vulnerability detected!")
    else:
        print("No Command Injection vulnerabilities detected.")

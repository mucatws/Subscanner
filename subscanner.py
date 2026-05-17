import subprocess
import sys
import os
import re
 
ALLOWED_PORTS = {
    9050, 9150, 1080, 8080, 3128, 8081, 8888, 9999,
    *range(1081, 1251)  # 1081 to 1250 inclusive
}
 
SCAN_TIMEOUT = 300  # segundos por scan
 
# FIX: valida formato de hostname antes de passar pro nmap
def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, host))
 
def parse_open_ports(output: str) -> set[int]:
    ports = set()
    for line in output.splitlines():
        match = re.search(r'(\d+)/tcp\s+open', line)
        if match:
            ports.add(int(match.group(1)))
    return ports
 
def scan_subdomains(file_path: str, output_dir: str = "nmap_results"):  # FIX: sem espaço no nome
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
 
    with open(file_path, 'r') as f:
        # FIX: filtra linhas vazias e espaços para não passar string vazia pro nmap
        subdomains = [s.strip() for s in f.read().splitlines() if s.strip()]
 
    for subdomain in subdomains:
        # FIX: valida o hostname antes de qualquer uso
        if not is_valid_hostname(subdomain):
            print(f"[SKIP] Hostname inválido ignorado: {subdomain!r}")
            continue
 
        print(f"Scanning {subdomain}...")
 
        scan_label = "primary"
        try:
            result = subprocess.run(
                ["nmap", "-p-", subdomain],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT   # FIX: evita travar indefinidamente
            )
        except subprocess.TimeoutExpired:
            print(f"[TIMEOUT] Scan primário excedeu {SCAN_TIMEOUT}s para {subdomain}, tentando fallback...")
            result = None
 
        # Fallback se primário falhou ou deu timeout
        if result is None or result.returncode != 0:
            if result is not None:
                print(f"Primary scan failed for {subdomain}, trying fallback...")
            scan_label = "fallback"
            try:
                result = subprocess.run(
                    ["nmap", "-sS", "-Pn", "-sV", subdomain],
                    capture_output=True,
                    text=True,
                    timeout=SCAN_TIMEOUT
                )
            except subprocess.TimeoutExpired:
                print(f"[TIMEOUT] Fallback também excedeu {SCAN_TIMEOUT}s para {subdomain}, pulando.")
                continue
 
            if result.returncode != 0:
                print(f"Fallback scan also failed for {subdomain}, skipping.")
                continue
 
        # FIX: nome do arquivo indica qual scan foi usado (primary vs fallback)
        output_file = os.path.join(output_dir, f"{subdomain}_{scan_label}_scan.txt")
        with open(output_file, 'w') as out_f:
            out_f.write(result.stdout)
        print(f"Saving scan in {output_file}")
 
        open_ports = parse_open_ports(result.stdout)
 
        # FIX: consistência — reporta todas as portas abertas, e separa as permitidas
        if open_ports:
            print(f"  Todas as portas abertas em {subdomain}: {sorted(open_ports)}")
            allowed_found = open_ports & ALLOWED_PORTS
            if allowed_found:
                print(f"  Portas na lista ALLOWED em {subdomain}: {sorted(allowed_found)}")
            else:
                print(f"  Nenhuma porta da lista ALLOWED encontrada em {subdomain}")
        else:
            print(f"  Nenhuma porta aberta encontrada em {subdomain}")
 
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: python {sys.argv[0]} <arquivo_subdomains> [pasta_saida]")
        sys.exit(1)
 
    file_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "nmap_results"
 
    if not os.path.isfile(file_path):
        print(f"Erro: arquivo não encontrado: {file_path}")
        sys.exit(1)
 
    scan_subdomains(file_path, output_dir)
 

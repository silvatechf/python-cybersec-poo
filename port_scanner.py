import socket
import argparse
import sys
from datetime import datetime

class NetworkTarget:
    """Classe responsável por representar o alvo de rede e realizar as varreduras de portas."""
    
    def __init__(self, host: str, timeout: float = 0.8):
        self.host = host
        self.timeout = timeout
        self.ip = self._resolve_host()
        self.open_ports = []

    def _resolve_host(self) -> str:
        """Resolve nome de domínio para IP ou valida o IP informado."""
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            print(f"[!] ERRO: Não foi possível resolver o host '{self.host}'. Verifique o endereço.")
            sys.exit(1)

    def scan_port(self, port: int) -> bool:
        """Tenta estabelecer conexão TCP com uma porta específica (Banner Check básico)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.ip, port))
                if result == 0:
                    self.open_ports.append(port)
                    return True
        except Exception:
            pass
        return False

    def run_scan(self, ports: list):
        """Orquestra a varredura das portas fornecidas e exibe o relatório."""
        print("\n" + "=" * 50)
        print(f"[*] Iniciando Scan em : {self.host} ({self.ip})")
        print(f"[*] Horário de início : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print("=" * 50 + "\n")

        for port in ports:
            print(f" Testando porta {port:5d}...", end="\r", flush=True)
            if self.scan_port(port):
                print(f"[+] Porta {port:5d}/TCP : ABERTA ")

        print("\n" + "-" * 50)
        print(f"[*] Varredura concluída. Total de portas abertas: {len(self.open_ports)}")
        print("-" * 50 + "\n")


def parse_ports(port_input: str) -> list:
    """Converte argumentos de porta do CMD (ex: '80,443' ou '20-80') em uma lista de inteiros."""
    ports = set()
    try:
        for item in port_input.split(','):
            if '-' in item:
                start, end = map(int, item.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(item))
        return sorted(list(ports))
    except ValueError:
        print("[!] ERRO: Formato de porta inválido. Use portas separadas por vírgula (80,443) ou intervalo (20-80).")
        sys.exit(1)


def main():
    # Configuração da interface de linha de comando (CLI)
    parser = argparse.ArgumentParser(
        description="Port Scanner Orientado a Objetos - Módulo 1 (Cybersecurity CLI)"
    )
    
    parser.add_argument(
        "-t", "--target", 
        required=True, 
        help="Endereço IP ou hostname do alvo (Ex: 127.0.0.1 ou scanme.nmap.org)"
    )
    
    parser.add_argument(
        "-p", "--ports", 
        default="21,22,80,443,8080,3306", 
        help="Portas a escanear. Ex: '80,443' ou '20-100'. Padrão: portas comuns."
    )
    
    parser.add_argument(
        "--timeout", 
        type=float, 
        default=0.8, 
        help="Tempo limite de conexão por porta em segundos (Padrão: 0.8s)"
    )

    args = parser.parse_args()
    
    # Execução utilizando a classe NetworkTarget
    target_ports = parse_ports(args.ports)
    target = NetworkTarget(host=args.target, timeout=args.timeout)
    target.run_scan(target_ports)


if __name__ == "__main__":
    main()
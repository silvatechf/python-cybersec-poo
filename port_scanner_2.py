import socket
import argparse
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class NetworkTarget:
    """Classe responsável por representar o alvo de rede e realizar as varreduras de portas."""
    
    def __init__(self, host: str, timeout: float = 0.8, threads: int = 20):
        self.host = host
        self.timeout = timeout
        self.threads = threads
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
        """Tenta estabelecer conexão TCP com uma porta específica."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.ip, port))
                if result == 0:
                    self.open_ports.append(port)
                    print(f"[+] Porta {port:5d}/TCP : ABERTA")
                    return True
        except Exception:
            pass
        return False

    def run_scan(self, ports: list):
        """Orquestra a varredura concorrente utilizando ThreadPoolExecutor."""
        print("\n" + "=" * 50)
        print(f"[*] Iniciando Scan em : {self.host} ({self.ip})")
        print(f"[*] Threads ativas   : {self.threads}")
        print(f"[*] Horário de início : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print("=" * 50 + "\n")

        # Execução paralela controlada pelo número de threads
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_port, ports)

        self.open_ports.sort()
        print("\n" + "-" * 50)
        print(f"[*] Varredura concluída. Total de portas abertas: {len(self.open_ports)}")
        print(f"[*] Portas abertas encontradas: {self.open_ports}")
        print("-" * 50 + "\n")


def parse_ports(port_input: str) -> list:
    """Converte argumentos de porta do CMD em uma lista de inteiros."""
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
        print("[!] ERRO: Formato de porta inválido. Use vírgulas (80,443) ou intervalos (20-80).")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Port Scanner Multi-threaded POO - Módulo 1 (Cybersecurity CLI)"
    )
    
    parser.add_argument(
        "-t", "--target", 
        required=True, 
        help="Endereço IP ou hostname do alvo"
    )
    
    parser.add_argument(
        "-p", "--ports", 
        default="21,22,80,443,8080,3306", 
        help="Portas a escanear. Ex: '80,443' ou '1-1024'."
    )
    
    parser.add_argument(
        "--timeout", 
        type=float, 
        default=0.8, 
        help="Timeout por conexão em segundos (Padrão: 0.8s)"
    )

    parser.add_argument(
        "-w", "--workers", 
        type=int, 
        default=30, 
        help="Número de threads simultâneas (Padrão: 30)"
    )

    args = parser.parse_args()
    
    target_ports = parse_ports(args.ports)
    target = NetworkTarget(host=args.target, timeout=args.timeout, threads=args.workers)
    target.run_scan(target_ports)


if __name__ == "__main__":
    main()
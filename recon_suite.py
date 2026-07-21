import socket
import argparse
import sys
import urllib.request
import urllib.error
from datetime import datetime
import ssl

# =====================================================================
# CLASSE BASE (PAI) - Herança
# =====================================================================
class BaseScanner:
    """
    Classe base para todos os scanners da suíte de recon.
    Define a estrutura padrão que toda verificação deve seguir.
    """
    def __init__(self, target: str):
        # Normaliza o alvo removendo esquemas de URL
        self.target = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.results = {}
        self.timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    def resolve_target(self) -> str:
        """Método utilitário compartilhado por todas as classes filhas."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return "Não resolvido"

    def scan(self):
        """
        Método abstrato que DEVE ser sobrescrito pelas classes filhas.
        Isso é a base do Polimorfismo.
        """
        raise NotImplementedError("As classes filhas devem implementar o método scan().")

    def print_report(self):
        """Exibe o relatório formatado com os dados coletados."""
        print("\n" + "=" * 60)
        print(f"[*] RELATÓRIO DE RECON: {self.__class__.__name__}")
        print(f"[*] Alvo       : {self.target}")
        print(f"[*] Data/Hora  : {self.timestamp}")
        print("=" * 60)
        for key, value in self.results.items():
            print(f"  [>] {key:25s}: {value}")
        print("=" * 60 + "\n")


# =====================================================================
# CLASSES FILHAS - Polimorfismo e Especialização
# =====================================================================

class DNSScanner(BaseScanner):
    """Scanner de registros e resoluções DNS (Herda de BaseScanner)."""

    def scan(self):
        """Sobrescreve o método scan() com a lógica específica de DNS."""
        print(f"[*] [DNSScanner] Consultando registros para {self.target}...")
        
        ip = self.resolve_target()
        self.results["IPv4 Principal"] = ip

        # Tenta resolução reversa (PTR)
        if ip != "Não resolvido":
            try:
                reverse_name, _, _ = socket.gethostbyaddr(ip)
                self.results["Reverse DNS (PTR)"] = reverse_name
            except (socket.herror, socket.gaierror):
                self.results["Reverse DNS (PTR)"] = "Não encontrado / Bloqueado"
        else:
            self.results["Reverse DNS (PTR)"] = "Impossível (IP não resolvido)"


class SSLScanner(BaseScanner):
    """Scanner para validação e inspeção de Certificados SSL/TLS (Herda de BaseScanner)."""

    def scan(self):
        """Sobrescreve o método scan() para obter informações do certificado SSL."""
        print(f"[*] [SSLScanner] Inspecionando certificado SSL/TLS de {self.target}...")

        context = ssl.create_default_context()

        try:
            # Estabelece conexão com a porta HTTPS padrão (443)
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()

                    # Extrai a entidade emissora (Issuer) e o proprietário (Subject)
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))

                    self.results["Emissor (CN)"] = issuer.get('commonName', 'N/A')
                    self.results["Organização Emissora"] = issuer.get('organizationName', 'N/A')
                    self.results["Titular (CN)"] = subject.get('commonName', 'N/A')
                    self.results["Válido Desde"] = cert.get('notBefore', 'N/A')
                    self.results["Válido Até"] = cert.get('notAfter', 'N/A')
                    self.results["Versão SSL/TLS"] = ssock.version()

        except socket.timeout:
            self.results["Erro SSL"] = "Timeout de conexão na porta 443"
        except ssl.SSLError as e:
            self.results["Erro SSL"] = f"Falha de Certificado/Handshake ({e.reason})"
        except Exception as e:
            self.results["Erro SSL"] = f"Não foi possível obter o certificado ({str(e)})"


class HTTPHeaderScanner(BaseScanner):
    """Scanner de Headers de Segurança HTTP/HTTPS (Herda de BaseScanner)."""

    def scan(self):
        """Sobrescreve o método scan() com a lógica de análise de cabeçalhos HTTP."""
        print(f"[*] [HTTPHeaderScanner] Analisando headers HTTP de {self.target}...")
        
        url = f"https://{self.target}"
        
        headers_to_check = [
            "Server",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]

        try:
            req = urllib.request.Request(
                url, 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberCLI-Recon/1.0'}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                resp_headers = response.info()
                self.results["Status HTTP"] = f"{response.status} {response.reason}"
                
                for header in headers_to_check:
                    val = resp_headers.get(header)
                    if val:
                        self.results[header] = val
                    else:
                        self.results[header] = "MISSING (Risco de Segurança)"

        except urllib.error.HTTPError as e:
            self.results["Status HTTP"] = f"Erro HTTP {e.code}"
        except urllib.error.URLError as e:
            self.results["Erro Conexão"] = f"Falha ao conectar em {url} ({e.reason})"


# =====================================================================
# GERENCIADOR DA SUÍTE (Orquestrador)
# =====================================================================
class ReconSuite:
    """Orquestrador polimórfico que gerencia todos os scanners."""

    def __init__(self, target: str):
        self.target = target
        self.scanners: list[BaseScanner] = [
            DNSScanner(self.target),
            HTTPHeaderScanner(self.target),
            SSLScanner(self.target)
        ]

    def run_all(self):
        """Executa todos os scanners em sequência através de Polimorfismo."""
        print(f"\n[🚀] INICIANDO SUÍTE COMPLETA DE RECON EM: {self.target}")
        for scanner in self.scanners:
            scanner.scan()
            scanner.print_report()


# =====================================================================
# CLI - Interface de Linha de Comando
# =====================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Suíte de Reconhecimento POO - Módulo 3 (Cybersecurity CLI)"
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Alvo para recon (Ex: scanme.nmap.org ou google.com)"
    )

    parser.add_argument(
        "-m", "--mode",
        choices=["dns", "http", "ssl", "all"],
        default="all",
        help="Modo de varredura: 'dns', 'http', 'ssl' ou 'all' (Padrão: all)"
    )

    args = parser.parse_args()

    if args.mode == "dns":
        scanner = DNSScanner(args.target)
        scanner.scan()
        scanner.print_report()
    elif args.mode == "http":
        scanner = HTTPHeaderScanner(args.target)
        scanner.scan()
        scanner.print_report()
    elif args.mode == "ssl":
        scanner = SSLScanner(args.target)
        scanner.scan()
        scanner.print_report()
    else:
        suite = ReconSuite(args.target)
        suite.run_all()


if __name__ == "__main__":
    main()
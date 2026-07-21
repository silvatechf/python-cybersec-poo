import hashlib
import os
import argparse
import sys
import time
from datetime import datetime

class FileIntegrityVault:
    """
    Classe responsável por monitorar e validar a integridade de arquivos utilizando SHA-256.
    Aplica o conceito de Encapsulamento para proteger o hash de referência contra modificações externas.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        # Atributos PRIVADOS: A baseline é gravada na criação do objeto na memória
        self.__original_hash = self._calculate_hash()
        self.__created_at = datetime.now()

    @property
    def original_hash(self) -> str:
        """Expõe o hash de referência apenas para LEITURA."""
        return self.__original_hash

    @property
    def created_at(self) -> str:
        """Retorna o momento em que a linha de base (baseline) foi registrada."""
        return self.__created_at.strftime("%d/%m/%Y %H:%M:%S")

    def _calculate_hash(self) -> str:
        """Método protegido para leitura em chunks de 64KB."""
        if not os.path.isfile(self.filepath):
            print(f"[!] ERRO: O arquivo '{self.filepath}' não foi encontrado.")
            sys.exit(1)

        sha256 = hashlib.sha256()
        try:
            with open(self.filepath, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except PermissionError:
            print(f"[!] ERRO: Sem permissão de leitura no arquivo '{self.filepath}'.")
            sys.exit(1)

    def verify(self) -> bool:
        """Recalcula o hash atual do arquivo e compara com o hash registrado na criação do objeto."""
        current_hash = self._calculate_hash()
        is_intact = (current_hash == self.__original_hash)

        print("\n" + "=" * 65)
        print(f"[*] AUDITORIA DE INTEGRIDADE: {os.path.basename(self.filepath)}")
        print("=" * 65)
        print(f"[*] Caminho Completo   : {os.path.abspath(self.filepath)}")
        print(f"[*] Hash da Baseline   : {self.__original_hash}")
        print(f"[*] Hash Atual         : {current_hash}")
        print("-" * 65)

        if is_intact:
            print("[✓] STATUS: INTEGRO (Nenhuma modificação detectada)")
        else:
            print("[✘] ALERTA DE SEGURANÇA: ARQUIVO VIOLADO/MODIFICADO!")

        print("=" * 65 + "\n")
        return is_intact

    def start_monitoring(self, interval: int = 2):
        """Monitora o arquivo em tempo real em um loop contínuo."""
        print(f"\n[+] Iniciando Monitoramento em Tempo Real (FIM)")
        print(f"[+] Arquivo: {self.filepath}")
        print(f"[+] Baseline SHA-256: {self.__original_hash}")
        print(f"[+] Pressione CTRL+C para interromper.\n")

        try:
            while True:
                time.sleep(interval)
                current_hash = self._calculate_hash()
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if current_hash == self.__original_hash:
                    print(f"[{timestamp}] [✓] {self.filepath} OK")
                else:
                    print(f"\n[{timestamp}] [✘] ALERTA CRÍTICO: {self.filepath} FOI ALTERADO!")
                    print(f"    -> Hash Original : {self.__original_hash}")
                    print(f"    -> Hash Atual    : {current_hash}\n")
        except KeyboardInterrupt:
            print("\n[*] Monitoramento finalizado pelo usuário.")


def main():
    parser = argparse.ArgumentParser(
        description="Hash Vault & Verificador de Integridade - Módulo 2 (Cybersecurity CLI)"
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Caminho do arquivo para monitorar ou verificar"
    )

    parser.add_argument(
        "-w", "--watch",
        action="store_true",
        help="Ativa o modo de monitoramento contínuo em tempo real"
    )

    args = parser.parse_args()

    vault = FileIntegrityVault(filepath=args.file)
    
    if args.watch:
        vault.start_monitoring(interval=2)
    else:
        vault.verify()


if __name__ == "__main__":
    main()
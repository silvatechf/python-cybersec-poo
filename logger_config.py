import logging
import re
import sys

# 1. Configuração do Logger
logger = logging.getLogger("SecurityAudit")
logger.setLevel(logging.DEBUG)

# Formato do Log: Data/Hora - Nome - Nível - Mensagem
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Handler para arquivo
file_handler = logging.FileHandler("audit.log", encoding="utf-8")
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

# atencion en esta parte

# Handler para o console (terminal)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.DEBUG)

# Adiciona os handlers ao logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)


# 2. Definindo Exceção Customizada
class InvalidTargetError(Exception):
    """Exceção para validação de alvos."""
    pass


# 3. Classe de Exemplo
class TargetValidator:
    @staticmethod
    def validate(target: str) -> bool:
        logger.debug(f"Iniciando validação do alvo: {target}")
        
        # Regex simples para validar IP ou hostname/domínio básico
        domain_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        ip_regex = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        
        if not (re.match(domain_regex, target) or re.match(ip_regex, target)):
            logger.error(f"Falha na validação do alvo: {target}")
            raise InvalidTargetError(f"O alvo '{target}' não é um IP ou FQDN válido.")
            
        logger.info(f"Alvo validado com sucesso: {target}")
        return True


# 4. Execução e Tratamento
if __name__ == "__main__":
    targets = ["scanme.nmap.org", "192.168.1.1", "alvo_invalido_#$"]

    for t in targets:
        try:
            TargetValidator.validate(t)
        except InvalidTargetError as e:
            logger.warning(f"Exceção capturada no fluxo principal: {e}")

def setup_logger(name: str = "SecuritySuite", log_file: str = "security_audit.log") -> logging.Logger:
    """
    Cria e retorna uma instância configurada de Logger.
    
    :param name: Nome do módulo/contexto do logger.
    :param log_file: Caminho do arquivo onde os logs serão salvos.
    :return: Objeto logging.Logger pronto para uso.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Evita duplicação de handlers se a função for chamada mais de uma vez
    if logger.hasHandlers():
        return logger

    # Formato padronizado: Data/Hora - Contexto - Nível - Mensagem
    formatter = logging.Formatter(
        '%(asctime)s - [%(name)s] - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Handler 1: Gravação em Arquivo (Nível INFO e acima)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Handler 2: Exibição no Console / Terminal (Nível DEBUG e acima)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)

    # Adiciona os handlers ao logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
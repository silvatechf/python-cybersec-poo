"""
Script de Teste de Integração - Módulo 4
Valida o lançamento de exceções personalizadas e o registro de logs.
"""

import re
from custom_exceptions import InvalidTargetError, TargetUnreachableError
from logger_config import setup_logger

# Inicializa o logger para o teste
logger = setup_logger("Module4Test")


def validate_target_format(target: str) -> bool:
    """Valida a sintaxe básica do IP ou domínio."""
    logger.debug(f"Analisando sintaxe do alvo: {target}")
    
    domain_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    ip_regex = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    if not (re.match(domain_regex, target) or re.match(ip_regex, target)):
        raise InvalidTargetError(target, "Sintaxe incorreta para IP/Hostname")
        
    return True


def simulate_audit_process(target: str, port: int):
    """Simula uma operação de auditoria e validação de erros."""
    logger.info(f"Iniciando procedimento de teste em {target}:{port}")
    
    # 1. Validação de Formato
    validate_target_format(target)
    
    # 2. Simulação de falha de conexão para portas específicas
    if port == 9999:
        raise TargetUnreachableError(target, port)
        
    logger.info(f"Procedimento em {target}:{port} concluído com sucesso!")


def run_tests():
    logger.info("=== INICIANDO BATERIA DE TESTES DO MÓDULO 4 ===")
    
    test_cases = [
        ("127.0.0.1", 80),          # Válido
        ("alvo_invalido_!@#", 80),  # Dispara InvalidTargetError
        ("192.168.1.100", 9999),    # Dispara TargetUnreachableError
    ]
    
    for target, port in test_cases:
        try:
            simulate_audit_process(target, port)
        except InvalidTargetError as e:
            logger.error(f"Erro de Validação Capturado: {e}")
        except TargetUnreachableError as e:
            logger.warning(f"Erro de Conectividade Capturado: {e}")
        except Exception as e:
            logger.critical(f"Erro não esperado: {e}", exc_info=True)
            
    logger.info("=== BATERIA DE TESTES FINALIZADA ===")


if __name__ == "__main__":
    run_tests()
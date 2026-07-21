
"""
Módulo de Exceções Personalizadas (Custom Exceptions)
"""

class SecurityToolError(Exception):
    """Classe base para todas as exceções da suíte de ferramentas de segurança."""
    pass


class InvalidTargetError(SecurityToolError):
    """Lançada quando o formato do IP ou domínio/FQDN fornecido é inválido."""
    def __init__(self, target: str, message: str = "Formato de alvo inválido"):
        self.target = target
        self.message = f"[{target}] {message}"
        super().__init__(self.message)


class TargetUnreachableError(SecurityToolError):
    """Lançada quando o host/alvo não responde a tempo ou está inacessível."""
    def __init__(self, target: str, port: int = None):
        self.target = target
        self.port = port
        msg = f"Inacessível: {target}" + (f" na porta {port}" if port else "")
        super().__init__(msg)


class ConfigurationError(SecurityToolError):
    """Lançada quando faltam parâmetros essenciais de configuração."""
    pass
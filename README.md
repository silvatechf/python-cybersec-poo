# Python Security & POO - Material de Estudos

Este repositório contém uma suíte de ferramentas CLI desenvolvidas em Python para consolidação de conceitos de **Programação Orientada a Objetos (POO)** aplicados à automação de segurança defensiva e auditoria.

## 📌 Módulos Desenvolvidos

1. **Escaneamento de Portas (`port_scanner.py`)**:
   - Aplicação de conceitos de Métodos, Atributos e Encapsulamento.
2. **Monitoramento de Integridade (`file_vault.py`)**:
   - Uso de hashes SHA-256 para File Integrity Monitoring (FIM).
3. **Suíte de Reconhecimento (`recon_suite.py`)**:
   - Implementação de **Herança** e **Polimorfismo** com scanners de DNS, Headers HTTP e SSL/TLS.

## 🚀 Como Executar

```bash
# Testar a Suíte de Recon
python recon_suite.py -t scanme.nmap.org -m all

# Testar o Scanner de Portas
python port_scanner.py
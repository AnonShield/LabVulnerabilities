# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Adicionado
- Biblioteca comum de funções (`lib/common.sh`) para eliminar duplicação de código
- Arquivo `.env.example` para configuração de credenciais
- Validação de IPs no scanner Python
- Validação de serviços no comando `start`
- Tratamento de sinais (trap) para cleanup gracioso
- Documentação CONTRIBUTING.md com guia de contribuição
- Contador de sucesso/falha no comando `start`

### Corrigido
- Bug no `openvas_scanner.py` onde `downloaded = True` deveria ser lista
- Caracteres corrompidos (encoding) no `scan_manager.sh`
- Docstring mal posicionada na classe Config do scanner

### Melhorado
- Script `generate_compose.py` com shebang, docstrings e CLI completa
- `.gitignore` reorganizado e expandido com suporte a `.env`
- Comentários e documentação em `config.yaml`
- Estrutura dos scripts Bash para usar biblioteca comum

---

## [1.0.0] - 2026-01-XX

### Adicionado
- 149 containers Docker vulneráveis em 11 categorias
- Script `lab.sh` para gerenciamento unificado
- Módulo de scanner OpenVAS automatizado
- Orquestrador de scans sequenciais (`scan_manager.sh`)
- Documentação completa em README.md
- Suporte a Docker Compose v1 e v2
- Rede isolada `vulnnet` (172.30.0.0/15)
- Binding em localhost para segurança
- Exportação de alvos para scanners externos
- Logs por serviço em caso de falha

### Categorias de Containers
- Aplicações Web Vulneráveis (OWASP/CTF): 18 containers
- CVEs Específicas: 5 containers (Log4Shell, SambaCry, Ghostcat, etc.)
- CMS e Plataformas Web: 14 containers
- Bancos de Dados: 16 containers
- Servidores Web e Application Servers: 17 containers
- DevOps e CI/CD: 9 containers
- Mensageria e Streaming: 8 containers
- Monitoramento e Logging: 12 containers
- Serviços de Rede e Infraestrutura: 31 containers
- Linguagens e Runtimes: 12 containers
- Sistemas Operacionais Base: 8 containers

---

## Tipos de Mudanças

- **Adicionado** - para novas funcionalidades
- **Alterado** - para mudanças em funcionalidades existentes
- **Obsoleto** - para funcionalidades que serão removidas
- **Removido** - para funcionalidades removidas
- **Corrigido** - para correções de bugs
- **Segurança** - para correções de vulnerabilidades

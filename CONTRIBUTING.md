# Guia de Contribuição - VulnLab

Obrigado por considerar contribuir com o VulnLab! Este documento fornece diretrizes e boas práticas para contribuições.

## Sumário

- [Código de Conduta](#código-de-conduta)
- [Como Contribuir](#como-contribuir)
- [Padrões de Código](#padrões-de-código)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Adicionando Novos Containers](#adicionando-novos-containers)
- [Testes](#testes)
- [Processo de Review](#processo-de-review)

---

## Código de Conduta

Este projeto segue princípios de respeito mútuo e colaboração construtiva. Esperamos que todos os contribuidores:

- Sejam respeitosos e inclusivos
- Aceitem críticas construtivas
- Foquem no que é melhor para a comunidade
- Mantenham comunicação profissional

---

## Como Contribuir

### 1. Reportando Bugs

Antes de reportar um bug:

1. Verifique se já não existe uma issue aberta
2. Tente reproduzir o problema em uma instalação limpa
3. Colete informações relevantes (versão do Docker, SO, logs)

Ao criar a issue, inclua:

- Descrição clara do problema
- Passos para reproduzir
- Comportamento esperado vs. atual
- Logs relevantes
- Ambiente (SO, versões)

### 2. Sugerindo Melhorias

Para sugestões de melhorias:

1. Verifique se já não existe uma issue similar
2. Descreva claramente a melhoria proposta
3. Explique o benefício para o projeto
4. Se possível, sugira uma implementação

### 3. Pull Requests

#### Processo

1. Fork o repositório
2. Crie uma branch para sua feature: `git checkout -b feature/nova-funcionalidade`
3. Faça commits atômicos e descritivos
4. Atualize a documentação se necessário
5. Teste suas alterações
6. Abra um Pull Request

#### Convenções de Commits

Use mensagens de commit claras e descritivas:

```
tipo(escopo): descrição breve

Corpo opcional com mais detalhes.

Refs: #123
```

**Tipos:**
- `feat`: Nova funcionalidade
- `fix`: Correção de bug
- `docs`: Alterações na documentação
- `style`: Formatação (não afeta código)
- `refactor`: Refatoração de código
- `test`: Adição ou correção de testes
- `chore`: Tarefas de manutenção

**Exemplos:**
```
feat(scanner): adiciona suporte a múltiplos formatos de relatório
fix(lab): corrige parsing de IPs no comando ips
docs(readme): atualiza seção de instalação
```

---

## Padrões de Código

### Bash Scripts

- Use `#!/bin/bash` como shebang
- Inclua `set -e` para falhar em erros
- Use a biblioteca comum `lib/common.sh`
- Prefira variáveis com nomes em MAIÚSCULAS
- Documente funções com comentários
- Use `shellcheck` para validação

```bash
#!/bin/bash
set -e

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# Descrição da função
# Args:
#   $1 - Primeiro argumento
minha_funcao() {
    local arg1="$1"
    # implementação
}
```

### Python

- Siga PEP 8
- Use type hints
- Documente funções com docstrings (Google style)
- Mantenha funções pequenas e focadas
- Use logging em vez de print

```python
def minha_funcao(param: str) -> bool:
    """
    Descrição breve da função.

    Args:
        param: Descrição do parâmetro.

    Returns:
        Descrição do retorno.

    Raises:
        ValueError: Quando param é inválido.
    """
    pass
```

### Docker Compose

- Use versão 3.8
- Mantenha binding em `127.0.0.1` para todas as portas
- Use nomes descritivos para services
- Documente CVEs conhecidas nos comentários
- Organize services por categoria

---

## Estrutura do Projeto

```
trabalho/
├── lab.sh                 # Script principal de orquestração
├── docker-compose.yml     # Definição dos containers
├── lib/
│   └── common.sh          # Biblioteca comum de funções
├── scanner/
│   ├── openvas_scanner.py # Scanner principal
│   ├── run.sh             # Wrapper do scanner
│   └── config.yaml        # Configuração
├── scripts/
│   └── generate_compose.py # Utilitários
├── docs/
│   └── ...                # Documentação adicional
└── README.md              # Documentação principal
```

---

## Adicionando Novos Containers

### Checklist

Antes de adicionar um novo container vulnerável:

- [ ] Verifique se não duplica um existente
- [ ] Confirme que a imagem está disponível no Docker Hub
- [ ] Documente as vulnerabilidades conhecidas
- [ ] Teste localmente
- [ ] Atualize a documentação

### Template

Adicione ao `docker-compose.yml`:

```yaml
  # CATEGORIA: Nome do Serviço
  # Vulnerabilidades: CVE-XXXX-YYYY, CVE-ZZZZ-WWWW
  nome-servico:
    image: imagem:versao
    container_name: nome-servico
    networks:
      vulnnet:
        ipv4_address: 172.30.X.Y
    ports:
      - 127.0.0.1:PORTA_HOST:PORTA_CONTAINER
    environment:
      - VARIAVEL=valor
```

### Atualize o README

Adicione uma entrada na seção apropriada do catálogo:

| Serviço | Imagem | IP | Porta | Vulnerabilidades |
|---------|--------|-----|-------|------------------|
| `nome-servico` | `imagem:versao` | `172.30.X.Y` | `PORTA:PORTA` | CVE-XXXX-YYYY |

---

## Testes

### Testes Manuais

Antes de submeter um PR:

1. **Sintaxe do Compose:**
   ```bash
   docker-compose config
   ```

2. **Inicialização:**
   ```bash
   ./lab.sh start nome-servico
   ./lab.sh status
   ```

3. **Conectividade:**
   ```bash
   ./lab.sh ips | grep nome-servico
   curl http://127.0.0.1:PORTA
   ```

4. **Scripts Bash:**
   ```bash
   shellcheck lab.sh scanner/*.sh
   ```

5. **Scripts Python:**
   ```bash
   python -m py_compile scanner/openvas_scanner.py
   ```

---

## Processo de Review

### O que os revisores verificam

1. **Funcionalidade:** O código faz o que deveria?
2. **Segurança:** Segue as práticas de segurança (binding localhost, etc.)?
3. **Qualidade:** Código limpo, documentado, sem duplicação?
4. **Testes:** Foi testado localmente?
5. **Documentação:** README atualizado se necessário?

### Tempo de Review

- PRs simples: 1-3 dias
- PRs complexos: 3-7 dias

---

## Dúvidas?

Se tiver dúvidas sobre como contribuir, abra uma issue com a tag `question` ou entre em contato com os mantenedores.

Agradecemos sua contribuição!

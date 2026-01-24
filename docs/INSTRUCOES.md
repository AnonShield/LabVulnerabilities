# 📄 INSTRUÇÕES FINAIS - LABORATÓRIO DE SCAN DE VULNERABILIDADES (v2)

Este documento resume o processo de configuração do laboratório de scan e a solução final, agora consolidada em scripts mais robustos e automáticos.

## 1. Resumo do Processo e Desafios

O objetivo era iniciar um laboratório de mais de 100 aplicações vulneráveis e escaneá-las com o OpenVAS. O processo inicial encontrou diversos problemas, como falhas no `docker-compose`, imagens de contêineres desatualizadas, incompatibilidade de bibliotecas de automação (`gvm-tools`) e problemas de conectividade de rede entre o scanner e os alvos.

A solução final contorna todos esses problemas de forma resiliente.

## 2. Solução Implementada

1.  **Bypass do `docker-compose`:** Um script Python (`build_and_run_lab.py`) agora orquestra a inicialização. Ele primeiro verifica quais imagens Docker estão indisponíveis e, em seguida, gera um script (`run_containers.sh`) que inicia cada contêiner funcional individualmente com `docker run`.
2.  **Resiliência a Falhas:** O script `run_containers.sh` gerado é resiliente. Se um contêiner individual falhar ao iniciar, ele reportará o erro, mas continuará a iniciar os outros, garantindo que o máximo possível do laboratório fique online.
3.  **Conexão de Rede Automática:** A solução para a detecção de alvos (`docker network connect`) foi incorporada no script principal de inicialização.
4.  **Scan Manual:** A automação do *início* do scan permanece um desafio de compatibilidade. Portanto, a abordagem mais confiável é iniciar o scan manualmente pela interface web do OpenVAS, que já se provou funcional.

## 3. Como Usar o Laboratório (Versão Final)

O processo foi simplificado em dois scripts principais.

### Passo 1: Iniciar o Contêiner do OpenVAS

Este passo só precisa ser executado uma vez, ou se o contêiner do OpenVAS for parado. Ele inicia o scanner e expõe as portas necessárias.

```bash
# Este comando puxará a imagem mais recente e iniciará o contêiner
docker run --detach --pull always --publish 8080:9392 --publish 9390:9390 \
  -e PASSWORD="Tr4mpp0Sup3rS3cur3P4ssw0rd!" \
  -e SKIPSYNC=true \
  --volume openvas:/data --name openvas immauss/openvas
```

### Passo 2: Iniciar o Laboratório de Alvos

Este é o novo comando principal para iniciar/reiniciar o laboratório.

```bash
# Navegue para a pasta 'trabalho' se ainda não estiver nela
cd trabalho

# Execute o script de inicialização principal
./start_lab_full.sh
```

O que este script faz:
1.  Garante que a rede `trabalho_vulnnet` exista.
2.  Conecta o contêiner `openvas` a essa rede.
3.  Executa o script `build_and_run_lab.py` para gerar um `run_containers.sh` atualizado e resiliente.
4.  Executa o `run_containers.sh` para iniciar todos os contêineres funcionais.

### Passo 3: Sincronizar Feeds e Realizar o Scan

Estes passos permanecem manuais para garantir a confiabilidade.

1.  **Sincronizar Feeds (Opcional, mas recomendado):**
    ```bash
    docker exec openvas /scripts/sync.sh
    ```
    *(Lembre-se que este processo pode levar horas. Monitore com `docker logs -f openvas`)*

2.  **Realizar o Scan Manualmente:**
    *   **Acesse:** `http://localhost:8080`
    *   **Login:** `admin` / `Tr4mpp0Sup3rS3cur3P4ssw0rd!`
    *   **Crie/Edite o Alvo:** Em `Configuration -> Targets`, certifique-se de que os hosts (do `trabalho/targets.txt`) estão corretos e que o **"Alive Test"** está como **"Consider Alive"**.
    *   **Inicie a Tarefa:** Em `Scans -> Tasks`, inicie a tarefa com a configuração "Full and Fast".
    *   **Visualize os Resultados:** No relatório final, mude o filtro para **`min_qod=0`** para ver todas as vulnerabilidades.

---
A automação e a documentação estão agora completas. O laboratório está mais fácil de gerenciar e mais robusto contra falhas.
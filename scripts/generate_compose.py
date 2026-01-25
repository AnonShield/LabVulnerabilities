#!/usr/bin/env python3
"""
VulnLab - Gerador de Docker Compose

Este script analisa arquivos Markdown contendo comandos `docker run` e gera
um arquivo docker-compose.yml correspondente.

Uso:
    python generate_compose.py [--input FILE] [--output FILE] [--subnet CIDR]

Exemplo:
    python generate_compose.py --input ../docs/adicional/containers_adicionais.md

Autor: VulnLab Project
Versão: 1.1.0
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:
    print("Erro: PyYAML não instalado. Execute: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def parse_docker_run_command(command_line: str) -> dict[str, Any]:
    """
    Analisa um comando 'docker run' e extrai as configurações do serviço.

    Args:
        command_line: String contendo o comando docker run completo.

    Returns:
        Dicionário com as configurações do serviço para docker-compose.

    Example:
        >>> parse_docker_run_command("docker run -d -p 8080:80 --name web nginx:1.19")
        {'ports': ['8080:80'], 'container_name': 'web', 'image': 'nginx:1.19'}
    """
    parts = command_line.split()
    service_def: dict[str, Any] = {}

    i = 0
    while i < len(parts):
        part = parts[i]

        if part == '-d':
            # Flag de detached, ignoramos
            pass

        elif part == '-p':
            # Mapeamento de portas
            i += 1
            if i < len(parts):
                if 'ports' not in service_def:
                    service_def['ports'] = []
                # Adiciona binding localhost para segurança
                port_mapping = parts[i]
                if ':' in port_mapping and not port_mapping.startswith('127.0.0.1:'):
                    port_mapping = f"127.0.0.1:{port_mapping}"
                service_def['ports'].append(port_mapping)

        elif part == '--name':
            # Nome do container
            i += 1
            if i < len(parts):
                service_def['container_name'] = parts[i]

        elif part == '-e':
            # Variáveis de ambiente
            i += 1
            if i < len(parts):
                if 'environment' not in service_def:
                    service_def['environment'] = []
                service_def['environment'].append(parts[i])

        elif part == '-v':
            # Volumes
            i += 1
            if i < len(parts):
                if 'volumes' not in service_def:
                    service_def['volumes'] = []
                service_def['volumes'].append(parts[i])

        elif part == '--network':
            # Rede (ignoramos, usaremos vulnnet)
            i += 1

        elif _is_image_name(part):
            # Provavelmente é a imagem
            if 'image' not in service_def:
                service_def['image'] = part

        i += 1

    # Se não encontrou imagem, tenta no final do comando
    if 'image' not in service_def:
        for part in reversed(parts):
            if _is_image_name(part) and part not in ['-d', '-p', '-e', '-v', '--name', '--network']:
                service_def['image'] = part
                break

    return service_def


def _is_image_name(text: str) -> bool:
    """
    Verifica se o texto parece ser um nome de imagem Docker.

    Args:
        text: String para verificar.

    Returns:
        True se parece ser uma imagem Docker.
    """
    # Imagens geralmente contêm / ou : e não começam com -
    if text.startswith('-'):
        return False
    if '/' in text or ':' in text:
        return True
    # Imagens oficiais sem tag (ex: nginx, mysql)
    if text.isalnum() and len(text) > 2:
        return True
    return False


def extract_docker_commands(content: str) -> list[str]:
    """
    Extrai comandos 'docker run' de um conteúdo Markdown.

    Args:
        content: Conteúdo do arquivo Markdown.

    Returns:
        Lista de comandos docker run encontrados.
    """
    # Padrão para capturar comandos docker run entre backticks ou em blocos de código
    pattern = r'`(docker run [^`]+)`|```(?:bash|sh)?\s*(docker run [^`]+?)```'
    matches = re.findall(pattern, content, re.DOTALL)

    commands = []
    for match in matches:
        cmd = match[0] or match[1]
        # Limpa quebras de linha e espaços extras
        cmd = ' '.join(cmd.split())
        if cmd:
            commands.append(cmd)

    return commands


def generate_compose(
    commands: list[str],
    start_subnet: int = 31,
    start_host: int = 1,
    network_name: str = "vulnnet",
    base_subnet: str = "172.30.0.0/15"
) -> dict[str, Any]:
    """
    Gera estrutura docker-compose a partir de comandos docker run.

    Args:
        commands: Lista de comandos docker run.
        start_subnet: Terceiro octeto inicial do IP.
        start_host: Quarto octeto inicial do IP.
        network_name: Nome da rede Docker.
        base_subnet: CIDR da subnet.

    Returns:
        Dicionário com a estrutura do docker-compose.
    """
    services = {}
    ip_subnet = start_subnet
    ip_host = start_host

    for command in commands:
        try:
            service_def = parse_docker_run_command(command)

            if 'container_name' not in service_def:
                logger.warning(f"Comando sem --name ignorado: {command[:50]}...")
                continue

            if 'image' not in service_def:
                logger.warning(f"Comando sem imagem ignorado: {command[:50]}...")
                continue

            service_name = service_def['container_name']

            # Atribui IP
            ip_address = f'172.{ip_subnet}.{ip_host // 256}.{ip_host % 256}'
            ip_host += 1
            if ip_host > 65534:  # Máximo de hosts no /16
                logger.warning("Limite de IPs atingido")
                break

            service_def['networks'] = {network_name: {'ipv4_address': ip_address}}

            # Usa o nome do container como chave do serviço
            services[service_name] = service_def
            logger.info(f"Serviço adicionado: {service_name} -> {ip_address}")

        except Exception as e:
            logger.error(f"Erro ao processar comando: {e}")
            continue

    # Monta estrutura completa
    compose_data = {
        'version': '3.8',
        'networks': {
            network_name: {
                'driver': 'bridge',
                'ipam': {
                    'config': [
                        {'subnet': base_subnet}
                    ]
                }
            }
        },
        'services': services
    }

    return compose_data


def main():
    """Função principal do script."""
    parser = argparse.ArgumentParser(
        description='Gera docker-compose.yml a partir de comandos docker run em Markdown.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s --input docs/containers.md
  %(prog)s --input docs/containers.md --output docker-compose.extra.yml
  %(prog)s --input docs/containers.md --subnet 172.31.0.0/16
        """
    )

    parser.add_argument(
        '-i', '--input',
        type=Path,
        default=Path('docs/adicional/containers_adicionais_50plus.md'),
        help='Arquivo Markdown de entrada (padrão: docs/adicional/containers_adicionais_50plus.md)'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path('docker-compose.adicional.yml'),
        help='Arquivo YAML de saída (padrão: docker-compose.adicional.yml)'
    )

    parser.add_argument(
        '--subnet',
        default='172.30.0.0/15',
        help='Subnet para a rede (padrão: 172.30.0.0/15)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verboso'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Verifica se arquivo de entrada existe
    if not args.input.exists():
        logger.error(f"Arquivo de entrada não encontrado: {args.input}")
        sys.exit(1)

    logger.info(f"Lendo arquivo: {args.input}")

    try:
        content = args.input.read_text(encoding='utf-8')
    except Exception as e:
        logger.error(f"Erro ao ler arquivo: {e}")
        sys.exit(1)

    # Extrai comandos
    commands = extract_docker_commands(content)
    logger.info(f"Encontrados {len(commands)} comandos docker run")

    if not commands:
        logger.warning("Nenhum comando docker run encontrado")
        sys.exit(0)

    # Gera compose
    compose_data = generate_compose(commands, base_subnet=args.subnet)

    # Salva arquivo
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            yaml.dump(compose_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        logger.info(f"Arquivo gerado: {args.output}")
        logger.info(f"Total de serviços: {len(compose_data['services'])}")
    except Exception as e:
        logger.error(f"Erro ao salvar arquivo: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

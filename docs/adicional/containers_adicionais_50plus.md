# 📦 +50 CONTAINERS DOCKER ADICIONAIS COM MÚLTIPLAS VULNERABILIDADES
## Para Escaneamento com OpenVAS - Complemento ao Laboratório SBRC

> ⚠️ **IMPORTANTE**: Todos estes containers possuem MÚLTIPLAS vulnerabilidades detectáveis por scanners.
> São ideais para gerar resultados ricos em scans com OpenVAS.

---

## 🔴 SEÇÃO 1: SISTEMAS OPERACIONAIS DESATUALIZADOS (Muitas CVEs de OS)

| # | Container | Imagem Docker | Comando | CVEs Estimadas |
|---|-----------|---------------|---------|----------------|
| 1 | Ubuntu 14.04 | `ubuntu:14.04` | `docker run -d --name ubuntu14 ubuntu:14.04 tail -f /dev/null` | 500+ |
| 2 | Ubuntu 16.04 | `ubuntu:16.04` | `docker run -d --name ubuntu16 ubuntu:16.04 tail -f /dev/null` | 300+ |
| 3 | Debian 8 (Jessie) | `debian:jessie` | `docker run -d --name debian8 debian:jessie tail -f /dev/null` | 600+ |
| 4 | Debian 9 (Stretch) | `debian:stretch` | `docker run -d --name debian9 debian:stretch tail -f /dev/null` | 400+ |
| 5 | CentOS 6 | `centos:6` | `docker run -d --name centos6 centos:6 tail -f /dev/null` | 700+ |
| 6 | CentOS 7 | `centos:7` | `docker run -d --name centos7 centos:7 tail -f /dev/null` | 200+ |
| 7 | Alpine 3.7 | `alpine:3.7` | `docker run -d --name alpine37 alpine:3.7 tail -f /dev/null` | 100+ |
| 8 | Fedora 28 | `fedora:28` | `docker run -d --name fedora28 fedora:28 tail -f /dev/null` | 300+ |

---

## 🟠 SEÇÃO 2: SERVIDORES WEB ANTIGOS (Múltiplas CVEs de Serviço)

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 9 | Apache 2.2 | `httpd:2.2` | 80 | `docker run -d -p 8050:80 --name apache22 httpd:2.2` |
| 10 | Apache 2.4.6 | `httpd:2.4.6` | 80 | `docker run -d -p 8051:80 --name apache246 httpd:2.4.6` |
| 11 | Nginx 1.10 | `nginx:1.10` | 80 | `docker run -d -p 8052:80 --name nginx110 nginx:1.10` |
| 12 | Nginx 1.12 | `nginx:1.12` | 80 | `docker run -d -p 8053:80 --name nginx112 nginx:1.12` |
| 13 | Nginx 1.14 | `nginx:1.14` | 80 | `docker run -d -p 8054:80 --name nginx114 nginx:1.14` |
| 14 | Lighttpd | `sebp/lighttpd` | 80 | `docker run -d -p 8055:80 --name lighttpd sebp/lighttpd` |
| 15 | Caddy 1.0 | `caddy:1.0.0` | 80 | `docker run -d -p 8056:80 --name caddy1 caddy:1.0.0` |

---

## 🟡 SEÇÃO 3: SERVIDORES DE APLICAÇÃO JAVA (1000+ CVEs cada)

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 16 | Tomcat 6 | `tomcat:6` | 8080 | `docker run -d -p 8060:8080 --name tomcat6 tomcat:6` |
| 17 | Tomcat 7.0.70 | `tomcat:7.0.70` | 8080 | `docker run -d -p 8061:8080 --name tomcat7 tomcat:7.0.70` |
| 18 | Tomcat 8.0 | `tomcat:8.0` | 8080 | `docker run -d -p 8062:8080 --name tomcat8 tomcat:8.0` |
| 19 | Tomcat 8.5.0 | `tomcat:8.5.0` | 8080 | `docker run -d -p 8063:8080 --name tomcat850 tomcat:8.5.0` |
| 20 | JBoss AS 7 | `jboss/wildfly:8.2.1.Final` | 8080 | `docker run -d -p 8064:8080 --name jboss7 jboss/wildfly:8.2.1.Final` |
| 21 | WildFly 9 | `jboss/wildfly:9.0.2.Final` | 8080 | `docker run -d -p 8065:8080 --name wildfly9 jboss/wildfly:9.0.2.Final` |
| 22 | WildFly 10 | `jboss/wildfly:10.1.0.Final` | 8080 | `docker run -d -p 8066:8080 --name wildfly10 jboss/wildfly:10.1.0.Final` |
| 23 | Jetty 9.2 | `jetty:9.2` | 8080 | `docker run -d -p 8067:8080 --name jetty92 jetty:9.2` |
| 24 | GlassFish 4 | `glassfish:4.1` | 8080 | `docker run -d -p 8068:8080 --name glassfish4 glassfish:4.1` |

---

## 🟢 SEÇÃO 4: BANCOS DE DADOS ANTIGOS (Centenas de CVEs)

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 25 | MySQL 5.5 | `mysql:5.5` | 3306 | `docker run -d -p 33062:3306 -e MYSQL_ROOT_PASSWORD=root --name mysql55 mysql:5.5` |
| 26 | MySQL 5.6 | `mysql:5.6` | 3306 | `docker run -d -p 33063:3306 -e MYSQL_ROOT_PASSWORD=root --name mysql56 mysql:5.6` |
| 27 | MariaDB 10.0 | `mariadb:10.0` | 3306 | `docker run -d -p 33064:3306 -e MYSQL_ROOT_PASSWORD=root --name mariadb10 mariadb:10.0` |
| 28 | PostgreSQL 9.3 | `postgres:9.3` | 5432 | `docker run -d -p 54322:5432 -e POSTGRES_PASSWORD=postgres --name pg93 postgres:9.3` |
| 29 | PostgreSQL 9.5 | `postgres:9.5` | 5432 | `docker run -d -p 54323:5432 -e POSTGRES_PASSWORD=postgres --name pg95 postgres:9.5` |
| 30 | MongoDB 3.2 | `mongo:3.2` | 27017 | `docker run -d -p 27018:27017 --name mongo32 mongo:3.2` |
| 31 | MongoDB 3.6 | `mongo:3.6` | 27017 | `docker run -d -p 27019:27017 --name mongo36 mongo:3.6` |
| 32 | Redis 3.2 | `redis:3.2` | 6379 | `docker run -d -p 6380:6379 --name redis32 redis:3.2` |
| 33 | Redis 5.0 | `redis:5.0` | 6379 | `docker run -d -p 6381:6379 --name redis50 redis:5.0` |
| 34 | Cassandra 2.2 | `cassandra:2.2` | 9042 | `docker run -d -p 9043:9042 --name cassandra22 cassandra:2.2` |
| 35 | CouchDB 1.6 | `couchdb:1.6` | 5984 | `docker run -d -p 5985:5984 --name couchdb16 couchdb:1.6` |

---

## 🔵 SEÇÃO 5: LINGUAGENS DE PROGRAMAÇÃO ANTIGAS (Bibliotecas Vulneráveis)

| # | Container | Imagem Docker | Comando | Vulnerabilidades |
|---|-----------|---------------|---------|------------------|
| 36 | Python 2.7 | `python:2.7` | `docker run -d --name python27 python:2.7 tail -f /dev/null` | SSL, urllib, etc |
| 37 | Python 3.5 | `python:3.5` | `docker run -d --name python35 python:3.5 tail -f /dev/null` | Múltiplas libs |
| 38 | Python 3.6 | `python:3.6` | `docker run -d --name python36 python:3.6 tail -f /dev/null` | Várias CVEs |
| 39 | Node.js 6 | `node:6` | `docker run -d --name node6 node:6 tail -f /dev/null` | OpenSSL, npm |
| 40 | Node.js 8 | `node:8` | `docker run -d --name node8 node:8 tail -f /dev/null` | HTTP/2, TLS |
| 41 | Node.js 10 | `node:10` | `docker run -d --name node10 node:10 tail -f /dev/null` | Várias |
| 42 | Ruby 2.3 | `ruby:2.3` | `docker run -d --name ruby23 ruby:2.3 tail -f /dev/null` | OpenSSL, JSON |
| 43 | Ruby 2.4 | `ruby:2.4` | `docker run -d --name ruby24 ruby:2.4 tail -f /dev/null` | Várias gems |
| 44 | PHP 5.6 | `php:5.6-apache` | `docker run -d -p 8070:80 --name php56 php:5.6-apache` | Centenas |
| 45 | PHP 7.0 | `php:7.0-apache` | `docker run -d -p 8071:80 --name php70 php:7.0-apache` | Dezenas |
| 46 | Golang 1.9 | `golang:1.9` | `docker run -d --name go19 golang:1.9 tail -f /dev/null` | Crypto, net |
| 47 | OpenJDK 8 | `openjdk:8` | `docker run -d --name jdk8 openjdk:8 tail -f /dev/null` | JNDI, XML |

---

## 🟣 SEÇÃO 6: APLICAÇÕES ENTERPRISE VULNERÁVEIS

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 48 | Jenkins 2.60 | `jenkins/jenkins:2.60` | 8080 | `docker run -d -p 8080:8080 --name jenkins260 jenkins/jenkins:2.60` |
| 49 | Jenkins 2.150 | `jenkins/jenkins:2.150` | 8080 | `docker run -d -p 8081:8080 --name jenkins2150 jenkins/jenkins:2.150` |
| 50 | Nexus 2 | `sonatype/nexus:2.14.4` | 8081 | `docker run -d -p 8082:8081 --name nexus2 sonatype/nexus:2.14.4` |
| 51 | Nexus 3.0 | `sonatype/nexus3:3.0.0` | 8081 | `docker run -d -p 8083:8081 --name nexus3 sonatype/nexus3:3.0.0` |
| 52 | SonarQube 6.7 | `sonarqube:6.7` | 9000 | `docker run -d -p 9001:9000 --name sonar67 sonarqube:6.7` |
| 53 | SonarQube 7.0 | `sonarqube:7.0` | 9000 | `docker run -d -p 9002:9000 --name sonar70 sonarqube:7.0` |
| 54 | Artifactory 5 | `docker.bintray.io/jfrog/artifactory-oss:5.11.0` | 8081 | `docker run -d -p 8084:8081 --name artifactory5 docker.bintray.io/jfrog/artifactory-oss:5.11.0` |
| 55 | GitLab 10 | `gitlab/gitlab-ce:10.0.0-ce.0` | 80 | `docker run -d -p 8085:80 --name gitlab10 gitlab/gitlab-ce:10.0.0-ce.0` |
| 56 | Gogs 0.11 | `gogs/gogs:0.11` | 3000 | `docker run -d -p 3002:3000 --name gogs011 gogs/gogs:0.11` |
| 57 | Gitea 1.4 | `gitea/gitea:1.4` | 3000 | `docker run -d -p 3003:3000 --name gitea14 gitea/gitea:1.4` |

---

## 🟤 SEÇÃO 7: MESSAGE BROKERS E FILAS

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 58 | RabbitMQ 3.6 | `rabbitmq:3.6-management` | 5672 | `docker run -d -p 5673:5672 -p 15673:15672 --name rabbit36 rabbitmq:3.6-management` |
| 59 | RabbitMQ 3.7 | `rabbitmq:3.7-management` | 5672 | `docker run -d -p 5674:5672 -p 15674:15672 --name rabbit37 rabbitmq:3.7-management` |
| 60 | Kafka (Old) | `wurstmeister/kafka:2.11-0.11.0.3` | 9092 | `docker run -d -p 9093:9092 --name kafka011 wurstmeister/kafka:2.11-0.11.0.3` |
| 61 | ActiveMQ 5.14 | `rmohr/activemq:5.14.3` | 61616 | `docker run -d -p 61617:61616 -p 8162:8161 --name activemq514 rmohr/activemq:5.14.3` |
| 62 | ActiveMQ 5.15 | `rmohr/activemq:5.15.0` | 61616 | `docker run -d -p 61618:61616 -p 8163:8161 --name activemq515 rmohr/activemq:5.15.0` |
| 63 | ZeroMQ | `zeromq/zeromq` | 5555 | `docker run -d -p 5556:5555 --name zeromq zeromq/zeromq` |

---

## ⚫ SEÇÃO 8: MONITORAMENTO E LOGGING

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 64 | Elasticsearch 2.4 | `elasticsearch:2.4` | 9200 | `docker run -d -p 9201:9200 --name es24 elasticsearch:2.4` |
| 65 | Elasticsearch 5.6 | `elasticsearch:5.6` | 9200 | `docker run -d -p 9202:9200 --name es56 elasticsearch:5.6` |
| 66 | Elasticsearch 6.0 | `elasticsearch:6.0.0` | 9200 | `docker run -d -p 9203:9200 --name es60 elasticsearch:6.0.0` |
| 67 | Kibana 4.6 | `kibana:4.6` | 5601 | `docker run -d -p 5602:5601 --name kibana46 kibana:4.6` |
| 68 | Kibana 5.6 | `kibana:5.6` | 5601 | `docker run -d -p 5603:5601 --name kibana56 kibana:5.6` |
| 69 | Logstash 5.6 | `logstash:5.6` | 5044 | `docker run -d -p 5045:5044 --name logstash56 logstash:5.6` |
| 70 | Grafana 4.6 | `grafana/grafana:4.6.0` | 3000 | `docker run -d -p 3004:3000 --name grafana46 grafana/grafana:4.6.0` |
| 71 | Grafana 5.0 | `grafana/grafana:5.0.0` | 3000 | `docker run -d -p 3005:3000 --name grafana50 grafana/grafana:5.0.0` |
| 72 | Prometheus 1.8 | `prom/prometheus:v1.8.0` | 9090 | `docker run -d -p 9091:9090 --name prom18 prom/prometheus:v1.8.0` |
| 73 | InfluxDB 1.3 | `influxdb:1.3` | 8086 | `docker run -d -p 8087:8086 --name influx13 influxdb:1.3` |
| 74 | Nagios Core | `jasonrivers/nagios:latest` | 80 | `docker run -d -p 8088:80 --name nagios jasonrivers/nagios` |
| 75 | Zabbix Server | `zabbix/zabbix-server-mysql:ubuntu-4.0-latest` | 10051 | `docker run -d -p 10052:10051 --name zabbix40 zabbix/zabbix-server-mysql:ubuntu-4.0-latest` |

---

## 🔶 SEÇÃO 9: PROXIES E LOAD BALANCERS

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 76 | HAProxy 1.5 | `haproxy:1.5` | 80 | `docker run -d -p 8090:80 --name haproxy15 haproxy:1.5` |
| 77 | HAProxy 1.6 | `haproxy:1.6` | 80 | `docker run -d -p 8091:80 --name haproxy16 haproxy:1.6` |
| 78 | HAProxy 1.7 | `haproxy:1.7` | 80 | `docker run -d -p 8092:80 --name haproxy17 haproxy:1.7` |
| 79 | Squid 3.5 | `sameersbn/squid:3.5.27-2` | 3128 | `docker run -d -p 3129:3128 --name squid35 sameersbn/squid:3.5.27-2` |
| 80 | Traefik 1.5 | `traefik:1.5` | 80 | `docker run -d -p 8093:80 --name traefik15 traefik:1.5` |
| 81 | Varnish 4.1 | `varnish:4.1` | 80 | `docker run -d -p 8094:80 --name varnish41 varnish:4.1` |

---

## 🔷 SEÇÃO 10: APLICAÇÕES WEB VULNERÁVEIS ADICIONAIS

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 82 | WordPress 4.6 | `wordpress:4.6` | 80 | `docker run -d -p 8095:80 --name wp46 wordpress:4.6` |
| 83 | WordPress 4.9 | `wordpress:4.9` | 80 | `docker run -d -p 8096:80 --name wp49 wordpress:4.9` |
| 84 | Drupal 7 | `drupal:7` | 80 | `docker run -d -p 8097:80 --name drupal7 drupal:7` |
| 85 | Drupal 8.5 | `drupal:8.5` | 80 | `docker run -d -p 8098:80 --name drupal85 drupal:8.5` |
| 86 | Joomla 3.8 | `joomla:3.8` | 80 | `docker run -d -p 8099:80 --name joomla38 joomla:3.8` |
| 87 | Magento 2 | `bitnami/magento:2.2` | 80 | `docker run -d -p 8100:80 --name magento22 bitnami/magento:2.2` |
| 88 | phpMyAdmin 4.6 | `phpmyadmin/phpmyadmin:4.6` | 80 | `docker run -d -p 8101:80 --name pma46 phpmyadmin/phpmyadmin:4.6` |
| 89 | phpMyAdmin 4.8 | `phpmyadmin/phpmyadmin:4.8` | 80 | `docker run -d -p 8102:80 --name pma48 phpmyadmin/phpmyadmin:4.8` |
| 90 | Adminer 4.2 | `adminer:4.2` | 8080 | `docker run -d -p 8103:8080 --name adminer42 adminer:4.2` |
| 91 | Roundcube 1.2 | `roundcube/roundcubemail:1.2.x` | 80 | `docker run -d -p 8104:80 --name roundcube12 roundcube/roundcubemail:1.2.x` |
| 92 | OwnCloud 9 | `owncloud:9` | 80 | `docker run -d -p 8105:80 --name owncloud9 owncloud:9` |
| 93 | Nextcloud 12 | `nextcloud:12` | 80 | `docker run -d -p 8106:80 --name nextcloud12 nextcloud:12` |
| 94 | MediaWiki 1.28 | `mediawiki:1.28` | 80 | `docker run -d -p 8107:80 --name mediawiki128 mediawiki:1.28` |
| 95 | Redmine 3.3 | `redmine:3.3` | 3000 | `docker run -d -p 3006:3000 --name redmine33 redmine:3.3` |

---

## 🔸 SEÇÃO 11: SERVIÇOS DE REDE E INFRAESTRUTURA

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 96 | OpenSSH 7.2 | `linuxserver/openssh-server` | 22 | `docker run -d -p 2224:22 --name openssh linuxserver/openssh-server` |
| 97 | vsftpd | `fauria/vsftpd` | 21 | `docker run -d -p 2123:21 --name vsftpd fauria/vsftpd` |
| 98 | ProFTPD | `hauptmedia/proftpd` | 21 | `docker run -d -p 2124:21 --name proftpd hauptmedia/proftpd` |
| 99 | Postfix | `catatnight/postfix` | 25 | `docker run -d -p 2526:25 --name postfix catatnight/postfix` |
| 100 | Dovecot | `dovecot/dovecot` | 143 | `docker run -d -p 1431:143 --name dovecot dovecot/dovecot` |
| 101 | BIND DNS | `sameersbn/bind:9.11.3-20190706` | 53 | `docker run -d -p 5354:53/udp --name bind sameersbn/bind:9.11.3-20190706` |
| 102 | Memcached 1.4 | `memcached:1.4` | 11211 | `docker run -d -p 11212:11211 --name memcached14 memcached:1.4` |
| 103 | Memcached 1.5 | `memcached:1.5` | 11211 | `docker run -d -p 11213:11211 --name memcached15 memcached:1.5` |

---

## ⭐ SEÇÃO 12: CONTAINERS ESPECIAIS PARA PENTEST

| # | Container | Imagem Docker | Porta | Comando |
|---|-----------|---------------|-------|---------|
| 104 | DVNA (Node) | `appsecco/dvna` | 9090 | `docker run -d -p 9094:9090 --name dvna appsecco/dvna` |
| 105 | VulnLab | `dvja/dvja` | 8080 | `docker run -d -p 8108:8080 --name vulnlab dvja/dvja` |
| 106 | SSRF Lab | `youyouorz/ssrf-vulnerable-lab` | 80 | `docker run -d -p 8109:80 --name ssrflab youyouorz/ssrf-vulnerable-lab` |
| 107 | SQLi Labs | `acgpiano/sqli-labs` | 80 | `docker run -d -p 8110:80 --name sqli acgpiano/sqli-labs` |
| 108 | XSS Lab | `vulnerables/xss-vulnerability-lab` | 80 | `docker run -d -p 8111:80 --name xsslab vulnerables/xss-vulnerability-lab` |
| 109 | Upload Vuln | `vulnerables/file-upload` | 80 | `docker run -d -p 8112:80 --name uploadlab vulnerables/file-upload` |
| 110 | WAVSEP | `yourselfscan/wavsep` | 8080 | `docker run -d -p 8113:8080 --name wavsep yourselfscan/wavsep` |

---

## 📊 RESUMO PARA ESCANEAMENTO

### Containers por Categoria:
- **Sistemas Operacionais**: 8 containers (Ubuntu, Debian, CentOS, Alpine, Fedora)
- **Servidores Web**: 7 containers (Apache, Nginx, Lighttpd, Caddy)
- **Servidores de Aplicação Java**: 9 containers (Tomcat, JBoss, WildFly, Jetty, GlassFish)
- **Bancos de Dados**: 11 containers (MySQL, MariaDB, PostgreSQL, MongoDB, Redis, Cassandra, CouchDB)
- **Linguagens de Programação**: 12 containers (Python, Node.js, Ruby, PHP, Go, Java)
- **Aplicações Enterprise**: 10 containers (Jenkins, Nexus, SonarQube, GitLab, Gogs, Gitea)
- **Message Brokers**: 6 containers (RabbitMQ, Kafka, ActiveMQ, ZeroMQ)
- **Monitoramento**: 12 containers (ELK Stack, Grafana, Prometheus, InfluxDB, Nagios, Zabbix)
- **Proxies**: 6 containers (HAProxy, Squid, Traefik, Varnish)
- **Aplicações Web CMS**: 14 containers (WordPress, Drupal, Joomla, Magento, etc.)
- **Serviços de Rede**: 8 containers (SSH, FTP, SMTP, DNS, Memcached)
- **Labs de Pentest**: 7 containers (DVNA, SQLi Labs, XSS Lab, etc.)

### Total de Vulnerabilidades Estimadas:
| Categoria | CVEs Estimadas |
|-----------|----------------|
| OS Desatualizados | 3.000+ |
| Servidores Web | 500+ |
| Servidores Java | 10.000+ |
| Bancos de Dados | 2.000+ |
| Linguagens | 1.500+ |
| Enterprise Apps | 5.000+ |
| Message Brokers | 500+ |
| Monitoramento | 1.000+ |
| Proxies | 300+ |
| CMS/Web Apps | 2.000+ |
| **TOTAL ESTIMADO** | **25.000+** |

---

## 🚀 SCRIPT PARA INICIAR TODOS

```bash
#!/bin/bash
# start-additional-containers.sh

echo "=== Iniciando containers adicionais ==="

# Sistemas Operacionais
docker run -d --name ubuntu14 ubuntu:14.04 tail -f /dev/null
docker run -d --name debian8 debian:jessie tail -f /dev/null
docker run -d --name centos7 centos:7 tail -f /dev/null

# Servidores Web
docker run -d -p 8050:80 --name apache22 httpd:2.2
docker run -d -p 8052:80 --name nginx110 nginx:1.10

# Tomcat
docker run -d -p 8060:8080 --name tomcat6 tomcat:6
docker run -d -p 8061:8080 --name tomcat7 tomcat:7.0.70

# Bancos de Dados
docker run -d -p 33062:3306 -e MYSQL_ROOT_PASSWORD=root --name mysql55 mysql:5.5
docker run -d -p 54322:5432 -e POSTGRES_PASSWORD=postgres --name pg93 postgres:9.3
docker run -d -p 27018:27017 --name mongo32 mongo:3.2
docker run -d -p 6380:6379 --name redis32 redis:3.2

# Linguagens
docker run -d --name python27 python:2.7 tail -f /dev/null
docker run -d --name node6 node:6 tail -f /dev/null
docker run -d -p 8070:80 --name php56 php:5.6-apache

# Enterprise
docker run -d -p 8080:8080 --name jenkins260 jenkins/jenkins:2.60
docker run -d -p 9001:9000 --name sonar67 sonarqube:6.7

# Monitoramento
docker run -d -p 9201:9200 --name es24 elasticsearch:2.4
docker run -d -p 5602:5601 --name kibana46 kibana:4.6
docker run -d -p 3004:3000 --name grafana46 grafana/grafana:4.6.0

# Web Apps
docker run -d -p 8095:80 --name wp46 wordpress:4.6
docker run -d -p 8097:80 --name drupal7 drupal:7

echo "=== Containers iniciados! ==="
docker ps
```

---

## 📝 NOTAS IMPORTANTES

1. **Memória**: Estes containers adicionais requerem ~16GB RAM extras
2. **Disco**: Reserve ~50GB adicionais para imagens
3. **Rede**: Configure uma subnet isolada (ex: 172.31.0.0/16)
4. **Tempo**: O pull de todas as imagens pode levar 1-2 horas
5. **Estabilidade**: Alguns containers antigos podem não iniciar corretamente

---

## 🔗 REFERÊNCIAS

- Snyk Vulnerability Database: https://snyk.io/vuln
- Docker Hub: https://hub.docker.com
- CVE Details: https://cvedetails.com
- National Vulnerability Database: https://nvd.nist.gov

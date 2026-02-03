# Testbed de ataques conteinerizados e desenvolvimento de ferramenta para a execução, controle, coleta e análise de tráfego de rede
[![Licença](https://img.shields.io/badge/License-GNU%20GPL-blue)](https://opensource.org/licenses/GNU)

### Objetivo:
Este repositório tem como objetivo exemplificar o funcionamento prático do catálogo de ataques, servidores e cliente conteinerizados e da ferramenta de operação do presente _testbed_, tendo seus procedimentos de instalação, execução e reivindicações documentadas em texto e demonstradas em vídeo.

### Resumo do Artigo:
_A reprodução de comportamentos de ataques cibernéticos sob demanda e a obtenção de dados de tráfego reais atualizados para análise e pesquisa se demonstram um desafio, tendo em vista que apesar de haver diversos estudos, ferramentas e repositórios sobre o tema, estes são ou muito verticalizados em protocolos específicos e/ou carecem de documentação de replicação, previsão de extensibilidade e facilidade de implementação. Este trabalho apresenta uma combinação de um repositório contendo 42 ataques individualizados e uma ferramenta do tipo interface que centraliza os controles para a exploração e o estudo de comportamento de tráfego de rede em cenários típicos de ataques cibernéticos, operacionalizando a execução dos ataques sob demanda, visualização de logs, captura de pacotes, extração e visualização de características de tráfego e consolidação de dados de fluxos em datasets para pesquisa._

---

# Estrutura do README.md

Este README.md está organizado nas seguintes seções:

1.  **Título, Objetivo e Resumo:** Título do projeto, objetivo do artefato e resumo do artigo.
2.  **Estrutura do README.md:** A presente estrutura.
3.  **Selos considerados:** Lista dos Selos a serem considerados no processo de avaliação.
4.  **Informações básicas:** Descrição dos componentes e requisitos mínimos para a execução do experimento.
5.  **Dependências:** Informação sobre as dependências necessárias.
6.  **Preocupações com segurança:** Lista das considerações e preocupações com a segurança.
7.  **Instalação:** Relação de opções para a realização do experimento, bem como as instruções individuais de cada opção.
8.  **Teste mínimo:** Instruções para a execução das simulações.
9.  **Experimentos:** Informações de replicação das reivindicações.
10. **Documentação:** Documentação básica da aplicação.
11. **Ambiente de teste:** Ambientes que foram usados em testes.
12. **Licença:** Informações sobre a licença do projeto.

---

# Selos considerados

Os selos considerados são:
- Artefatos Disponíveis (SeloD)
- Artefatos Funcionais (SeloF)
- Artefatos Sustentáveis (SeloS)
- Experimentos Reprodutíveis (SeloR)

---

# Informações básicas

#### O testbed possui duas opções disponíveis para execução, sendo:

 1. **Opção 1:** Imagem de **VirtualBox** com ambiente auto-contido já preparado para o experimento (testado em Sistema Operacional Microsoft Windows 10 ou superior e distribuições Linux baseada em Ubuntu versão 20.04 ou mais recente: Ubuntu, Kubuntu e variantes). Neste ambiente, a autenticação se dá como usuário **user** e senha **ubuntu24**; ou
 2. **Opção 2:** Procedimento manual execução dos scripts que efetuam de maneira automatizada o download de todos pacotes de dependências e demais elementos envolvidos e a instalação destes, localmente em um desktop ou laptop (testado em Sistema Operacional não virtualizado, bare-metal, baseado em Ubuntu versão 24.04 ou mais recente: Ubuntu, Kubuntu e variantes).
 
#### Requisitos de software e hardware para cada Opção de execução:

 1. **Opção 1:** Nesta opção, deve ser feito o download e importação de um Appliance Virtual (arquivo .ova) e execução do ambiente virtualizado utilizando VirtualBox. Para tanto, são necessários: Sistema Operacional Microsoft Windows 10 ou superior e distribuições Linux baseada em Ubuntu versão 20.04 ou mais recente: Ubuntu, Kubuntu e variantes), processador de arquitetura AMD64 com no mínimo 4 núcleos e flag de virtualzação VT-x ativada na BIOS, 8GB de memória RAM para uso exclusivo no experimento, 15GB de espaço de armazenamento adicional, VirtualBox 7.1 ou superior com Extension Pack correspondente à versão do VirtualBox; ou
 2. **Opção 2:** Nesta opção, todo experimento será executado em ambiente local através do download e execução automatizada de todos os componentes. Para isto, são necessários: Sistema Operacional Linux, bare-metal ou VM, baseado em Ubuntu versão 24.04 ou mais recente: Ubuntu, Kubuntu e variantes), processador de arquitetura AMD64 com no mínimo 4 núcleos, 8GB de memória RAM, 15GB de espaço de armazenamento adicional.

Resumo dos requisitos de hardware e sistema operacional:

| Opção | Sistema Operacional                                                                    | Memória RAM |  Requisito              |
|-------|----------------------------------------------------------------------------------------|-------------|-------------------------|
| 1     | Microsoft Windows 10 ou superior, Linux baseado em Ubuntu versão 24.04 ou mais recente | 8GB         | VirtualBox 7+ e ExtPack |
| 2     | Ubuntu bare-metal versão 24.04 ou mais recente: Ubuntu, Kubuntu e variantes            | 8GB         | Usuário com `sudo`      |
 
---

# Dependências

#### O testbed possui duas opções disponíveis para execução, tendo cada uma delas as seguintes dependências:

 1. **Opção 1:** Cumpridos os requisitos descritos na seção anterior, referentes a **Opção 1**, esta opção não possui dependências.
 2. **Opção 2:** Cumpridos os requisitos descritos na seção anterior, referentes a **Opção 2**, todas as dependências necessárias serão instaladas e configuradas automaticamente pelos scripts de instalação. Para informação, os pacotes dependências que serão instaladas são: `ca-certificates curl`, `cmake`, `docker-ce`, `git`, `python3-venv`, `tcpdump` e `wireshark`.

Resumo dos pacotes adicionais necessários (dependências):

| Opção | Pacotes adicionais necessários                                                                       |
|-------|------------------------------------------------------------------------------------------------------|
| 1     | Nenhum pacote adicional                                                                              |
| 2*    | Pacotes `ca-certificates curl`, `cmake`, `docker-ce`, `git`, `python3-venv`, `tcpdump` e `wireshark` |

\* A instalação das dependências ocorrerá automaticamente durante a execução dos instaladores, bastando seguir as instruções exibidas em tela.

---

# Preocupações com segurança

#### O testbed possui as seguintes preocupações com segurança:

 1. O presente testbed tem propósito educacional e não deve ser utilizada para atacar endereços externos ao experimento. Para fins de demonstração, utilize o próprio IP desta máquina como alvo dos ataques (nos ataques diretos a um endereço IP. Nos ataques em nível de rede, utilize a rede docker0 (geralmente 172.17.0.0/16) ou sua rede local.
 2. Nos conteineres servidores serão mapeadas as seguintes portas (tabela abaixo) do host para os conteineres, podendo haver conflitos de portas no caso de o host ser de uso geral e não um ambiente criado exclusivamente para a instalação.
 3. O mapeamento de portas descrito no item 2 pode representar uma exposição sensível de informações do host caso este faça interface diretamente com a internet sem nenhum tipo de filtragem. 

 | Protocolo | Mapeamentos de Portas                         |
 |-----------|-----------------------------------------------|
 | TCP       | 139, 445, 1883, 2222, 2323, 5683, 8443 e 9001 |
 | UDP       | 137, 138 e 5683                               |

#### Preocupações adicionais a com segurança

Cabe ressaltar que todas as senhas, chaves SSH, chaves de API e outros elementos secretos dos componentes foram gerados apenas para fins de demonstração do testbed, de tal forma que sua força de segurança foram propositalmente baixadas para facilitar sua reprodução. As senhas, chaves SSH, chaves de API e outros elementos secretos utilizada são descartáveis e servem apenas ao propósito desta demonstração.

---

# Instalação

#### O experimento possui duas opções disponíveis para execução, tendo cada uma delas as seguintes etapas de instalação:

### **Opção 1: Appliance pronta de VirtualBox:**

1. Baixe o appliance (arquivo .ova) do experimento que está disponível através do [link](https://drive.google.com/file/d/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/view?usp=sharing).
2. Importe o arquivo __XXXXXXXXX.ova__ baixado no VirtualBox:
   
![assets/vb1.png](assets/vb1.png)

![assets/vb2.png](assets/vb2.png)

3. Clique em _Finalizar_ e aguarde o processo de importação.

4. Execute a VM recém importada.

![assets/vb3.png](assets/vb3.png)

**4.1. Caso seja exibida uma mensagem de erro do VirtualBox referente a interface de rede, isto é porque a nomenclatura do dispositivo de rede local é diferente daquela existente no computador onde a imagem foi gerada. Basta selecionar a opção "Alterar as opções de rede" e salvar.**

![assets/vb4.png](assets/vb4.png)

5. Após a inicialização da VM e login (usuário **user** e senha **ubuntu24**), abra o atalho no desktop:

![assets/vb5.png](assets/vb5.png)


### **Opção 2: Execução manual dos procedimentos de instalação:**

1. Em um terminal do Linux local, executar:
```
sudo apt update && sudo apt install git -y
```
2. Aguarde o término da instalação do pacote `git`, clone o repostirório e entre no diretório raiz do mesmo:

```
git clone https://github.com/ljbitzki/sbrc26-sf.git && cd sbrc26-sf/
```

### Instalação automatizada:

#### Estando no diretório raiz deste repositório, tornar executável o script `instalador1.sh` e executá-lo:

```
chmod +x instalador1.sh && ./instalador1.sh
```

Aguarde o término da instalação das dependências e da ferramenta ao término do `instalador1.sh` e execute os próximos comandos:

```
newgrp docker
./instalador2.sh
```

4. Aguarde o término do processo de construção das imagens e inicialização da ferramenta.
Ao concluir, serão exibidas informações em tela da URL em que a aplicação estará acessível.

**Nota:** _No ambiente de desenvolvimento, com recursos iguais aos da `Opção 2`, os procedimentos de instalação levaram em média `11 minutos e 30 segundos` para concluir na totalidade, baixando cerca de 2.3GB de dados pela internet e resultando no uso de 12GB de espaço adicional em disco. Este tempo deve variar conforme os recursos do ambiente de cada instalação._

#### Vídeo de demonstração da instalação do testbed em uma VM nova utilizando o a `Opção 2`:

[![video-demonstracao-instalacao](https://img.youtube.com/vi/qNCpw_xKxzU/0.jpg)](https://www.youtube.com/watch?v=qNCpw_xKxzU)

---

# Teste mínimo

#### O ambiente do testbed será considerado operacional se: (estando em um terminal no dispositivo onde a instalação foi executada)

A URL (resultante do comando seguinte) estiver acessível pelo navegador de internet:

```
echo "http://$( ip route get 9.9.9.9 | awk '{print $7; exit}' ):8501"
```

O retorno de contagem mínima de conteineres esperado (resultante do comando seguinte) seja `Containeres OK`:

```
if [ $( docker ps -a | grep -c 'sbrc-' ) -ge 49 ]; then echo "Containeres OK"; else echo "Containeres NOK"; fi
```

---

# Experimentos

## Reivindicações: 

### Catálogo de ataques, servidores e cliente conteinerizados:

Para verificar a criação das 50 imagens de conteineres Docker descritas no artigo, execute em um terminal no dispositivo onde o ambiente foi instalado:
```
docker image ls -a --format table | grep 'sbrc26-'
```

### Operações do testbed:

#### Tela principal: Acessível em http://seu.endereço.ip:8501/

![assets/1.png](assets/1.png)

#### Funções da tela principal:

![assets/2.png](assets/2.png)

1. URL base da ferramental
2. Status e visualização de logs dos servidores alvo
3. Status e controles sobre os clientes benignos
4. Menu de macro categorias dos ataques
5. Menu de seleção de um ataque específico
6. Detalhes do ataque selecionado (ID, Nome, Descrição, Imagem, Container e Categorização MITRE)
7. Status e controles sobre a execução do ataque
8. Parâmetros de execução do ataque (Endereço IP e Porta do alvo, quando aplicável) e seletor de captura de pacotes simultânea
9. Menu de operações sobre capturas já realizadas

#### Funções relativas aos logs dos servidores alvo:

![assets/3.png](assets/3.png)

1. Abertura da tela de logs de um servidor alvo
2. Título da tela
3. Função para forçar a atualização dos logs exibidos
4. Seletor do número de linhas de logs para exibir (200 por padrão)
5. Comando executado para a obtenção dos logs
6. Exibição dos logs
7. Botão para voltar a tela anterior

#### Funções relativas controle dos clientes benignos:

![assets/4.png](assets/4.png)

1. Informação do número de clientes atualmente em execução (máximo de 10 para fins de demonstração)
2. Botão para interromper a execução e remover todos os clientes benignos
3. Botão para iniciar mais um cliente benigno (máximo de 10 para fins de demonstração)
4. Informação adicional sobre os clientes benignos em execução

#### Funções referentes a execução de um ataque:

![assets/5.png](assets/5.png)

1. Ataque específico selecionado
2. Endereço IP do servidor alvo (tipicamente, utilizar as informações sugeridas e pré-preenchidas)
3. Porta do servidor alvo (tipicamente, utilizar as informações sugeridas e pré-preenchidas)
4. Seletor para capturar pacotes durante a execução do ataque
5. Botão para iniciar o ataque
6. Informação relativa ao arquivo de captura resultante (somente se ativado o seletor de captura)
7. Informação sobre o comando efetivamente executado para a captura (somente se ativado o seletor de captura)
8. ID da execução do container no Docker Engine
9. Informação sobre o comando efetivamente executado no Docker Engine
10. Botão para forçar a atualização do status da execução
11. Botão para interromper imediatamente o container do atacante

#### Funções referentes à manipulação de arquivos de captura:

![assets/6.png](assets/6.png)

1. Botão de acesso ao módulo de visualização e processamento dos arquivos de captura
2. Nome do(s) arquivo(s) de captura armazenados no diretório `/captures`
3. Tamanho do arquivo de captura
4. Data de modificação do arquivo de captura
5. Botão para efetuar o download do arquivo de captura
6. Botão para acionar o módulo de extração de features

#### Funções referentes ao módulo de extração de features de um arquivo de captura:

![assets/7.png](assets/7.png)

1. Nome do arquivo de captura selecionado
2. Nome dos arquivos `.csv` previstos pós extração `/features`
3. Seleção para extrair utilizando NTLFlowLyzer
4. Seleção para extrair utilizando Dumpcap TShark
5. Seleção para extrair utilizando Python Scapy
6. Seletor para forçar a reescrita dos arquivos `.csv` caso estes já existam de processamento anterior
7. Botão para a execução da extração das features conforme as opções selecionadas

#### Tela de resumo do processamento de features:

![assets/8.png](assets/8.png)

1. Status da execução da extração com NTLFlowLyzer (somente se selecionado na tela anterior) e arquivo resultante salvo em `/features`
2. Status da execução da extração com Dumpcap TShark (somente se selecionado na tela anterior) e arquivo resultante salvo em `/features`
3. Status da execução da extração com Python Scapy (somente se selecionado na tela anterior) e arquivo resultante salvo em `/features`

#### Funções referentes a pré-visualização das features extraídas e geração de dataset:

![assets/9.png](assets/9.png)

> Note que após um arquivo de captura ter features extraídas, são habilidados os botões adicionais
1. Nome do arquivo de captura
2. Botão para pré-visualização no navegador as features extraídas
3. Botão para gerar dataset de fluxos consolidados da extração de features já realizada

#### Tela de pré-visualização de features extraídas:

![assets/10.png](assets/10.png)

1. Arquivos referentes a extração e possíveis de serem visualizados
2. Informação da fonte de cada arquivo `.csv`
3. Botões para efetuar o download de cada arquivo `.csv` disponível
4. Seletor da fonte de dados para a visualização
5. Seletor do número de linhas para exibição (50 por padrão)
6. Tabela de visualização da fonte de dados selecionada

#### Geração de dataset de fluxos consolidados de extração de features já realizada:

![assets/11.png](assets/11.png)

1. Nome do arquivo de captura
2. Botão para gerar o dataset em `datasets/`

#### Função para pré-visualização de dataset gerado:

![assets/12.png](assets/12.png)

1. Seletor de pré-visualização de dataset

#### Tela de pré-visualização de dataset gerado:

![assets/13.png](assets/13.png)

1. Nome dos arquivos de captura e features extraídos relativos ao dataset
2. Botões para efetuar o download do arquivo `.csv` disponível
3. Seletor do número de linhas para exibição (200 por padrão), máximo de colunas (80 por padrão) e campo de busca/filtragem
4. Tabela de visualização do dataset

---


## Demonstração completa em vídeo do testbed e das reivindicações, utilizando o ambiente instalado manualmente (`Opção 2`)

[![video-demonstracao-uso](https://img.youtube.com/vi/fx2Z5ZD_Rbo/0.jpg)](https://www.youtube.com/watch?v=fx2Z5ZD_Rbo)

---

# Documentação básica:

## Estrutura do projeto:
```
sbrc26-sf
|
├── assets/                   # Diretório auxiliar para documentação
├── captures/                 # Diretório de armazenamento das capturas .pcap
├── datasets/                 # Diretório de datasets gerados
├── docker/                   # Repositório de contêineres
│   ├── atacantes/            # Diretório dos contêineres atacantes
│   ├── build-images.sh       # Script de construção de todas as imagens
│   ├── clientes/             # Diretório dos contêineres clientes (benignos)
│   └── servidores/           # Diretório dos contêineres servidores alvo
├── features/                 # Diretório dos CSV de extração de features
├── modules/                  # Diretório dos módulos da ferramenta
│   ├── datasets.py           # Módulo de geração de datasets
│   ├── features.py           # Módulo de extração de features
│   ├── registry.py           # Módulo de declaração das especificações dos contêineres
│   └── runners.py            # Módulo de ações práticas da ferramenta
├── clientes.sh               # Script para controlar manualmente os contêineres de clientes
├── ferramenta.py             # Arquivo principal da ferramenta
├── instalador1.sh            # Script automatizado para instalação das dependências
├── instalador2.sh            # Script para geração das imagens e artefatos Docker
├── LICENSE                   # Arquivo de licença da ferramenta (GNU GENERAL PUBLIC LICENSE)
├── README.md                 # Este arquivo README.md
├── requirements.txt          # Arquivo com requisitos de pacotes Python do instalador PIP
└── servidores.sh             # Script para controlar manualmente os servidores alvo
```

## Documentação das funções (gerado por documentação inline do tipo Docstrings junto ao código) via Sphinx:

[https://github.com/LeftRedShift/leftredshift.github.io](https://leftredshift.github.io/modules)

# Ambiente de testes:
 ***Hardware:*** Processador: AMD Ryzen 5 5500X, Memória RAM: 16GB DDR4, Armazenamento SSD.
 ***Software:*** Sistema Operacional: Kubuntu 24.04 LTS, Python 3.12, Docker Engine 29.2.1 e Virtual box 7.1

# LICENSE

Este projeto está licenciado sob a Licença GNU General Public License v3.0 - veja o arquivo [LICENSE](LICENSE) para mais detalhes.
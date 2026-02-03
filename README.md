# sbrc26-sf - Salão de Ferramentas SBRC 2026

## Informações sobre o ambiente e requisitos:

### Ambiente de desenvolvimento (apenas para referência):
- Sistema Operacional Host: Kubuntu Desktop 24.04 LTS
- Processador AMD Ryzen 5 5600X
- 32 GB de RAM
- GPU GeForce RTX 3070Ti com 8 GB de VRAM
- 1TB de armazenamento
- Internet 500Mbps de download / 50Mbps de upload

### Ambiente e configurações mínimas para execução:
- Dispositivo Bare-metal ou VM com Sistema Operacional baseado em Ubuntu 24.04 LTS
  - Dispositivo com navegador de internet que possua acesso à rede da instalação (caso a instalação seja realizada em outro computador/VM)
- Processador baseado em arquitetura x86/AMD64
- 8 GB de RAM
- 15GB de espaço disponível
- Acesso à internet
- Navegador de internet
- Usuário com permissão de execução de `sudo`

> Os pacotes que serão instalados são bastante comuns e não devem causar nenhum tipo de distúrbio no ambiente onde for instalado, apesar disto, ***sugere-se fortemente*** que a instalação desta ferramenta seja realizada em uma instalação nova de Sistema Operacional, própria para este fim de demonstração da ferramenta, no intuito de não interferir de alguma forma não intencional no ambiente do operador que efetuará uma instalação.

---

## Procedimentos de instalação:

### Clonar e entrar no repositório:
```
git clone https://github.com/ljbitzki/sbrc26-sf.git && cd sbrc26-sf/
```

### Instalação automatizada:

#### Estando no diretório raiz deste repositório, tornar executável o script `instalador1.sh`:

```
chmod +x instalador1.sh
```

#### Instalar **todas as dependências** e instalar a ferramenta, rodando o script `instalador1.sh`:

```
./instalador1.sh
```

Aguarde o término da instalação das dependências e da ferramenta através do `instalador1.sh` e execute o próximo comando.

```
newgrp docker
```

#### Construir todas as imagens e iniciar a ferramenta, rodando o script `instalador2.sh`:

```
./instalador2.sh
```

**Nota:** _No ambiente de desenvolvimento mencionado acima, os procedimentos de instalação levaram em média `11 minutos e 30 segundos` para concluir na totalidade, baixando cerca de 2.3GB de dados pela internet e resultando no uso de 12GB de espaço adicional em disco. Este tempo deve variar conforme os recursos do ambiente de cada instalação._

Concluída a instalação, a ferramenta estará disponível acessando http://endereço.ip.da.instalação:8501/ ou http://127.0.0.1:8501/ (caso o local da instalação possua um Web Browser).

### Vídeo de demonstração da instalação da ferramenta em uma VM nova:

[![video-demonstracao-instalacao](https://img.youtube.com/vi/qNCpw_xKxzU/0.jpg)](https://www.youtube.com/watch?v=qNCpw_xKxzU)

---

## Procedimentos pós-instalação (opcionais e caso necessário):

### Parar, iniciar ou reiniciar os servidores (estando no diretório raiz deste repositório):

#### Parar e remover os contêineres dos servidores:

```
./servidores.sh parar
```

#### Iniciar os contêineres dos servidores:

```
./servidores.sh iniciar
```

#### Reiniciar os contêineres dos servidores:

```
./servidores.sh reiniciar
```

### Parar ou iniciar os clientes "benignos" (estando no diretório raiz deste repositório):

#### Parar e remover os contêineres dos clientes:

```
./clientes.sh parar
```

#### Iniciar um cliente:

```
./clientes.sh iniciar
```
> O comando `./clientes.sh iniciar` inicia mais um cliente, independente de quantos já estejam rodando.

### Iniciar a ferramenta (estando no diretório raiz deste repositório):
```
source .venv/bin/activate
streamlit run ferramenta.py
```

#### Parar e remover contêineres e imagens residuais (limpeza completa do ambiente):

```
while read -r CONT; do docker rm -f ${CONT}; done < <( docker ps -a | grep 'sbrc26-' | awk '{print $1}' )
while read -r IMG; do docker rmi -f ${IMG}; done < <( docker images --format table | grep 'sbrc26-' | awk '{print $3}' )

```
> Este comando para todos os contêineres e remove todas as imagens que contenham `sbrc26-` no nome.

---

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

---

## Documentação das funções (gerado por documentação inline do tipo Docstrings junto ao código) via Sphinx:

[https://github.com/LeftRedShift/leftredshift.github.io](https://leftredshift.github.io/modules)

---

## Apresentação e operação da ferramenta:

### Tela principal: Acessível em http://seu.endereço.ip:8501/

![assets/1.png](assets/1.png)

### Funções da tela principal:

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

### Funções relativas aos logs dos servidores alvo:

![assets/3.png](assets/3.png)

1. Abertura da tela de logs de um servidor alvo
2. Título da tela
3. Função para forçar a atualização dos logs exibidos
4. Seletor do número de linhas de logs para exibir (200 por padrão)
5. Comando executado para a obtenção dos logs
6. Exibição dos logs
7. Botão para voltar a tela anterior

### Funções relativas controle dos clientes benignos:

![assets/4.png](assets/4.png)

1. Informação do número de clientes atualmente em execução (máximo de 10 para fins de demonstração)
2. Botão para interromper a execução e remover todos os clientes benignos
3. Botão para iniciar mais um cliente benigno (máximo de 10 para fins de demonstração)
4. Informação adicional sobre os clientes benignos em execução

### Funções referentes a execução de um ataque:

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

### Funções referentes à manipulação de arquivos de captura:

![assets/6.png](assets/6.png)

1. Botão de acesso ao módulo de visualização e processamento dos arquivos de captura
2. Nome do(s) arquivo(s) de captura armazenados no diretório `/captures`
3. Tamanho do arquivo de captura
4. Data de modificação do arquivo de captura
5. Botão para efetuar o download do arquivo de captura
6. Botão para acionar o módulo de extração de features

### Funções referentes ao módulo de extração de features de um arquivo de captura:

![assets/7.png](assets/7.png)

1. Nome do arquivo de captura selecionado
2. Nome dos arquivos `.csv` previstos pós extração `/features`
3. Seleção para extrair utilizando NTLFlowLyzer
4. Seleção para extrair utilizando Dumpcap TShark
5. Seleção para extrair utilizando Python Scapy
6. Seletor para forçar a reescrita dos arquivos `.csv` caso estes já existam de processamento anterior
7. Botão para a execução da extração das features conforme as opções selecionadas

### Tela de resumo do processamento de features:

![assets/8.png](assets/8.png)

1. Status da execução da extração com NTLFlowLyzer (somente se selecionado na tela anterior) e arquivo resultante salvo em `/features`
2. Status da execução da extração com Dumpcap TShark (somente se selecionado na tela anterior) e arquivo resultante salvo em `/features`
3. Status da execução da extração com Python Scapy (somente se selecionado na tela anterior) e arquivo resultante salvo em `/features`

### Funções referentes a pré-visualização das features extraídas e geração de dataset:

![assets/9.png](assets/9.png)

> Note que após um arquivo de captura ter features extraídas, são habilidados os botões adicionais
1. Nome do arquivo de captura
2. Botão para pré-visualização no navegador as features extraídas
3. Botão para gerar dataset de fluxos consolidados da extração de features já realizada

### Tela de pré-visualização de features extraídas:

![assets/10.png](assets/10.png)

1. Arquivos referentes a extração e possíveis de serem visualizados
2. Informação da fonte de cada arquivo `.csv`
3. Botões para efetuar o download de cada arquivo `.csv` disponível
4. Seletor da fonte de dados para a visualização
5. Seletor do número de linhas para exibição (50 por padrão)
6. Tabela de visualização da fonte de dados selecionada

### Geração de dataset de fluxos consolidados de extração de features já realizada:

![assets/11.png](assets/11.png)

1. Nome do arquivo de captura
2. Botão para gerar o dataset em `datasets/`

### Função para pré-visualização de dataset gerado:

![assets/12.png](assets/12.png)

1. Seletor de pré-visualização de dataset

#### Tela de pré-visualização de dataset gerado:

![assets/13.png](assets/13.png)

1. Nome dos arquivos de captura e features extraídos relativos ao dataset
2. Botões para efetuar o download do arquivo `.csv` disponível
3. Seletor do número de linhas para exibição (200 por padrão), máximo de colunas (80 por padrão) e campo de busca/filtragem
4. Tabela de visualização do dataset

---

## Vídeo de demonstração do uso da ferramenta:

[![video-demonstracao-uso](https://img.youtube.com/vi/fx2Z5ZD_Rbo/0.jpg)](https://www.youtube.com/watch?v=fx2Z5ZD_Rbo)
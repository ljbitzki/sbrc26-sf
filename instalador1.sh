#!/usr/bin/env bash

echo "Instalando pacotes necessários..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y tshark tcpdump python3-venv cmake wireshark redis git ca-certificates curl
sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common
sudo chmod +x /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
sudo apt remove $(dpkg --get-selections docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc | cut -f1)
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt update
echo "Instalando Docker Engine..."
sudo DEBIAN_FRONTEND=noninteractive apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
echo "Instalando a ferramenta..."
chmod +x clientes.sh servidores.sh instalador2.sh
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
git clone https://github.com/ahlashkari/NTLFlowLyzer.git
cd NTLFlowLyzer
echo -e "\nsetuptools" >> requirements.txt
pip install -r requirements.txt
python3 setup.py install
cd ../
pip install -r requirements.txt
echo "Instalação de dependências concluída. Execute agora \" newgrp docker \" e prossiga para a instalação do \" ./instalador2.sh \""
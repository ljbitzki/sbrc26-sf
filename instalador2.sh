#!/usr/bin/env bash
echo "Construindo os contêineres..."
cd docker/ || exit 1
chmod +x criar-imagens.sh
./criar-imagens.sh
echo "Contêineres criados... Executando Streamlit"
cd ../
source .venv/bin/activate
streamlit run ferramenta.py --theme.base="dark" --server.headless true &

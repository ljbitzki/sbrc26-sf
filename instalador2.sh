#!/usr/bin/env bash
echo "Construindo os contêineres..."
cd docker/ || exit 1
chmod +x build-images.sh
./build-images.sh
echo "Contêineres criados... Executando Streamlit"
cd ../
source .venv/bin/activate
streamlit run ferramenta.py &

#!/bin/bash
# Le o ventivul.csv do Figshare (v3) em fluxo, sem gravar em disco, e mostra a estrutura (so metadados).
S="$(cd "$(dirname "$0")" && pwd)"
curl -sL --fail https://ndownloader.figshare.com/files/67579809 | python3 "$S/${1:-estrutura_ventivul.py}"

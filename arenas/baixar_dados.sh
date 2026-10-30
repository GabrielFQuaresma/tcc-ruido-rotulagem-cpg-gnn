#!/bin/bash
# Preparacao das arenas externas (PREREGISTRO_ARENAS.md §10, passo 2): baixa os dados OFICIAIS.
#   PrimeVul v0.1 — pasta do Google Drive do README oficial (github.com/DLVulDet/PrimeVul)
#   VentiVul v3   — Figshare, artigo 33263469 (ventivul.csv)
# Grava em ~/curadoria/arenas/ (fora do repositorio) e registra SHA-256 e tamanho de cada arquivo.
# Idempotente: arquivo que ja existe nao e baixado de novo. Nenhum modelo, nenhuma predicao.
set -u
DEST="$HOME/curadoria/arenas"
mkdir -p "$DEST/primevul" "$DEST/ventivul"

baixar_drive() {  # id destino
  local id="$1" out="$2"
  [ -s "$out" ] && { echo "ja existe: $out"; return 0; }
  curl -sL --fail --retry 3 -o "$out.part" \
    "https://drive.usercontent.google.com/download?id=$id&export=download&confirm=t" \
    && mv "$out.part" "$out" || { echo "FALHOU: $out"; rm -f "$out.part"; return 1; }
}

# ids lidos da listagem publica da pasta v0.1 (embeddedfolderview), 15/10/2026
baixar_drive 1ABV5cIdtyNAzKlGxjW_BsFZOp9MFd-AH "$DEST/primevul/primevul_test.jsonl"
baixar_drive 1490USYtUtb5n3i3m3n2LaSfjTCiKhPoO "$DEST/primevul/primevul_valid.jsonl"
baixar_drive 12b1QkCwW0SC6l9KvxSmMe4jHF7VhjwCa "$DEST/primevul/primevul_train.jsonl"
baixar_drive 1WIZSzVwcLI-wFbSIvxh0Yak8qjbDWyd5 "$DEST/primevul/file_info.json"

V="$DEST/ventivul/ventivul.csv"
[ -s "$V" ] || curl -sL --fail --retry 3 -o "$V" https://ndownloader.figshare.com/files/67579809 || echo "FALHOU: $V"

cd "$DEST" && find . -type f ! -name "*.part" ! -name "*.sha256" | sort | xargs sha256sum | tee "$DEST/arquivos.sha256"
ls -l "$DEST"/primevul "$DEST"/ventivul
echo "md5 do ventivul.csv (o Figshare publica e1a78082e1d83342eba23342a4e17572):"
md5sum "$V"

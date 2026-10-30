#!/bin/bash
# Confere que os scripts de contagem rodam a partir desta pasta (CWE-416 e teste do PrimeVul v0.1).
D="$(cd "$(dirname "$0")" && pwd)"
python3 "$D/contar_cwe416.py" /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul | tail -3
bash "$D/contar_primevul.sh" test | grep -E "total|ficam"
bash "$D/estrutura_ventivul.sh" contar_ventivul.py | grep -E "^positivos|^negativos"

#!/usr/bin/env python3
# Diagnostico (20/10/2026) do excesso sobre o acaso das arenas, na versao da abertura de 18/10.
# (1) confirma que o excesso gravado = VP - A*P/N_neg (N = so as nao vulneraveis);
# (2) calcula o excesso como o PREREGISTRO_ARENAS.md (Decisao J) define: VP - A*P/(P+N_neg);
# (3) diz se o piso mudaria. Nao grava nada.
# Em 21/10/2026 a abertura foi refeita com a conta corrigida, e a versao de 18/10 passou a se chamar
# resultado_arenas_anterior_20261021_123410.json; o diagnostico le essa versao.
import json
import statistics as st

J = json.load(open("/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul/arenas/"
                   "resultado_arenas_anterior_20261021_123410.json", encoding="utf-8"))
BR = ["M_raw", "M_cur", "M_ctrl_g2026", "M_ctrl_g2027", "M_ctrl_g2028", "M_ctrl_g2029", "M_ctrl_g2030"]
for a, r in J["arenas"].items():
    P, N = r["P"], r["N"]
    print(f"== {a}: P {P}, N (nao vuln.) {N}, total {P + N}; fator do acaso gravado/pre-registrado = "
          f"{(P + N) / N:.4f}")
    piso_corrigido = True
    for b in BR:
        ps = r["por_semente"][b]
        grav, refeito, certo = [], [], []
        for s, d in ps.items():
            g = d["geral"]
            tp, fp = g["tp"], g["fp"]
            grav.append(g["excesso"])
            refeito.append(tp - (tp + fp) * P / N)
            certo.append(tp - (tp + fp) * P / (P + N))
        dif = max(abs(x - y) for x, y in zip(grav, refeito))
        mg, mc = st.median(grav), st.median(certo)
        if b != "M_raw" and mc > 2:
            piso_corrigido = False
        print(f"  {b:13s} gravado {mg:8.2f} (= VP - A*P/N_neg? maior dif {dif:.1e}) | pre-registrado {mc:8.2f}")
    print(f"  piso gravado: {r['piso']} | piso com a conta pre-registrada: {piso_corrigido}")

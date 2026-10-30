#!/usr/bin/env python3
"""Pecas comuns do ReVeal do TCC: caminhos, hiperparametros, bracos e os dois modelos.

O QUE VEM DO CODIGO OFICIAL (licenca MIT) e o que e nosso. Os dois modelos que decidem o
resultado sao COPIADOS, nao reescritos:
  - GGNNSum            <- github.com/saikat107/Devign, commit be2f831, modules/model.py:64-82
  - MetricLearningModel <- github.com/VulDetProject/ReVeal, commit ca31b78,
                           Vuld_SySe/representation_learning/models.py
No MetricLearningModel a unica mudanca e a distancia da triplet loss, 1 - |cosseno| como no
artigo (PLANO_TREINO.md §3.1). A unica mudanca no GGNNSum e a interface de entrada: o original recebe o objeto de lote do Devign
(`batch.get_network_inputs`, `de_batchify_graphs`); aqui recebe o grafo DGL em lote, os vetores
de no e os tipos de aresta, e soma os nos com `dgl.sum_nodes` — a mesma soma que o original faz
sobre o tensor preenchido com zeros.

HIPERPARAMETROS: cada um com a fonte, conforme PLANO_TREINO.md (§3.1, §3.2, D9-D12) e
PIPELINE_REVEAL.md (§2). [A] = artigo, preprint; [D] = Devign; [R] = ReVeal.
"""

import os
import random

import numpy as np
import torch
from torch import nn

# --------------------------------------------------------------------------- caminhos
REPO = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul"
TRAVERSAL = os.path.join(REPO, "traversal")
INDICE = os.path.join(TRAVERSAL, "dataset_indice_v3.tsv")
BRACOS_DIR = os.path.join(TRAVERSAL, "conjuntos_treino_v3")
RELATORIO = os.path.join(REPO, "saida_final", "relatorio_extracao.csv")
GRUPOS = os.path.expanduser("~/curadoria/dataset_v3/grupos")
COMPLETA = os.path.expanduser("~/curadoria/completa")
SAIDA = os.path.expanduser("~/curadoria/modelo")
VETORES = os.path.join(SAIDA, "vetores")

# --------------------------------------------------------------------------- hiperparametros
W2V_DIM = 100           # [A] Tabela 2
W2V_JANELA = 10         # [A] Tabela 2 (o codigo nao passa window: segue o artigo, §3.1)
W2V_MIN_COUNT = 1       # [R] word2vec_train.py:37 (--min_occ 1); o artigo nao diz
W2V_EPOCAS_EXTRA = 100  # [R] word2vec_train.py:17-18 (5 do construtor + 100 chamadas de 1)
W2V_WORKERS = 8         # [R] word2vec_train.py:15

GGNN_OCULTA = 200       # [A] Tabela 2; [D] main.py:30
GGNN_PASSOS = 8         # [A] Tabela 2 (o codigo usa 6; segue o artigo, §3.1)
GGNN_LR = 1e-4          # [A] Tabela 2; [D] main.py:72
GGNN_WD = 1e-3          # [D] main.py:72; o artigo nao diz
GGNN_LOTE = 128         # [D] main.py:32; o artigo nao diz
GGNN_MAX_EPOCAS = 500   # [A] §5.1, "iteracao" lida como epoca (D11)
GGNN_PACIENCIA = 50     # [A] §5.1, em epocas, F1 na validacao (D11)
GGNN_SEMENTE = 1000     # [D] main.py:18-19
LIMIAR = 0.5            # D12: o do ReVeal

F2_OCULTA = 256         # [A] Tabela 2; [R] representation_learning_api.py:14
F2_DROPOUT = 0.2        # [A] Tabela 2
F2_ALFA = 0.5           # gama do artigo (margem); [R] api_test.py
F2_LAMBDA1 = 0.5        # alfa do artigo; [R] api_test.py
F2_LAMBDA2 = 0.001      # beta do artigo; [R] api_test.py
F2_LR = 1e-3            # [A] Tabela 2; Adam padrao em [R]
F2_LOTE = 128           # [R] api_test.py:81
F2_EPOCAS = 100         # [A] §5.1; [R] representation_learning_api.py:16
F2_PACIENCIA = 5        # [A] §5.1; [R] api_test.py:81
F2_SEMENTES = list(range(1000, 1030))  # PLANO_TREINO.md §5: 30 repeticoes
SMOTE_SEMENTE = 1000    # [R] graph_dataset.py:53

PAR_NEG_SEMENTE = 5050  # PLANO_TREINO.md §5.1: os 523 negativos do par balanceado
CONTROLES = ["M_ctrl_g%d" % s for s in range(2026, 2031)]
BRACOS_PRINCIPAIS = ["M_raw", "M_cur"] + CONTROLES
BRACOS_PAR = [b + "_bal" for b in ["M_cur"] + CONTROLES]
TODOS_BRACOS = BRACOS_PRINCIPAIS + BRACOS_PAR


def fixar_sementes(s):
    random.seed(s)
    np.random.seed(s)
    torch.manual_seed(s)
    torch.cuda.manual_seed_all(s)


# --------------------------------------------------------------------------- dados
def ler_grafos():
    """Indice dos grafos vetorizados: lista de dicts na ordem dos arrays em VETORES."""
    caminho = os.path.join(VETORES, "grafos.tsv")
    linhas = open(caminho, encoding="utf-8").read().splitlines()
    cab = linhas[0].split("\t")
    saida = []
    for l in linhas[1:]:
        d = dict(zip(cab, l.split("\t")))
        for k in ("rotulo", "n_nos", "n_arestas", "ini_no", "ini_aresta"):
            d[k] = int(d[k])
        saida.append(d)
    return saida


def positivos_do_braco(nome):
    """Ids dos positivos de treino de um braco (o arquivo do braco base, para os _bal)."""
    base = nome[:-4] if nome.endswith("_bal") else nome
    linhas = open(os.path.join(BRACOS_DIR, base + ".tsv"), encoding="utf-8").read().splitlines()
    return [l.split("\t")[0] for l in linhas[1:]]


def negativos_do_braco(nome, grafos):
    """Os 14.394 negativos de treino; nos _bal, os 523 sorteados uma vez com a semente 5050."""
    neg = sorted(g["id"] for g in grafos if g["particao"] == "treino" and g["rotulo"] == 0)
    if not nome.endswith("_bal"):
        return neg
    n = len(positivos_do_braco("M_cur"))
    return sorted(random.Random(PAR_NEG_SEMENTE).sample(neg, n))


# --------------------------------------------------------------------------- modelos
class GGNNSum(nn.Module):
    """[D] modules/model.py:64-82, com a entrada adaptada (ver o cabecalho)."""

    def __init__(self, input_dim, output_dim, max_edge_types, num_steps=8):
        super(GGNNSum, self).__init__()
        from dgl.nn import GatedGraphConv
        self.inp_dim = input_dim
        self.out_dim = output_dim
        self.max_edge_types = max_edge_types
        self.num_timesteps = num_steps
        self.ggnn = GatedGraphConv(in_feats=input_dim, out_feats=output_dim, n_steps=num_steps,
                                   n_etypes=max_edge_types)
        self.classifier = nn.Linear(in_features=output_dim, out_features=1)
        self.sigmoid = nn.Sigmoid()

    def vetor_da_funcao(self, g, features, edge_types):
        """x_g: a soma dos estados dos nos depois da GGNN — o que vai para a Fase II."""
        import dgl
        outputs = self.ggnn(g, features, edge_types)
        g.ndata["_h"] = outputs
        soma = dgl.sum_nodes(g, "_h")
        g.ndata.pop("_h")
        return soma

    def forward(self, g, features, edge_types):
        ggnn_sum = self.classifier(self.vetor_da_funcao(g, features, edge_types))
        return self.sigmoid(ggnn_sum).squeeze(dim=-1)


class MetricLearningModel(nn.Module):
    """[R] Vuld_SySe/representation_learning/models.py, copiado; uma mudanca, a distancia (abaixo)."""

    def __init__(self, input_dim, hidden_dim, dropout_p=0.2, aplha=0.5, lambda1=0.5, lambda2=0.001,
                 num_layers=1):
        super(MetricLearningModel, self).__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.internal_dim = int(hidden_dim / 2)
        self.dropout_p = dropout_p
        self.alpha = aplha
        self.layer1 = nn.Sequential(
            nn.Linear(in_features=self.input_dim, out_features=self.hidden_dim, bias=True),
            nn.ReLU(),
            nn.Dropout(p=self.dropout_p)
        )
        self.feature = nn.ModuleList([nn.Sequential(
            nn.Linear(in_features=self.hidden_dim, out_features=self.internal_dim, bias=True),
            nn.ReLU(),
            nn.Dropout(p=self.dropout_p),
            nn.Linear(in_features=self.internal_dim, out_features=self.hidden_dim, bias=True),
            nn.ReLU(),
            nn.Dropout(p=self.dropout_p),
        ) for _ in range(num_layers)])
        self.classifier = nn.Sequential(
            nn.Linear(in_features=self.hidden_dim, out_features=2),
            nn.LogSoftmax(dim=-1)
        )
        self.lambda1 = lambda1
        self.lambda2 = lambda2
        self.loss_function = nn.NLLLoss(reduction='none')

    def extract_feature(self, x):
        out = self.layer1(x)
        for layer in self.feature:
            out = layer(out)
        return out

    def forward(self, example_batch, targets=None, positive_batch=None, negative_batch=None):
        train_mode = (positive_batch is not None and
                      negative_batch is not None and
                      targets is not None)
        h_a = self.extract_feature(example_batch)
        y_a = self.classifier(h_a)
        probs = torch.exp(y_a)
        batch_loss = None
        if targets is not None:
            ce_loss = self.loss_function(input=y_a, target=targets)
            batch_loss = ce_loss.sum(dim=-1)
        if train_mode:
            h_p = self.extract_feature(positive_batch)
            h_n = self.extract_feature(negative_batch)
            dot_p = h_a.unsqueeze(dim=1) \
                .bmm(h_p.unsqueeze(dim=-1)).squeeze(-1).squeeze(-1)
            dot_n = h_a.unsqueeze(dim=1) \
                .bmm(h_n.unsqueeze(dim=-1)).squeeze(-1).squeeze(-1)
            mag_a = torch.norm(h_a, dim=-1)
            mag_p = torch.norm(h_p, dim=-1)
            mag_n = torch.norm(h_n, dim=-1)
            # UNICA mudanca de calculo: o artigo ([A] eq. 5) usa 1 - |cosseno|; o codigo, 1 - cosseno.
            # PLANO_TREINO.md §3.1: segue o artigo.
            D_plus = 1 - torch.abs(dot_p / (mag_a * mag_p))
            D_minus = 1 - torch.abs(dot_n / (mag_a * mag_n))
            trip_loss = self.lambda1 * torch.abs((D_plus - D_minus + self.alpha))
            ce_loss = self.loss_function(input=y_a, target=targets)
            l2_loss = self.lambda2 * (mag_a + mag_p + mag_n)
            total_loss = ce_loss + trip_loss + l2_loss
            batch_loss = (total_loss).sum(dim=-1)
        return probs, h_a, batch_loss

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF.EXE — servidor local para o PWA.

Porquê é preciso um servidor?
  Um Progressive Web App só instala/funciona num "contexto seguro":
  https OU localhost. Abrir o index.html com file:// NÃO chega — o
  service worker não arranca. Este script serve o jogo em localhost.

Espelha também os endpoints (/api/pin, /api/sessao, /api/admin, ...) para
quem quiser atacá-los com scripts Python a partir do terminal. Dentro do
browser quem responde é o service worker; os dois lados dizem o mesmo.

Arranca:  python3 servidor.py
Abre:     http://localhost:8000
Desliga:  Ctrl+C
Só usa a biblioteca-padrão. Nada para instalar.
"""

import base64
import http.server
import json
import os
import socketserver
import urllib.parse
import webbrowser

# ─────────────────────────────────────────────────────────────────────
#  PERSONALIZA (tem de bater certo com o sw.js)
# ─────────────────────────────────────────────────────────────────────

PORTA = 8000
PIN_DO_COFRE = "1984"          # igual ao PIN_DO_COFRE do sw.js
TOKEN_SESSAO = "sess-b17e-ok"  # igual ao do sw.js

BANDEIRA_RECON = "CTF{recon_paga_sempre_o_bilhete}"
BANDEIRA_CABECALHOS = "CTF{os_cabecalhos_tambem_falam}"
BANDEIRA_COFRE = "CTF{dez_mil_hipoteses_zero_limites}"
BANDEIRA_JWT = "CTF{alg_none_e_sempre_um_convite}"

# ─────────────────────────────────────────────────────────────────────

BANDEIRA_SQLI = "CTF{uma_aspa_solta_abre_a_porta}"
UTILIZADORES = [{"utilizador": "admin", "senha": "x8Q!p_nunca_vais_adivinhar_isto_2011"}]

RAIZ = os.path.dirname(os.path.abspath(__file__))
PUBLICO = os.path.join(RAIZ, "docs")

ROBOTS = """# CTF.EXE — o robots.txt de sempre
User-agent: *
Allow: /
Disallow: /backup-nsm/

# nota interna: a pasta backup-nsm ficou esquecida desde a migracao.
# ninguem la vai -- o robots.txt trata disso.
"""

NOTAS = """notas-migracao.txt

Pendentes de quando mudamos de servidor:
  - apagar esta pasta                    [por fazer]
  - deixar de guardar segredos em texto  [por fazer]

Token de servico temporario (remover!):
  %s

Se estas a ler isto, o "temporario" durou anos.
""" % BANDEIRA_RECON


def _dividir_topo(texto, operador):
    alvo = " " + operador + " "
    partes, atual, dentro, i = [], "", False, 0
    while i < len(texto):
        c = texto[i]
        if c == "'":
            dentro = not dentro
            atual += c
            i += 1
            continue
        if not dentro and texto[i:i + len(alvo)].upper() == alvo:
            partes.append(atual)
            atual = ""
            i += len(alvo)
            continue
        atual += c
        i += 1
    partes.append(atual)
    return partes


def _dividir_igual(texto):
    dentro = False
    for i, c in enumerate(texto):
        if c == "'":
            dentro = not dentro
        elif c == "=" and not dentro:
            return [texto[:i], texto[i + 1:]]
    return [texto]


def _valor(token, linha):
    token = token.strip()
    if len(token) >= 2 and token.startswith("'") and token.endswith("'"):
        return token[1:-1]
    return linha.get(token.lower())


def _comparar(expr, linha):
    lados = _dividir_igual(expr)
    if len(lados) != 2:
        return False
    return _valor(lados[0], linha) == _valor(lados[1], linha)


def avaliar_where(clause, linha):
    corte = clause.find("--")
    if corte >= 0:
        clause = clause[:corte]
    clause = clause.strip()
    if not clause:
        return False
    return any(
        all(_comparar(termo, linha) for termo in _dividir_topo(grupo, "AND"))
        for grupo in _dividir_topo(clause, "OR")
    )


def login_vulneravel(utilizador, senha):
    clause = "utilizador = '%s' AND senha = '%s'" % (utilizador, senha)
    return any(avaliar_where(clause, linha) for linha in UTILIZADORES)


def descodificar_segmento(seg):
    try:
        resto = len(seg) % 4
        if resto:
            seg += "=" * (4 - resto)
        return json.loads(base64.urlsafe_b64decode(seg.encode()))
    except Exception:
        return None


class Manipulador(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLICO, **kwargs)

    def log_message(self, *_):
        pass

    def _json(self, dados, codigo=200, cabecalhos=None):
        corpo = json.dumps(dados, ensure_ascii=False).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        if cabecalhos:
            for chave, valor in cabecalhos.items():
                self.send_header(chave, valor)
        self.end_headers()
        self.wfile.write(corpo)

    def _texto(self, texto):
        corpo = texto.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_GET(self):
        alvo = urllib.parse.urlparse(self.path)
        rota = alvo.path
        param = urllib.parse.parse_qs(alvo.query)

        if rota == "/robots.txt":
            return self._texto(ROBOTS)
        if rota in ("/backup-nsm/notas-migracao.txt",):
            return self._texto(NOTAS)
        if rota in ("/backup-nsm", "/backup-nsm/"):
            return self._texto(
                "Index of /backup-nsm/\n\n  notas-migracao.txt   2011-11-03   1 KB\n"
            )

        if rota == "/api/ola":
            return self._json(
                {"estado": "online", "dica": "nem tudo vem no corpo da resposta"},
                cabecalhos={"X-Bandeira": BANDEIRA_CABECALHOS},
            )

        if rota == "/api/sessao":
            return self._json({"token": TOKEN_SESSAO, "expira_em": 999999})

        if rota == "/api/pin":
            codigo = param.get("codigo", [""])[0]
            token = param.get("token", [""])[0]
            if token != TOKEN_SESSAO:
                return self._json(
                    {"erro": "sem sessao valida. pede um token a /api/sessao primeiro."}, 401
                )
            if not (codigo.isdigit() and len(codigo) == 4):
                return self._json({"aberto": False, "erro": "codigo = 4 digitos"}, 400)
            if codigo == PIN_DO_COFRE:
                return self._json({"aberto": True, "bandeira": BANDEIRA_COFRE})
            return self._json({"aberto": False})

        if rota == "/api/login":
            utilizador = param.get("utilizador", [""])[0]
            senha = param.get("senha", [""])[0]
            if not utilizador and not senha:
                return self._json({"erro": "faltam credenciais"}, 400)
            if login_vulneravel(utilizador, senha):
                return self._json({"entrou": True, "como": "admin", "bandeira": BANDEIRA_SQLI})
            return self._json({"entrou": False, "nota": "credenciais invalidas"}, 401)

        return super().do_GET()

    def do_POST(self):
        rota = urllib.parse.urlparse(self.path).path
        if rota != "/api/admin":
            return self._json({"erro": "rota desconhecida"}, 404)
        return self._tratar_admin()

    def do_GET_admin_alias(self):
        pass

    def _tratar_admin(self):
        auth = self.headers.get("Authorization", "")
        token = auth.split(" ", 1)[1] if " " in auth else auth
        partes = token.split(".")
        if len(partes) < 2:
            return self._json({"erro": "falta o token. Authorization: Bearer <jwt>"}, 401)
        cabecalho = descodificar_segmento(partes[0])
        carga = descodificar_segmento(partes[1])
        if not cabecalho or not carga:
            return self._json({"erro": "token ilegivel"}, 400)
        alg = str(cabecalho.get("alg", "")).lower()
        if alg == "none" and carga.get("role") == "admin":
            return self._json({"acesso": "admin", "bandeira": BANDEIRA_JWT})
        if carga.get("role") != "admin":
            return self._json({"acesso": carga.get("role", "?"), "nota": "so o admin ve a bandeira"}, 403)
        return self._json({"erro": "assinatura exigida", "dica": "e se nao houvesse alg?"}, 403)


# /api/admin também aceita GET (com header Authorization), por conveniência
_do_GET_original = Manipulador.do_GET
def _do_GET(self):
    if urllib.parse.urlparse(self.path).path == "/api/admin":
        return self._tratar_admin()
    return _do_GET_original(self)
Manipulador.do_GET = _do_GET


class Servidor(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def arrancar():
    with Servidor(("127.0.0.1", PORTA), Manipulador) as servidor:
        endereco = "http://localhost:%d" % PORTA
        print("")
        print("  CTF.EXE (PWA) a correr em %s" % endereco)
        print("  Sete desafios. Ctrl+C para desligar.")
        print("")
        try:
            webbrowser.open(endereco)
        except Exception:
            pass
        try:
            servidor.serve_forever()
        except KeyboardInterrupt:
            print("\n  Servidor desligado.\n")


if __name__ == "__main__":
    arrancar()

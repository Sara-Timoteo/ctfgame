# CTF.EXE

Um mini *Capture The Flag* de aniversário: oito desafios de segurança,
num **PWA** que se instala e funciona **offline**. Feito em HTML, CSS e
JavaScript, com um service worker que serve a app e faz de "backend"
que os desafios atacam. Há também um launcher opcional em Python.

## Jogar (não precisas de instalar nada)

Basta abrir a página publicada — ela corre no browser e, no fim, pode
instalar-se como app. Depois de instalada, funciona sem net.

Há duas portas de entrada, ambas publicadas:

- `.../` — o jogo directamente (`docs/index.html`).
- `.../convite.html` — um cartão de aniversário que apresenta a missão e
  tem um botão para entrar no jogo. Bom para partilhar primeiro.

Dentro do jogo, o botão **Descarregar .zip** (no rodapé) faz a própria app
empacotar-se num `.zip` — para quem quiser guardar ou re-hospedar a cópia.
Funciona offline, sem bibliotecas externas.

> **Publicar no GitHub Pages:** em *Settings → Pages → Build and
> deployment*, escolhe *Deploy from a branch*, ramo `main`, pasta
> `/docs`. Em 1–2 minutos o jogo fica em
> `https://<utilizador>.github.io/<repo>/`.

Como está tudo em caminhos relativos, funciona debaixo desse subcaminho
sem configuração extra.

## Os oito desafios

1. **RECON** — recon a um `robots.txt`
2. **CABECALHOS** — bandeira num cabeçalho HTTP de resposta
3. **CAMADAS** — base64 → hex → ROT13
4. **VIGENERE** — cifra de Vigenère
5. **COFRE** — sessão + brute force a um PIN sem *rate limit*
6. **SQLI** — SQL injection num login (`admin'--` ou `' OR '1'='1`)
7. **JWT** — forjar um token com `alg:none`
8. **HASH** — ataque de dicionário a um SHA-256

Cada desafio resolve-se no próprio browser (as pistas dão os comandos para
a consola, F12). A validação é por SHA-256; o progresso fica guardado no
browser.

## Nota honesta

Num jogo 100% do lado do cliente, nada é *verdadeiramente* secreto — quem
insistir chega ao `docs/sw.js` pelas DevTools. É de propósito: **segredos
no cliente não são segredos**. Os desafios são sobre técnica.

## Opcional: atacar com Python (local)

Para quem quiser atacar os endpoints com scripts reais a partir do
terminal, `python3 servidor.py` serve o jogo em `http://localhost:8000` e
espelha os mesmos endpoints. (A pasta `solucoes/` tem spoilers e por isso
está fora do repositório publicado.)

## Estrutura

```
docs/        → a app publicada (GitHub Pages aponta para aqui)
servidor.py  → launcher/alvo local, opcional
solucoes/    → soluções (spoilers, ignoradas pelo git)
```

Feito com carinho. 🎂

/* CTF.EXE — service worker.
 *
 * Faz duas coisas:
 *   1. Guarda a app em cache para funcionar offline (é o que a torna PWA).
 *   2. É o "servidor" que os desafios atacam. Intercepta /robots.txt,
 *      /api/sessao, /api/pin, /api/admin, etc. e responde ele próprio.
 *
 * Estás a ler o alvo. Nada aqui está encriptado de verdade — num jogo
 * client-side nunca está, e essa é uma das lições. O que conta é a técnica.
 */

const CACHE = "ctf-exe-v6";

const APP_SHELL = [
  "./",
  "./index.html",
  "./convite.html",
  "./estilo.css",
  "./jogo.js",
  "./qr.js",
  "./manifest.webmanifest",
  "./lista-palavras.txt",
  "./icones/icone-192.png",
  "./icones/icone-512.png",
];

// ─────────────────────────────────────────────────────────────────────
//  Segredos servidos pelo "backend". Extrai-os com a técnica de cada nível.
// ─────────────────────────────────────────────────────────────────────

const BANDEIRA_RECON = "CTF{recon_paga_sempre_o_bilhete}";
const BANDEIRA_CABECALHOS = "CTF{os_cabecalhos_tambem_falam}";
const BANDEIRA_COFRE = "CTF{dez_mil_hipoteses_zero_limites}";
const BANDEIRA_JWT = "CTF{alg_none_e_sempre_um_convite}";
const BANDEIRA_SQLI = "CTF{uma_aspa_solta_abre_a_porta}";

const PIN_DO_COFRE = "1984";          // 4 dígitos — muda no servidor.py também
const TOKEN_SESSAO = "sess-b17e-ok";  // emitido por /api/sessao

// "base de dados" do desafio SQLI. A senha do admin é insondável de propósito.
const UTILIZADORES = [
  { utilizador: "admin", senha: "x8Q!p_nunca_vais_adivinhar_isto_2011" },
];

const ROBOTS = `# CTF.EXE — o robots.txt de sempre
User-agent: *
Allow: /
Disallow: /backup-nsm/

# nota interna: a pasta backup-nsm ficou cá esquecida desde a migração.
# ninguém lá vai — o robots.txt trata disso. (foi o que dissemos em 2011.)
`;

const NOTAS = `notas-migracao.txt

Pendentes de quando mudámos de servidor:
  - apagar esta pasta                    [por fazer]
  - deixar de guardar segredos em texto  [por fazer]

Token de serviço temporário (remover!):
  ${BANDEIRA_RECON}

Se estás a ler isto, o "temporário" durou anos.
`;

// ─────────────────────────────────────────────────────────────────────
//  Utilidades
// ─────────────────────────────────────────────────────────────────────

function json(objecto, opcoes) {
  const cabecalhos = { "Content-Type": "application/json; charset=utf-8" };
  if (opcoes && opcoes.headers) Object.assign(cabecalhos, opcoes.headers);
  return new Response(JSON.stringify(objecto), {
    status: (opcoes && opcoes.status) || 200,
    headers: cabecalhos,
  });
}

function texto(corpo, tipo) {
  return new Response(corpo, {
    headers: { "Content-Type": (tipo || "text/plain") + "; charset=utf-8" },
  });
}

// ── Avaliador ingénuo de SQL (o coração do desafio SQLI) ──────────────
// Simula uma consulta montada por concatenação de strings, vulnerável a
// injecção. Não é um motor SQL real — chega para partir a autenticação.
function dividirTopo(texto, operador) {
  const alvo = " " + operador + " ";
  const partes = [];
  let atual = "", dentro = false, i = 0;
  while (i < texto.length) {
    const c = texto[i];
    if (c === "'") { dentro = !dentro; atual += c; i += 1; continue; }
    if (!dentro && texto.substr(i, alvo.length).toUpperCase() === alvo) {
      partes.push(atual); atual = ""; i += alvo.length; continue;
    }
    atual += c; i += 1;
  }
  partes.push(atual);
  return partes;
}
function dividirIgual(texto) {
  let dentro = false;
  for (let i = 0; i < texto.length; i++) {
    const c = texto[i];
    if (c === "'") dentro = !dentro;
    else if (c === "=" && !dentro) return [texto.slice(0, i), texto.slice(i + 1)];
  }
  return [texto];
}
function valorSql(token, linha) {
  token = token.trim();
  if (token.startsWith("'") && token.endsWith("'") && token.length >= 2) {
    return token.slice(1, -1);
  }
  return linha[token.toLowerCase()];
}
function compararSql(expr, linha) {
  const lados = dividirIgual(expr);
  if (lados.length !== 2) return false;
  return valorSql(lados[0], linha) === valorSql(lados[1], linha);
}
function avaliarWhere(clause, linha) {
  const corte = clause.indexOf("--");           // comentário SQL
  if (corte >= 0) clause = clause.slice(0, corte);
  clause = clause.trim();
  if (!clause) return false;
  return dividirTopo(clause, "OR").some((grupo) =>
    dividirTopo(grupo, "AND").every((termo) => compararSql(termo, linha))
  );
}
function loginVulneravel(utilizador, senha) {
  const clause = "utilizador = '" + utilizador + "' AND senha = '" + senha + "'";
  return UTILIZADORES.some((linha) => avaliarWhere(clause, linha));
}

// descodifica um segmento base64url de um JWT (sem verificar nada)
function descodificarSegmento(seg) {
  try {
    let s = seg.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return JSON.parse(atob(s));
  } catch (e) {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────
//  Ciclo de vida
// ─────────────────────────────────────────────────────────────────────

self.addEventListener("install", (evento) => {
  evento.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (evento) => {
  evento.waitUntil(
    caches.keys().then((chaves) =>
      Promise.all(chaves.filter((c) => c !== CACHE).map((c) => caches.delete(c)))
    ).then(() => self.clients.claim())
  );
});

// ─────────────────────────────────────────────────────────────────────
//  O "backend": intercepta e responde
// ─────────────────────────────────────────────────────────────────────

self.addEventListener("fetch", (evento) => {
  const url = new URL(evento.request.url);

  // só tratamos pedidos do próprio jogo
  if (url.origin !== self.location.origin) return;

  const caminho = url.pathname.replace(/\/index\.html$/, "/");

  // ── Desafio 1: RECON ──────────────────────────────────────────────
  if (caminho.endsWith("/robots.txt")) {
    return evento.respondWith(texto(ROBOTS));
  }
  if (caminho.endsWith("/backup-nsm/notas-migracao.txt")) {
    return evento.respondWith(texto(NOTAS));
  }
  if (caminho.endsWith("/backup-nsm/") || caminho.endsWith("/backup-nsm")) {
    return evento.respondWith(texto(
      "Index of /backup-nsm/\n\n  notas-migracao.txt   2011-11-03   1 KB\n"
    ));
  }

  // ── Desafio 2: CABEÇALHOS ─────────────────────────────────────────
  // resposta banal, mas com uma bandeira num cabeçalho pouco visto.
  if (caminho.endsWith("/api/ola")) {
    return evento.respondWith(json(
      { estado: "online", dica: "nem tudo vem no corpo da resposta" },
      { headers: { "X-Bandeira": BANDEIRA_CABECALHOS } }
    ));
  }

  // ── Desafio 5: COFRE (sessão + brute force sem limite) ────────────
  if (caminho.endsWith("/api/sessao")) {
    return evento.respondWith(json({ token: TOKEN_SESSAO, expira_em: 999999 }));
  }
  if (caminho.endsWith("/api/pin")) {
    const codigo = url.searchParams.get("codigo") || "";
    const token = url.searchParams.get("token") || "";
    if (token !== TOKEN_SESSAO) {
      return evento.respondWith(json(
        { erro: "sem sessão válida. pede um token a /api/sessao primeiro." },
        { status: 401 }
      ));
    }
    if (!/^\d{4}$/.test(codigo)) {
      return evento.respondWith(json({ aberto: false, erro: "código = 4 dígitos" }, { status: 400 }));
    }
    if (codigo === PIN_DO_COFRE) {
      return evento.respondWith(json({ aberto: true, bandeira: BANDEIRA_COFRE }));
    }
    return evento.respondWith(json({ aberto: false }));  // sem atraso, sem bloqueio
  }

  // ── Desafio 6: JWT com alg:none ───────────────────────────────────
  if (caminho.endsWith("/api/admin")) {
    const auth = evento.request.headers.get("Authorization") || "";
    const partes = auth.replace(/^Bearer\s+/i, "").split(".");
    if (partes.length < 2) {
      return evento.respondWith(json(
        { erro: "falta o token. Authorization: Bearer <jwt>" }, { status: 401 }
      ));
    }
    const cabecalho = descodificarSegmento(partes[0]);
    const carga = descodificarSegmento(partes[1]);
    if (!cabecalho || !carga) {
      return evento.respondWith(json({ erro: "token ilegível" }, { status: 400 }));
    }
    // a falha: aceitamos alg:none e confiamos no que o token diz ser.
    const alg = String(cabecalho.alg || "").toLowerCase();
    if (alg === "none" && carga.role === "admin") {
      return evento.respondWith(json({ acesso: "admin", bandeira: BANDEIRA_JWT }));
    }
    if (carga.role !== "admin") {
      return evento.respondWith(json(
        { acesso: carga.role || "?", nota: "só o admin vê a bandeira" }, { status: 403 }
      ));
    }
    return evento.respondWith(json(
      { erro: "assinatura exigida para este alg", dica: "e se não houvesse alg?" },
      { status: 403 }
    ));
  }

  // ── Desafio SQLI: login por concatenação de strings ──────────────
  if (caminho.endsWith("/api/login")) {
    const utilizador = url.searchParams.get("utilizador") || "";
    const senha = url.searchParams.get("senha") || "";
    if (!utilizador && !senha) {
      return evento.respondWith(json(
        { erro: "faltam credenciais",
          consulta: "SELECT * FROM utilizadores WHERE utilizador='' AND senha=''" },
        { status: 400 }
      ));
    }
    if (loginVulneravel(utilizador, senha)) {
      return evento.respondWith(json({ entrou: true, como: "admin", bandeira: BANDEIRA_SQLI }));
    }
    return evento.respondWith(json({ entrou: false, nota: "credenciais inválidas" }, { status: 401 }));
  }

  // ── Tudo o resto: cache primeiro, rede a seguir (offline-friendly) ─
  evento.respondWith(
    caches.match(evento.request).then((emCache) => {
      if (emCache) return emCache;
      return fetch(evento.request).then((resposta) => {
        if (evento.request.method === "GET" && resposta.ok && url.origin === self.location.origin) {
          const copia = resposta.clone();
          caches.open(CACHE).then((cache) => cache.put(evento.request, copia));
        }
        return resposta;
      }).catch(() => emCache);
    })
  );
});

/* CTF.EXE — lógica do jogo.
 * A validação é por SHA-256: comparo o hash da tua resposta com um hash
 * guardado. O texto certo nunca está aqui em claro. Os segredos que se
 * apanham por técnica (recon, brute force, jwt) vivem no service worker.
 */

(function () {
  "use strict";

  // ── PERSONALIZA: nome, mensagem e assinatura ────────────────────
  var NOME = "Colega";
  var MENSAGEM_FINAL =
    "Oito desafios, zero exploits contra mim: bem jogado.\n\n" +
    "Fizeste recon a um robots.txt, leste um cabeçalho que ninguém lê,\n" +
    "descascaste três camadas de codificação, partiste um Vigenère,\n" +
    "abriste um cofre à bruta, injectaste SQL num login, forjaste um JWT\n" +
    "com alg:none e ainda crackaste um SHA-256 à conta de um dicionário.\n\n" +
    "Este jogo foi escrito de propósito para ti, porque és a única\n" +
    "pessoa que eu conheço que acha 'vamos ver o robots.txt' divertido.\n\n" +
    "Parabéns. Que este ano te traga poucos incidentes e muitos logs limpos.";
  var ASSINATURA = "— com carinho, Sara";

  // ── Desafios. As respostas estão só como hash SHA-256. ──────────
  var DESAFIOS = [
    {
      id: 1, codinome: "RECON",
      titulo: "O ficheiro que pede para ser ignorado",
      enunciado:
        "Todo o site publica um /robots.txt. Quem escreve essas regras\n" +
        "costuma listar exactamente aquilo que preferia esconder.\n\n" +
        "Abre  ./robots.txt  e segue o rasto até à bandeira.",
      hash: "c424e7880be05a121b7267b91729abcfa564ed7dc9a2d5ae535d680c4ea6bf3f",
      pistas: [
        "Um robots.txt tem linhas Disallow. Cada uma é um caminho no servidor.",
        "O caminho proibido é uma pasta. Espreita lá dentro pelo browser.",
        "Vai a ./backup-nsm/notas-migracao.txt",
      ],
    },
    {
      id: 2, codinome: "CABECALHOS",
      titulo: "Nem tudo vem no corpo da resposta",
      enunciado:
        "Há um endpoint tranquilo em  ./api/ola  que responde um JSON\n" +
        "sem graça. Mas uma resposta HTTP é mais do que o corpo.\n\n" +
        "Inspecciona os cabeçalhos da resposta e traz a bandeira.",
      hash: "bf140bb0ddfdc84b7ca54034f7e2ce8065db6cf714ee27440efd5936735689f7",
      pistas: [
        "Abre as DevTools (F12) → separador Rede/Network, recarrega e clica no pedido a /api/ola.",
        "Olha os Response Headers. Há um cabeçalho que não devia lá estar: começa por X-.",
        "Na consola: fetch('./api/ola').then(r => r.headers.get('X-Bandeira')).then(console.log)",
      ],
    },
    {
      id: 3, codinome: "CAMADAS",
      titulo: "Três camadas, como uma cebola",
      enunciado:
        "Interceptámos isto. O estagiário jurou que estava 'encriptado\n" +
        "com camadas de segurança'. São mesmo camadas — mas de codificação.\n\n" +
        "Descasca-as todas.",
      carga: "NTA0NzUzN2I2NzY1NzI2NjVmNzA2ZTdhNmU3MTZlNjY1ZjcwNjI3YTYyNWY2ODdhNmU1ZjcwNzI2ZjYyNzk2ZTdk",
      hash: "ef1016a84665b4118028036db059dd87a2102b252a07e2772adfad98be93db89",
      pistas: [
        "Camada de fora: base64. Descodifica e vê o que sai — vai parecer só dígitos e letras a-f.",
        "Isso é hexadecimal. Converte os pares de hex em bytes/texto.",
        "Ainda não é legível? A última camada é ROT13. Roda 13 e lê.",
      ],
    },
    {
      id: 4, codinome: "VIGENERE",
      titulo: "César foi à escola e trouxe uma palavra-chave",
      enunciado:
        "Cifra polialfabética. Cada letra roda uma quantidade diferente,\n" +
        "ditada por uma palavra-chave que se repete.\n\n" +
        "A chave é uma coisa que um profissional de segurança guarda a sete\n" +
        "chaves — sete letras, em maiúsculas, sem acento. Decifra.",
      carga: "CTF{nmmvrhfw_zkeghi_g_gkjeu}",
      hash: "56b178d97ddec2c4e254e63b3736369fcb113f61b509dd7ce7dabbb725f7b939",
      pistas: [
        "É Vigenère. Só rodam as letras a-z; chavetas e underscores ficam na mesma.",
        "A palavra-chave tem 7 letras e é, literalmente, SEGREDO.",
        "Decifrar = subtrair o deslocamento de cada letra da chave (A=0, B=1, ...). Há decifradores online se preferires confirmar.",
      ],
    },
    {
      id: 5, codinome: "COFRE",
      titulo: "O cofre sem tentativas limitadas",
      enunciado:
        "O cofre está em  ./api/pin  e valida um código de 4 dígitos.\n" +
        "Mas primeiro exige uma sessão: pede um token a  ./api/sessao .\n\n" +
        "Depois é força bruta — não há bloqueio, não há atraso, não há captcha.\n" +
        "10 000 hipóteses. Escreve o script e abre o cofre.",
      hash: "908163328dfacefec53cf4ca9472a1392f107c2ed1b56a86043d82175e5cf4dd",
      pistas: [
        "Passo 1: token = (await (await fetch('./api/sessao')).json()).token",
        "Passo 2: para cada n de 0 a 9999, fetch('./api/pin?token='+token+'&codigo='+String(n).padStart(4,'0'))",
        "Quando a resposta trouxer {aberto:true, bandeira:...}, é essa a bandeira. (Também dá para atacar em Python contra o servidor.py — vê a pasta solucoes.)",
      ],
    },
    {
      id: 6, codinome: "SQLI",
      titulo: "A consulta que acredita no que lhe escrevem",
      enunciado:
        "Há um login em  ./api/login?utilizador=...&senha=...  que monta a\n" +
        "consulta à moda antiga, colando texto:\n\n" +
        "    SELECT * FROM utilizadores\n" +
        "    WHERE utilizador='...' AND senha='...'\n\n" +
        "Entra como admin sem saberes a senha. A bandeira vem no acesso.",
      hash: "d94ab618fac53ac3701003f69b1849c6954f0e5d7091e00544cdc511c8a8c386",
      pistas: [
        "As aspas do teu texto entram directas na consulta. E se fechasses a aspa tu próprio?",
        "Dois clássicos: no utilizador  admin'--  (comenta o resto da linha), ou na senha  ' OR '1'='1 .",
        "Na consola: fetch(\"./api/login?utilizador=\"+encodeURIComponent(\"admin'--\")+\"&senha=x\").then(r=>r.json()).then(console.log)",
      ],
    },
    {
      id: 7, codinome: "JWT",
      titulo: "Um token que se acredita a si próprio",
      enunciado:
        "O painel  ./api/admin  aceita um JWT no cabeçalho\n" +
        "  Authorization: Bearer <token> .\n\n" +
        "Tens um token de convidado (em baixo). O servidor tem uma falha\n" +
        "clássica: confia no campo 'alg' do próprio token. Forja um que\n" +
        "lhe faça abrir a porta ao admin.",
      carga:
        "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9." +
        "eyJ1c2VyIjogImNvbnZpZGFkbyIsICJyb2xlIjogInVzZXIifQ." +
        "YXNzaW5hdHVyYS1mYWxzYS1uYW8tdmVyaWZpY2FkYQ",
      hash: "30fcf2d78ceaf6e64d0c8d25a40d92ceff02104e85b3ad37ce10557625799f1f",
      pistas: [
        "Um JWT é  base64url(cabeçalho).base64url(carga).assinatura . Descodifica as duas primeiras partes e lê o JSON.",
        "A falha é 'alg:none': se o cabeçalho disser {\"alg\":\"none\"}, o servidor aceita sem assinatura. Muda também role para admin.",
        "Monta:  h=btoa('{\"alg\":\"none\",\"typ\":\"JWT\"}'); p=btoa('{\"user\":\"eu\",\"role\":\"admin\"}');  passa a base64url (troca +/ por -_, tira '='), junta com um ponto final e assinatura vazia:  h+'.'+p+'.'  e envia no header Authorization.",
      ],
    },
    {
      id: 8, codinome: "HASH",
      titulo: "Uma palavra, um dicionário, um resumo",
      enunciado:
        "Encontrámos este SHA-256 numa base de dados, sem sal nenhum:\n\n" +
        "    d93449f3e5b4bc1fb096a29c2fe7cb71b2694f1436f738741c35950fdb36fbaf\n\n" +
        "A palavra original está na lista que o jogo serve em\n" +
        "./lista-palavras.txt . Descobre qual é.\n" +
        "(A resposta é a palavra, não CTF{...}.)",
      hash: "d93449f3e5b4bc1fb096a29c2fe7cb71b2694f1436f738741c35950fdb36fbaf",
      pistas: [
        "Ataque de dicionário: percorre a lista, calcula o SHA-256 de cada palavra, compara com o alvo.",
        "Em JS (consola): fetch('./lista-palavras.txt').then(r=>r.text()).then(async t=>{ for(const p of t.split('\\n')){ const h=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(p.trim())))].map(x=>x.toString(16).padStart(2,'0')).join(''); if(h==='d93449f3e5b4bc1fb096a29c2fe7cb71b2694f1436f738741c35950fdb36fbaf'){console.log(p.trim());break;} } })",
        "A palavra está toda em minúsculas. Cuidado com o \\n no fim de cada linha — usa .trim().",
      ],
    },
  ];

  var CHAVE_ESTADO = "ctf-exe-progresso-v3";

  var estado = { activo: 0, resolvidos: carregarResolvidos(), jaConcluido: false };
  var pistasPedidas = {};
  var eventoInstalar = null;

  var el = {};
  ["arranque","linhas-arranque","moldura","destinatario","instalar","lista-desafios",
   "progresso","estado-rede","titulo-desafio","codinome","enunciado","carga-caixa",
   "carga-texto","copiar","pistas","resposta","enviar","veredicto","tecla-pista",
   "tecla-anterior","tecla-seguinte","tecla-reset","descarregar","final","bolo",
   "mensagem-final","assinatura"].forEach(function (id) {
    el[camel(id)] = document.getElementById(id);
  });
  function camel(s) { return s.replace(/-([a-z])/g, function (_, c) { return c.toUpperCase(); }); }

  var LINHAS_ARRANQUE = [
    "CTF.EXE  v2.1  [pwa]",
    "a carregar modulos ................ ok",
    "a registar service worker ......... ok",
    "a mapear superficie de ataque ..... 8 alvos",
    "",
    "oito desafios. modo offline pronto.",
    "",
  ];
  var BOLO = [
    "         .  .  .  .  .  .  .  .",
    "         |  |  |  |  |  |  |  |",
    "     _______________________________",
    "    |      P A R A B E N S          |",
    "    |_______________________________|",
    "   |_________________________________|",
  ].join("\n");

  /* ── Persistência ────────────────────────────────────────────── */
  function carregarResolvidos() {
    try { return JSON.parse(localStorage.getItem(CHAVE_ESTADO)) || {}; }
    catch (e) { return {}; }
  }
  function guardarResolvidos() {
    try { localStorage.setItem(CHAVE_ESTADO, JSON.stringify(estado.resolvidos)); }
    catch (e) {}
  }

  /* ── Hash ────────────────────────────────────────────────────── */
  function sha256Hex(texto) {
    var dados = new TextEncoder().encode(texto);
    return crypto.subtle.digest("SHA-256", dados).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) {
        return b.toString(16).padStart(2, "0");
      }).join("");
    });
  }
  function normalizar(texto) {
    return texto.trim().replace(/^["']|["']$/g, "").toLowerCase();
  }

  /* ── Desenho ─────────────────────────────────────────────────── */
  function estaResolvido(id) { return !!estado.resolvidos[id]; }
  function totalResolvidos() {
    return DESAFIOS.filter(function (d) { return estaResolvido(d.id); }).length;
  }

  function desenharLista() {
    el.listaDesafios.innerHTML = "";
    DESAFIOS.forEach(function (desafio, indice) {
      var feito = estaResolvido(desafio.id);
      var li = document.createElement("li");
      var botao = document.createElement("button");
      botao.type = "button";
      botao.className = "item-desafio" + (feito ? " feito" : "");
      botao.setAttribute("aria-current", indice === estado.activo ? "true" : "false");
      botao.innerHTML =
        '<span class="numero">' + desafio.id + "</span>" +
        "<span>" + desafio.codinome + "</span>" +
        '<span class="marca">' + (feito ? "[x]" : "[ ]") + "</span>";
      botao.addEventListener("click", function () { irPara(indice); });
      li.appendChild(botao);
      el.listaDesafios.appendChild(li);
    });
    el.progresso.textContent = totalResolvidos() + " de " + DESAFIOS.length + " resolvidos";
  }

  function desenharDesafio() {
    var desafio = DESAFIOS[estado.activo];
    var feito = estaResolvido(desafio.id);
    el.tituloDesafio.textContent = desafio.titulo;
    el.codinome.textContent = "desafio " + desafio.id + " · " + desafio.codinome;
    el.enunciado.textContent = desafio.enunciado;

    if (desafio.carga) {
      el.cargaTexto.textContent = desafio.carga;
      el.cargaCaixa.hidden = false;
    } else {
      el.cargaCaixa.hidden = true;
    }

    el.resposta.value = "";
    el.resposta.disabled = feito;
    el.enviar.disabled = feito;
    el.veredicto.textContent = feito ? "Resolvido." : "";
    el.veredicto.className = "veredicto" + (feito ? " certo" : "");
    desenharPistas();
  }

  function desenharPistas() {
    var desafio = DESAFIOS[estado.activo];
    el.pistas.innerHTML = "";
    (pistasPedidas[desafio.id] || []).forEach(function (texto, i) {
      var p = document.createElement("p");
      p.className = "pista";
      p.textContent = "pista " + (i + 1) + ": " + texto;
      el.pistas.appendChild(p);
    });
  }

  function irPara(indice) {
    if (indice < 0 || indice >= DESAFIOS.length) return;
    estado.activo = indice;
    desenharLista();
    desenharDesafio();
    el.resposta.focus();
  }

  /* ── Acções ──────────────────────────────────────────────────── */
  function validar() {
    var desafio = DESAFIOS[estado.activo];
    var tentativa = el.resposta.value;
    if (!tentativa.trim()) return;

    sha256Hex(normalizar(tentativa)).then(function (hash) {
      if (hash !== desafio.hash) {
        el.veredicto.textContent = "Não é essa. Tenta outra vez.";
        el.veredicto.className = "veredicto errado";
        el.resposta.select();
        return;
      }
      estado.resolvidos[desafio.id] = true;
      guardarResolvidos();
      el.veredicto.textContent = "Certo. Desafio " + desafio.id + " fechado.";
      el.veredicto.className = "veredicto certo";
      el.resposta.disabled = true;
      el.enviar.disabled = true;
      desenharLista();

      if (totalResolvidos() === DESAFIOS.length) {
        return setTimeout(mostrarFinal, 900);
      }
      var seguinte = DESAFIOS.findIndex(function (d) { return !estaResolvido(d.id); });
      if (seguinte >= 0) setTimeout(function () { irPara(seguinte); }, 1100);
    });
  }

  function pedirPista() {
    var desafio = DESAFIOS[estado.activo];
    var jaTem = (pistasPedidas[desafio.id] || []).length;
    if (jaTem >= desafio.pistas.length) {
      el.veredicto.textContent = "Já não há mais pistas para este.";
      el.veredicto.className = "veredicto";
      return;
    }
    pistasPedidas[desafio.id] = (pistasPedidas[desafio.id] || []).concat(desafio.pistas[jaTem]);
    desenharPistas();
  }

  function recomecar() {
    if (!confirm("Recomeçar do zero? Apaga todo o progresso guardado.")) return;
    estado.resolvidos = {};
    pistasPedidas = {};
    guardarResolvidos();
    estado.jaConcluido = false;
    el.final.hidden = true;
    el.moldura.hidden = false;
    irPara(0);
  }

  function mostrarFinal() {
    el.moldura.hidden = true;
    el.bolo.textContent = BOLO;
    el.mensagemFinal.textContent = MENSAGEM_FINAL;
    el.assinatura.textContent = ASSINATURA;
    el.final.hidden = false;
  }

  /* ── Arranque ────────────────────────────────────────────────── */
  function arrancar() {
    el.destinatario.textContent = "para " + NOME;
    desenharLista();
    desenharDesafio();
    estado.jaConcluido = totalResolvidos() === DESAFIOS.length;

    var reduzido = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduzido) {
      el.linhasArranque.textContent = LINHAS_ARRANQUE.join("\n");
      return setTimeout(mostrarJanela, 400);
    }
    var i = 0;
    (function proxima() {
      if (i >= LINHAS_ARRANQUE.length) return setTimeout(mostrarJanela, 450);
      el.linhasArranque.textContent += LINHAS_ARRANQUE[i] + "\n";
      i += 1;
      setTimeout(proxima, 240);
    })();
  }

  function mostrarJanela() {
    el.arranque.hidden = true;
    el.arranque.style.display = "none";
    if (estado.jaConcluido) return mostrarFinal();
    el.moldura.hidden = false;
    el.resposta.focus();
  }

  function actualizarRede() {
    el.estadoRede.textContent = navigator.onLine ? "· online" : "· offline (PWA a servir)";
  }

  /* ── Descarregar a própria app num .zip (JS puro, sem bibliotecas) ─ */
  var FICHEIROS_JOGO = [
    "index.html", "convite.html", "estilo.css", "jogo.js", "sw.js",
    "manifest.webmanifest", "lista-palavras.txt",
    "icones/icone-192.png", "icones/icone-512.png", "icones/icone-maskable-512.png",
  ];
  var LEIA_ME_ZIP =
    "CTF.EXE — cópia da app.\n\n" +
    "Para jogar, esta pasta precisa de ser servida (o service worker exige\n" +
    "https ou localhost — abrir o index.html com file:// não chega):\n\n" +
    "  python3 -m http.server 8000    e abre  http://localhost:8000\n\n" +
    "Ou publica a pasta em qualquer host estático / GitHub Pages.\n" +
    "Ponto de entrada do jogo: index.html   (cartão: convite.html)\n";

  function u16(n) { return new Uint8Array([n & 255, (n >>> 8) & 255]); }
  function u32(n) { return new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]); }
  function juntarBytes(lista) {
    var total = 0, i;
    for (i = 0; i < lista.length; i++) total += lista[i].length;
    var saida = new Uint8Array(total), p = 0;
    for (i = 0; i < lista.length; i++) { saida.set(lista[i], p); p += lista[i].length; }
    return saida;
  }
  var TABELA_CRC = (function () {
    var t = new Uint32Array(256), c, n, k;
    for (n = 0; n < 256; n++) {
      c = n;
      for (k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(bytes) {
    var crc = 0xFFFFFFFF, i;
    for (i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ TABELA_CRC[(crc ^ bytes[i]) & 255];
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }
  var DOS_HORA = (12 << 11);                              // 12:00:00
  var DOS_DATA = ((2026 - 1980) << 9) | (1 << 5) | 1;     // 2026-01-01

  function construirZip(ficheiros) {
    var codificador = new TextEncoder();
    var locais = [], central = [], offset = 0;
    ficheiros.forEach(function (f) {
      var nome = codificador.encode(f.nome);
      var crc = crc32(f.dados), tam = f.dados.length;
      var local = juntarBytes([
        u32(0x04034b50), u16(20), u16(0), u16(0), u16(DOS_HORA), u16(DOS_DATA),
        u32(crc), u32(tam), u32(tam), u16(nome.length), u16(0), nome, f.dados,
      ]);
      locais.push(local);
      central.push(juntarBytes([
        u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(DOS_HORA), u16(DOS_DATA),
        u32(crc), u32(tam), u32(tam), u16(nome.length), u16(0), u16(0),
        u16(0), u16(0), u32(0), u32(offset), nome,
      ]));
      offset += local.length;
    });
    var centralBytes = juntarBytes(central);
    var fim = juntarBytes([
      u32(0x06054b50), u16(0), u16(0), u16(ficheiros.length), u16(ficheiros.length),
      u32(centralBytes.length), u32(offset), u16(0),
    ]);
    return new Blob([juntarBytes(locais), centralBytes, fim], { type: "application/zip" });
  }

  function descarregarJogo() {
    el.descarregar.textContent = "A preparar…";
    el.descarregar.disabled = true;
    var ficheiros = [];
    Promise.all(FICHEIROS_JOGO.map(function (nome) {
      return fetch("./" + nome).then(function (r) { return r.arrayBuffer(); })
        .then(function (buf) { ficheiros.push({ nome: nome, dados: new Uint8Array(buf) }); });
    })).then(function () {
      ficheiros.push({ nome: "LEIA-ME.txt", dados: new TextEncoder().encode(LEIA_ME_ZIP) });
      var blob = construirZip(ficheiros);
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url; a.download = "ctf-exe.zip";
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 3000);
      el.descarregar.textContent = "Descarregado ✓";
      setTimeout(function () {
        el.descarregar.textContent = "Descarregar .zip";
        el.descarregar.disabled = false;
      }, 2500);
    }).catch(function () {
      el.descarregar.textContent = "Falhou — tenta de novo";
      el.descarregar.disabled = false;
    });
  }

  /* ── Ligações ────────────────────────────────────────────────── */
  el.enviar.addEventListener("click", validar);
  el.resposta.addEventListener("keydown", function (e) { if (e.key === "Enter") validar(); });
  el.copiar.addEventListener("click", function () {
    navigator.clipboard.writeText(el.cargaTexto.textContent).then(function () {
      el.copiar.textContent = "Copiado";
      setTimeout(function () { el.copiar.textContent = "Copiar"; }, 1500);
    });
  });
  el.teclaPista.addEventListener("click", pedirPista);
  el.teclaAnterior.addEventListener("click", function () { irPara(estado.activo - 1); });
  el.teclaSeguinte.addEventListener("click", function () { irPara(estado.activo + 1); });
  el.teclaReset.addEventListener("click", recomecar);
  el.descarregar.addEventListener("click", descarregarJogo);
  document.addEventListener("keydown", function (e) {
    if (e.target === el.resposta) return;
    if (e.key === "F1") { e.preventDefault(); pedirPista(); }
    if (e.key === "F2") { e.preventDefault(); irPara(estado.activo - 1); }
    if (e.key === "F3") { e.preventDefault(); irPara(estado.activo + 1); }
  });
  window.addEventListener("online", actualizarRede);
  window.addEventListener("offline", actualizarRede);

  // instalação PWA
  window.addEventListener("beforeinstallprompt", function (e) {
    e.preventDefault();
    eventoInstalar = e;
    el.instalar.hidden = false;
  });
  el.instalar.addEventListener("click", function () {
    if (!eventoInstalar) return;
    eventoInstalar.prompt();
    eventoInstalar.userChoice.finally(function () {
      eventoInstalar = null;
      el.instalar.hidden = true;
    });
  });
  window.addEventListener("appinstalled", function () { el.instalar.hidden = true; });

  // service worker
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
      navigator.serviceWorker.register("./sw.js").catch(function () {});
    });
  }

  actualizarRede();
  arrancar();
})();

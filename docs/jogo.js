/* CTF.EXE — lógica do jogo.
 * A validação é por SHA-256: comparo o hash da tua resposta com um hash
 * guardado. O texto certo nunca está aqui em claro. Os segredos que se
 * apanham por técnica (recon, brute force, jwt) vivem no service worker.
 */

(function () {
  "use strict";

  // ── PERSONALIZA: nome, mensagem e assinatura ────────────────────
  var NOME = "Diogo Anastácio";
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
        "Abre a consola (F4) e faz  get /robots.txt . Segue o rasto.\n" +
        "(Podes na mesma abri-lo no browser, se preferires.)",
      hash: "c424e7880be05a121b7267b91729abcfa564ed7dc9a2d5ae535d680c4ea6bf3f",
      pistas: [
        "Um robots.txt tem linhas Disallow. Cada uma é um caminho no servidor.",
        "O caminho proibido é uma pasta/ficheiro. Na consola:  get <esse-caminho>",
        "Faz  get /backup-nsm/notas-migracao.txt",
      ],
    },
    {
      id: 2, codinome: "CABECALHOS",
      titulo: "Nem tudo vem no corpo da resposta",
      enunciado:
        "Há um endpoint tranquilo em  /api/ola  que responde um JSON\n" +
        "sem graça. Mas uma resposta HTTP é mais do que o corpo.\n\n" +
        "Na consola (F4):  headers /api/ola  — e lê o que vem no topo.",
      hash: "bf140bb0ddfdc84b7ca54034f7e2ce8065db6cf714ee27440efd5936735689f7",
      pistas: [
        "Faz  headers /api/ola  na consola e percorre a lista de cabeçalhos.",
        "Há um cabeçalho que não devia lá estar: começa por X-.",
        "O valor desse cabeçalho X- é a própria bandeira.",
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
        "É Vigenère, e só o interior de CTF{...} foi cifrado — o 'CTF' e as chavetas ficaram intactos. Decifra só o miolo; underscores contam como separadores, não gastam chave.",
        "A palavra-chave tem 7 letras e é, literalmente, SEGREDO.",
        "Decifrar = subtrair o deslocamento de cada letra da chave (A=0, B=1, ...). Há decifradores online se preferires confirmar.",
      ],
    },
    {
      id: 5, codinome: "COFRE",
      titulo: "O cofre sem tentativas limitadas",
      enunciado:
        "O cofre está em  /api/pin  e valida um código de 4 dígitos.\n" +
        "Mas primeiro exige uma sessão: pede um token a  /api/sessao .\n\n" +
        "Depois é força bruta — não há bloqueio, não há atraso, não há captcha.\n" +
        "10 000 hipóteses. Automatiza e abre o cofre.",
      hash: "908163328dfacefec53cf4ca9472a1392f107c2ed1b56a86043d82175e5cf4dd",
      pistas: [
        "Primeiro espreita:  get /api/sessao  (traz um token) e  get /api/pin  (diz o que espera).",
        "O pin quer  ?token=<token>&codigo=<4-dígitos> . São só 10 000 hipóteses.",
        "A consola tem um atalho:  pin /api/pin /api/sessao  — percorre tudo por ti. (Ou escreve o teu ciclo, ou ataca o servidor.py em Python.)",
      ],
    },
    {
      id: 6, codinome: "SQLI",
      titulo: "A consulta que acredita no que lhe escrevem",
      enunciado:
        "Há um login em  /api/login?utilizador=...&senha=...  que monta a\n" +
        "consulta à moda antiga, colando texto:\n\n" +
        "    SELECT * FROM utilizadores\n" +
        "    WHERE utilizador='...' AND senha='...'\n\n" +
        "Entra como admin sem saberes a senha. A bandeira vem no acesso.",
      hash: "d94ab618fac53ac3701003f69b1849c6954f0e5d7091e00544cdc511c8a8c386",
      pistas: [
        "As aspas do teu texto entram directas na consulta. E se fechasses a aspa tu próprio?",
        "Dois clássicos: no utilizador  admin'--  (comenta o resto da linha), ou na senha  ' OR '1'='1 .",
        "Na consola (F4):  get /api/login?utilizador=admin'--&senha=x",
      ],
    },
    {
      id: 7, codinome: "JWT",
      titulo: "Um token que se acredita a si próprio",
      enunciado:
        "O painel  /api/admin  aceita um JWT no cabeçalho\n" +
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
        "Constrói as duas partes em base64url — {\"alg\":\"none\",\"typ\":\"JWT\"} e uma carga com role:admin — junta-as com um ponto e deixa a assinatura vazia (o token acaba num ponto). Depois envia na consola:  curl /api/admin -H \"Authorization: Bearer <o-teu-token>\"",
      ],
    },
    {
      id: 8, codinome: "HASH",
      titulo: "Uma palavra, um dicionário, um resumo",
      enunciado:
        "Encontrámos este SHA-256 numa base de dados, sem sal nenhum:\n\n" +
        "    d93449f3e5b4bc1fb096a29c2fe7cb71b2694f1436f738741c35950fdb36fbaf\n\n" +
        "A palavra original está na lista que o jogo serve em\n" +
        "/lista-palavras.txt . Descobre qual é.\n" +
        "(A resposta é a palavra, não CTF{...}.)",
      hash: "d93449f3e5b4bc1fb096a29c2fe7cb71b2694f1436f738741c35950fdb36fbaf",
      pistas: [
        "Ataque de dicionário: percorre a lista, calcula o SHA-256 de cada palavra, compara com o alvo. Espreita-a com  get /lista-palavras.txt .",
        "A consola faz o resumo de qualquer texto:  sha256 <palavra>  — e o alvo é o hash do enunciado.",
        "Ou deixa-a correr tudo:  crack d93449f3e5b4bc1fb096a29c2fe7cb71b2694f1436f738741c35950fdb36fbaf /lista-palavras.txt",
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
   "mensagem-final","assinatura","abrir-consola","consola-fundo","consola",
   "consola-fechar","consola-saida","consola-entrada","abrir-instalar",
   "instalar-fundo","instalar-fechar","instalar-qr","instalar-url",
   "instalar-agora"].forEach(function (id) {
    el[camel(id)] = document.getElementById(id);
  });
  function camel(s) { return s.replace(/-([a-z])/g, function (_, c) { return c.toUpperCase(); }); }

  var LINHAS_ARRANQUE = [
    "CTF.EXE  v3.0  [pwa]",
    "a carregar modulos ................ ok",
    "a registar service worker ......... ok",
    "a abrir consola local (F4) ........ ok",
    "a mapear superficie de ataque ..... 8 alvos",
    "",
    "oito desafios. consola integrada. modo offline pronto.",
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
    "index.html", "convite.html", "estilo.css", "jogo.js", "qr.js", "sw.js",
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

  /* ── Consola integrada ───────────────────────────────────────────
     Uma shell dentro da app. Os comandos de rede (get/headers/post/curl)
     passam por fetch(), que o service worker interceta — por isso batem
     nos mesmos endpoints do jogo, offline e sem sair da PWA.
     Os utilitários (b64/hex/rot/vigenere/sha256/pin/crack) são genéricos,
     não atalhos por desafio: dão-te o canivete, não a resposta. */
  var historico = [], posHist = -1, consolaPronta = false;

  function escreverConsola(texto, classe) {
    var linha = document.createElement("span");
    if (classe) linha.className = classe;
    linha.textContent = texto + "\n";
    el.consolaSaida.appendChild(linha);
    el.consolaSaida.scrollTop = el.consolaSaida.scrollHeight;
  }

  function abrirConsola() {
    el.consolaFundo.hidden = false;
    if (!consolaPronta) {
      escreverConsola("consola CTF.EXE — tudo local, tudo offline.", "fraco");
      escreverConsola("escreve  ajuda  para a lista de comandos.\n", "fraco");
      consolaPronta = true;
    }
    setTimeout(function () { el.consolaEntrada.focus(); }, 30);
  }
  function fecharConsola() { el.consolaFundo.hidden = true; }

  var AJUDA = [
    "comandos de rede (batem nos endpoints do jogo):",
    "  get <caminho>                 — corpo da resposta (ex: get /robots.txt)",
    "  headers <caminho>             — todos os cabeçalhos da resposta",
    "  post <caminho> <corpo>        — POST com corpo (ex: post /api/login {\"u\":\"..\"})",
    "  curl <caminho> [-H \"K: V\"]     — pedido com cabeçalho à escolha (ex: Authorization)",
    "",
    "utilitários (genéricos — a técnica é tua):",
    "  b64d <texto>   b64e <texto>    — descodificar / codificar base64",
    "  hex <hex>                      — hex → texto",
    "  rot <n> <texto>   rot13 <texto>— rodar o alfabeto",
    "  vigenere <chave> <texto>       — decifrar Vigenère",
    "  sha256 <texto>                 — resumo SHA-256",
    "  pin <caminho-pin> <caminho-sessao> — força bruta a um cofre de 4 dígitos",
    "  crack <hash> [<caminho-lista>] — dicionário SHA-256 (lista: /lista-palavras.txt)",
    "",
    "  limpar    — apaga o ecrã     |    fechar / F4 / Esc — fecha a consola",
  ];

  function classificarHttp(status) { return status >= 200 && status < 300 ? "ok" : "erro"; }

  function resolverCaminho(p) {
    if (!p) return null;
    if (/^https?:\/\//i.test(p)) return p;          // absoluto
    return new URL(p.replace(/^\//, "./"), location.href).href; // relativo ao scope
  }

  function cmdGet(args) {
    var alvo = resolverCaminho(args[0]);
    if (!alvo) return escreverConsola("uso: get <caminho>", "erro");
    fetch(alvo).then(function (r) {
      escreverConsola("HTTP " + r.status + " " + r.statusText, classificarHttp(r.status));
      return r.text();
    }).then(function (t) { escreverConsola(t.length ? t : "(corpo vazio)"); })
      .catch(function (e) { escreverConsola("falhou: " + e.message, "erro"); });
  }

  function cmdHeaders(args) {
    var alvo = resolverCaminho(args[0]);
    if (!alvo) return escreverConsola("uso: headers <caminho>", "erro");
    fetch(alvo).then(function (r) {
      escreverConsola("HTTP " + r.status + " " + r.statusText, classificarHttp(r.status));
      var houve = false;
      r.headers.forEach(function (v, k) { escreverConsola("  " + k + ": " + v); houve = true; });
      if (!houve) escreverConsola("  (sem cabeçalhos expostos por CORS — tenta na aba Network das DevTools)", "fraco");
    }).catch(function (e) { escreverConsola("falhou: " + e.message, "erro"); });
  }

  function cmdPost(args, resto) {
    var alvo = resolverCaminho(args[0]);
    if (!alvo) return escreverConsola("uso: post <caminho> <corpo>", "erro");
    var corpo = resto.slice(resto.indexOf(args[0]) + args[0].length).trim();
    fetch(alvo, { method: "POST", body: corpo,
      headers: { "Content-Type": "application/json" } }).then(function (r) {
      escreverConsola("HTTP " + r.status + " " + r.statusText, classificarHttp(r.status));
      return r.text();
    }).then(function (t) { escreverConsola(t.length ? t : "(corpo vazio)"); })
      .catch(function (e) { escreverConsola("falhou: " + e.message, "erro"); });
  }

  function cmdCurl(resto) {
    // curl <caminho> [-H "Chave: Valor"] ...
    var cabecalhos = {};
    var reH = /-H\s+"([^"]+)"/g, m;
    while ((m = reH.exec(resto))) {
      var idx = m[1].indexOf(":");
      if (idx > 0) cabecalhos[m[1].slice(0, idx).trim()] = m[1].slice(idx + 1).trim();
    }
    var semH = resto.replace(reH, "").trim();
    var alvo = resolverCaminho(semH.split(/\s+/)[0]);
    if (!alvo) return escreverConsola('uso: curl <caminho> [-H "Chave: Valor"]', "erro");
    fetch(alvo, { headers: cabecalhos }).then(function (r) {
      escreverConsola("HTTP " + r.status + " " + r.statusText, classificarHttp(r.status));
      return r.text();
    }).then(function (t) { escreverConsola(t.length ? t : "(corpo vazio)"); })
      .catch(function (e) { escreverConsola("falhou: " + e.message, "erro"); });
  }

  function cmdB64d(resto) {
    try { escreverConsola(decodeURIComponent(escape(atob(resto.trim())))); }
    catch (e) { escreverConsola("base64 inválido", "erro"); }
  }
  function cmdB64e(resto) {
    try { escreverConsola(btoa(unescape(encodeURIComponent(resto)))); }
    catch (e) { escreverConsola("não deu para codificar", "erro"); }
  }
  function cmdHex(resto) {
    var h = resto.replace(/[^0-9a-fA-F]/g, "");
    if (h.length % 2) return escreverConsola("número ímpar de dígitos hex", "erro");
    var s = "";
    for (var i = 0; i < h.length; i += 2) s += String.fromCharCode(parseInt(h.substr(i, 2), 16));
    try { escreverConsola(decodeURIComponent(escape(s))); } catch (e) { escreverConsola(s); }
  }
  function rodar(texto, n) {
    return texto.replace(/[a-z]/g, function (c) {
      return String.fromCharCode((c.charCodeAt(0) - 97 + n) % 26 + 97);
    }).replace(/[A-Z]/g, function (c) {
      return String.fromCharCode((c.charCodeAt(0) - 65 + n) % 26 + 65);
    });
  }
  function cmdRot(args, resto) {
    var n = parseInt(args[0], 10);
    if (isNaN(n)) return escreverConsola("uso: rot <n> <texto>", "erro");
    escreverConsola(rodar(resto.slice(resto.indexOf(args[0]) + args[0].length).trim(), ((n % 26) + 26) % 26));
  }
  function cmdVigenere(args, resto) {
    var chave = (args[0] || "").toUpperCase().replace(/[^A-Z]/g, "");
    if (!chave) return escreverConsola("uso: vigenere <chave> <texto>", "erro");
    var texto = resto.slice(resto.indexOf(args[0]) + args[0].length).trim();
    var j = 0, saida = texto.replace(/[a-zA-Z]/g, function (c) {
      var maiusc = c <= "Z", base = maiusc ? 65 : 97;
      var desloc = chave.charCodeAt(j % chave.length) - 65;
      j++;
      return String.fromCharCode((c.charCodeAt(0) - base - desloc + 26) % 26 + base);
    });
    escreverConsola(saida);
  }
  function hashHex(texto) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(texto)).then(function (buf) {
      return [].map.call(new Uint8Array(buf), function (x) {
        return x.toString(16).padStart(2, "0");
      }).join("");
    });
  }
  function cmdSha256(resto) {
    hashHex(resto).then(function (h) { escreverConsola(h); });
  }
  function cmdPin(args) {
    var alvoPin = resolverCaminho(args[0]), alvoSessao = resolverCaminho(args[1]);
    if (!alvoPin || !alvoSessao)
      return escreverConsola("uso: pin <caminho-pin> <caminho-sessao>", "erro");
    escreverConsola("a pedir sessão...", "fraco");
    fetch(alvoSessao).then(function (r) { return r.json(); }).then(function (s) {
      var token = s.token;
      if (!token) { escreverConsola("não veio token da sessão", "erro"); return; }
      escreverConsola("token: " + token + "  — a percorrer 0000–9999...", "fraco");
      var n = 0;
      function tentar() {
        if (n > 9999) { escreverConsola("esgotei o espaço sem abrir", "erro"); return; }
        var codigo = String(n).padStart(4, "0");
        var u = alvoPin + (alvoPin.indexOf("?") < 0 ? "?" : "&") +
                "token=" + encodeURIComponent(token) + "&codigo=" + codigo;
        fetch(u).then(function (r) { return r.json(); }).then(function (d) {
          if (d && (d.aberto || d.bandeira)) {
            escreverConsola("ABERTO com " + codigo + " → " + (d.bandeira || JSON.stringify(d)), "ok");
          } else { n++; (n % 500 === 0) && escreverConsola("... " + n, "fraco"); tentar(); }
        }).catch(function (e) { escreverConsola("erro em " + codigo + ": " + e.message, "erro"); });
      }
      tentar();
    }).catch(function (e) { escreverConsola("falhou: " + e.message, "erro"); });
  }
  function cmdCrack(args) {
    var alvo = (args[0] || "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(alvo))
      return escreverConsola("uso: crack <hash-sha256> [<caminho-lista>]", "erro");
    var lista = resolverCaminho(args[1] || "/lista-palavras.txt");
    escreverConsola("a carregar lista...", "fraco");
    fetch(lista).then(function (r) { return r.text(); }).then(function (t) {
      var palavras = t.split(/\r?\n/).map(function (p) { return p.trim(); })
                      .filter(Boolean);
      escreverConsola(palavras.length + " palavras. a testar...", "fraco");
      var i = 0;
      function passo() {
        if (i >= palavras.length) { escreverConsola("nenhuma bate com esse hash", "erro"); return; }
        var p = palavras[i];
        hashHex(p).then(function (h) {
          if (h === alvo) { escreverConsola("ENCONTRADA: " + p, "ok"); return; }
          i++; passo();
        });
      }
      passo();
    }).catch(function (e) { escreverConsola("falhou: " + e.message, "erro"); });
  }

  function correrComando(linha) {
    var texto = linha.trim();
    if (!texto) return;
    escreverConsola("$ " + texto, "eco");
    historico.unshift(texto); posHist = -1;
    var partes = texto.split(/\s+/);
    var cmd = partes[0].toLowerCase();
    var args = partes.slice(1);
    var resto = texto.slice(partes[0].length).trim();
    switch (cmd) {
      case "ajuda": case "help": case "?": AJUDA.forEach(function (l) { escreverConsola(l); }); break;
      case "limpar": case "clear": el.consolaSaida.textContent = ""; break;
      case "fechar": case "exit": fecharConsola(); break;
      case "get": cmdGet(args); break;
      case "headers": case "head": cmdHeaders(args); break;
      case "post": cmdPost(args, resto); break;
      case "curl": cmdCurl(resto); break;
      case "b64d": case "base64d": cmdB64d(resto); break;
      case "b64e": case "base64e": cmdB64e(resto); break;
      case "hex": cmdHex(resto); break;
      case "rot": cmdRot(args, resto); break;
      case "rot13": escreverConsola(rodar(resto, 13)); break;
      case "vigenere": case "vig": cmdVigenere(args, resto); break;
      case "sha256": case "sha": cmdSha256(resto); break;
      case "pin": cmdPin(args); break;
      case "crack": cmdCrack(args); break;
      default: escreverConsola("comando desconhecido: " + cmd + "  (escreve ajuda)", "erro");
    }
  }

  /* ── Janela "Instalar" (QR do próprio endereço do jogo) ──────────── */
  var qrDesenhado = false;
  function abrirInstalar() {
    var url = new URL("./", location.href).href;   // o endereço público do jogo
    el.instalarUrl.textContent = url;
    if (!qrDesenhado && window.CTF_QR) {
      try { el.instalarQr.innerHTML = window.CTF_QR.svg(url, 4); qrDesenhado = true; }
      catch (e) { el.instalarQr.textContent = "(não foi possível gerar o QR)"; }
    }
    // se o browser deixar instalar aqui mesmo, mostra o botão
    el.instalarAgora.hidden = !eventoInstalar;
    el.instalarFundo.hidden = false;
  }
  function fecharInstalar() { el.instalarFundo.hidden = true; }

  /* ── Ligações ────────────────────────────────────────────────── */
  el.abrirInstalar.addEventListener("click", abrirInstalar);
  el.instalarFechar.addEventListener("click", fecharInstalar);
  el.instalarFundo.addEventListener("click", function (e) {
    if (e.target === el.instalarFundo) fecharInstalar();
  });
  el.instalarAgora.addEventListener("click", function () {
    if (!eventoInstalar) return;
    eventoInstalar.prompt();
    eventoInstalar.userChoice.finally(function () {
      eventoInstalar = null;
      el.instalar.hidden = true;
      el.instalarAgora.hidden = true;
    });
  });
  el.consolaFechar.addEventListener("click", fecharConsola);
  el.abrirConsola.addEventListener("click", abrirConsola);
  el.consolaFundo.addEventListener("click", function (e) {
    if (e.target === el.consolaFundo) fecharConsola();
  });
  el.consolaEntrada.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { correrComando(el.consolaEntrada.value); el.consolaEntrada.value = ""; }
    else if (e.key === "ArrowUp") {
      if (posHist < historico.length - 1) { posHist++; el.consolaEntrada.value = historico[posHist]; }
      e.preventDefault();
    } else if (e.key === "ArrowDown") {
      if (posHist > 0) { posHist--; el.consolaEntrada.value = historico[posHist]; }
      else { posHist = -1; el.consolaEntrada.value = ""; }
      e.preventDefault();
    } else if (e.key === "Escape") { fecharConsola(); }
  });

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
    if (e.target === el.consolaEntrada) return;
    if (e.key === "F1") { e.preventDefault(); pedirPista(); }
    if (e.key === "F2") { e.preventDefault(); irPara(estado.activo - 1); }
    if (e.key === "F3") { e.preventDefault(); irPara(estado.activo + 1); }
    if (e.key === "F4") { e.preventDefault(); el.consolaFundo.hidden ? abrirConsola() : fecharConsola(); }
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

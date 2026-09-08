require("dotenv").config();

const path = require("path");
const http = require("http");
const crypto = require("crypto");

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Server: SocketIOServer } = require("socket.io");

const rooms = require("./rooms");
const users = require("./users");
const friends = require("./friends");
const zpay = require("./zpay");

const PORT = process.env.PORT || 3006;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const IS_PROD = process.env.NODE_ENV === "production";
const ALLOWED_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:3006";

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/api/auth/discord/callback`;
// Token de BOT (diferente do client secret do OAuth!). É com ele que buscamos
// o perfil público (nome + foto) de um usuário qualquer por ID, direto na API
// oficial da Discord — sem depender de scrapers de terceiros que caem sem aviso.
// Como criar: no Developer Portal, no seu app -> aba "Bot" -> "Reset Token".
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const CREATOR_DISCORD_ID = "1035283110885081098";

// Toda doação criada pelo site leva essa tag (campo "tag" documentado pela
// Z.PAY). É assim que separamos "doações do ZUK SCREEN" de qualquer outra
// coisa que porventura use a mesma conta Z.PAY - o ranking e o feed só
// mostram doações com essa tag.
const SITE_DONATION_TAG = process.env.ZPAY_TAG || "zukscreen";

if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
  console.warn(
    "[ZUK SCREEN] Faltam DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET no .env — o login com Discord não vai funcionar até você preencher isso (veja .env.example)."
  );
}
if (!DISCORD_BOT_TOKEN) {
  console.warn(
    "[ZUK SCREEN] Falta DISCORD_BOT_TOKEN no .env — a tela de Créditos vai usar o nome/avatar padrão até você configurar isso (veja .env.example)."
  );
}
if (!zpay.isConfigured()) {
  console.warn(
    "[ZUK SCREEN] Faltam ZPAY_CLIENT_ID / ZPAY_CLIENT_SECRET no .env — a aba Apoie não vai conseguir gerar Pix até você configurar isso (veja .env.example)."
  );
}

const app = express();
const server = http.createServer(app);

/* ---------------------------------------------------------------------- */
/* SEGURANÇA - camadas gerais                                             */
/* ---------------------------------------------------------------------- */

// Cabeçalhos de segurança (CSP, HSTS, no-sniff, etc.)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // 'unsafe-inline' aqui é necessário porque o front-end usa <script> inline
        // e atributos onclick no HTML. Numa versão futura, o ideal é mover todo o
        // JS pra um arquivo .js separado e usar um nonce em vez de 'unsafe-inline'.
        scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
        // O Helmet, por padrão, bloqueia atributos inline tipo onclick="..."
        // através da diretiva script-src-attr (o default dele é 'none',
        // separado de script-src). Sem isso aqui, todo onclick do HTML
        // fica mudo mesmo com script-src liberado.
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https://cdn.discordapp.com"],
        connectSrc: ["'self'", "wss:", "ws:"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  cors({
    origin: ALLOWED_ORIGIN,
    credentials: true,
  })
);

app.use(express.json({ limit: "10kb" })); // corpo pequeno, evita payloads gigantes
app.use(cookieParser());

// Rate limit geral pra API - evita brute force e abuso
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitas requisições. Espere um pouco e tente de novo." },
});

// Rate limit mais apertado só pra tentativas de entrar em sala (senha)
const joinLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitas tentativas de entrar na sala. Aguarde um minuto." },
});

// Rate limit dedicado pra criação de cobrança Pix (evita flood de cobranças)
const donationLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitas tentativas de gerar Pix. Aguarde um minuto." },
});

app.use("/api", apiLimiter);

/* ---------------------------------------------------------------------- */
/* LOGIN COM DISCORD - OAuth2 real                                        */
/* ---------------------------------------------------------------------- */

// Passo 1: manda o usuário pro Discord autorizar o app.
// Um "state" aleatório é guardado num cookie de curta duração e conferido
// na volta (passo 2) — isso impede ataques de CSRF no fluxo de login.
app.get("/api/auth/discord/login", (req, res) => {
  if (!DISCORD_CLIENT_ID) {
    return res.status(500).send("O servidor ainda não tem DISCORD_CLIENT_ID configurado (veja server/.env.example).");
  }
  const state = crypto.randomBytes(16).toString("hex");
  res.cookie("zuk_oauth_state", state, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: "lax",
    maxAge: 5 * 60 * 1000, // só precisa durar o tempo do login
  });

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify",
    state,
    prompt: "consent",
  });

  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

// Passo 2: o Discord chama essa URL de volta com um "code". Trocamos esse
// code por um access_token e buscamos o perfil real em /users/@me.
app.get("/api/auth/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const expectedState = req.cookies?.zuk_oauth_state;

    if (!code || !state || !expectedState || state !== expectedState) {
      return res.status(400).send("Login inválido ou expirado. Volte e tente entrar de novo.");
    }
    res.clearCookie("zuk_oauth_state");

    // Troca o code pelo token de acesso
    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });
    if (!tokenResp.ok) throw new Error("Falha ao trocar o código pelo token do Discord.");
    const tokenData = await tokenResp.json();

    // Busca o perfil real do usuário
    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    if (!userResp.ok) throw new Error("Falha ao buscar o perfil do Discord.");
    const discordUser = await userResp.json();

    const safeUsername = String(discordUser.username || "Usuário").replace(/<[^>]*>/g, "").slice(0, 32);
    const avatarUrl = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
      : null;

    // Guarda esse usuário no registro conhecido do site - é isso que permite
    // outras pessoas encontrarem ela depois pra adicionar como amiga.
    users.upsertUser({ id: discordUser.id, username: safeUsername, avatar: avatarUrl });

    const sessionToken = jwt.sign(
      { sub: discordUser.id, name: safeUsername, avatar: avatarUrl },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.cookie("zuk_session", sessionToken, {
      httpOnly: true, // não acessível via JS - protege contra roubo de sessão por XSS
      secure: IS_PROD, // só via HTTPS em produção
      sameSite: "lax", // mitiga CSRF
      maxAge: 12 * 60 * 60 * 1000,
    });

    res.redirect("/"); // volta pro site já logado
  } catch (err) {
    console.error("[OAuth Discord]", err.message);
    res.status(500).send("Não foi possível concluir o login com o Discord. Tente novamente.");
  }
});

// O front consulta essa rota ao carregar a página pra saber se já existe sessão ativa
app.get("/api/auth/me", (req, res) => {
  const token = req.cookies?.zuk_session;
  if (!token) return res.status(401).json({ error: "Não autenticado." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Mantém o registro atualizado mesmo sem precisar logar de novo
    users.upsertUser({ id: payload.sub, username: payload.name, avatar: payload.avatar });
    res.json({ user: { discordId: payload.sub, username: payload.name, avatar: payload.avatar || null } });
  } catch {
    res.status(401).json({ error: "Sessão inválida ou expirada." });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("zuk_session");
  res.json({ ok: true });
});

function requireAuth(req, res, next) {
  const token = req.cookies?.zuk_session;
  if (!token) return res.status(401).json({ error: "Você precisa entrar com o Discord primeiro." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Sessão inválida ou expirada." });
  }
}

/* ---------------------------------------------------------------------- */
/* API DE SALAS                                                           */
/* ---------------------------------------------------------------------- */

app.post("/api/rooms", requireAuth, async (req, res) => {
  try {
    const { name, password } = req.body || {};
    if (typeof password === "string" && password.length > 100) {
      return res.status(400).json({ error: "Senha muito longa." });
    }
    const room = await rooms.createRoom({
      name,
      password,
      hostId: req.user.sub,
      hostName: req.user.name,
    });
    res.json({ ok: true, code: room.code, name: room.name, hasPassword: room.hasPassword });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/rooms/join-by-code", joinLimiter, requireAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    const room = await rooms.joinByCode(code);
    res.json({ ok: true, code: room.code, name: room.name });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/rooms/join-by-name", joinLimiter, requireAuth, async (req, res) => {
  try {
    const { name, password } = req.body || {};
    const room = await rooms.joinByNameAndPassword(name, password);
    res.json({ ok: true, code: room.code, name: room.name });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------------- */
/* AMIGOS (sistema próprio do site - ver server/friends.js pro porquê)    */
/* ---------------------------------------------------------------------- */

app.get("/api/users/search", requireAuth, (req, res) => {
  const { q } = req.query;
  const results = users.searchUsers(q, req.user.sub).map((u) => ({
    id: u.id,
    username: u.username,
    avatar: u.avatar,
  }));
  res.json({ users: results });
});

app.get("/api/friends", requireAuth, (req, res) => {
  const me = req.user.sub;
  const resolve = (id) => {
    const u = users.getUser(id);
    return {
      id,
      username: u?.username || "Usuário",
      avatar: u?.avatar || null,
      online: isUserOnline(id),
    };
  };
  res.json({
    friends: friends.getFriendIds(me).map(resolve),
    incoming: friends.getIncomingIds(me).map(resolve),
    outgoing: friends.getOutgoingIds(me).map(resolve),
  });
});

app.post("/api/friends/request", requireAuth, (req, res) => {
  try {
    const { targetId } = req.body || {};
    friends.sendRequest(req.user.sub, targetId);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/friends/accept", requireAuth, (req, res) => {
  try {
    const { requesterId } = req.body || {};
    friends.acceptRequest(req.user.sub, requesterId);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/friends/decline", requireAuth, (req, res) => {
  const { requesterId } = req.body || {};
  friends.declineRequest(req.user.sub, requesterId);
  res.json({ ok: true });
});

/* ---------------------------------------------------------------------- */
/* CRÉDITOS - perfil real do criador, via API oficial da Discord (bot)    */
/* ---------------------------------------------------------------------- */

let creatorProfileCache = { data: null, fetchedAt: 0 };
const CREATOR_CACHE_TTL = 10 * 60 * 1000; // 10 min - evita bater na API toda hora

app.get("/api/creator", async (req, res) => {
  const now = Date.now();
  if (creatorProfileCache.data && now - creatorProfileCache.fetchedAt < CREATOR_CACHE_TTL) {
    return res.json(creatorProfileCache.data);
  }

  // Fallback caso o bot token não esteja configurado - a tela de créditos
  // usa o nome/emoji padrão nesse caso, sem quebrar nada.
  if (!DISCORD_BOT_TOKEN) {
    return res.json({ username: null, globalName: null, discordId: CREATOR_DISCORD_ID, avatarUrl: null });
  }

  try {
    // Endpoint oficial da Discord: GET /users/{id}. Não precisa de servidor em
    // comum com o bot - só precisa de um token de bot válido.
    const resp = await fetch(`https://discord.com/api/v10/users/${CREATOR_DISCORD_ID}`, {
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
    });
    if (!resp.ok) throw new Error(`Discord respondeu ${resp.status}`);
    const data = await resp.json();

    const avatarUrl = data.avatar
      ? `https://cdn.discordapp.com/avatars/${CREATOR_DISCORD_ID}/${data.avatar}.png?size=128`
      : null;

    const profile = {
      username: data.username || null,
      globalName: data.global_name || data.username || null,
      discordId: CREATOR_DISCORD_ID,
      avatarUrl,
    };
    creatorProfileCache = { data: profile, fetchedAt: now };
    res.json(profile);
  } catch (err) {
    console.error("[Perfil do criador]", err.message);
    res.json({ username: null, globalName: null, discordId: CREATOR_DISCORD_ID, avatarUrl: null });
  }
});

/* ---------------------------------------------------------------------- */
/* APOIE - doações via Pix (Z.PAY)                                        */
/* Front-end nunca fala com a Z.PAY diretamente: só com estas rotas.      */
/* A client-secret fica só aqui no servidor (server/zpay.js + .env).      */
/* ---------------------------------------------------------------------- */

// Cria a cobrança Pix. Exige login (o payerName vem da sessão, não de input
// livre do usuário, pra evitar que qualquer um injete texto arbitrário aqui).
app.post("/api/donations", requireAuth, donationLimiter, async (req, res) => {
  try {
    const { amount, message } = req.body || {};

    const payment = await zpay.createPayment({
      amount: typeof amount === "string" ? parseFloat(amount) : amount,
      payerName: req.user.name,
      description: message ? String(message).slice(0, 200) : undefined,
      tag: SITE_DONATION_TAG, // fixa - garante que só doações do site entram no ranking/feed
    });

    res.json({
      paymentId: payment.paymentId,
      status: payment.status,
      copyPaste: payment.copyPaste,
      qrCodeBase64: payment.qrCodeBase64,
      qrcodeUrl: payment.qrcodeUrl,
    });
  } catch (err) {
    const status = err instanceof zpay.ZPayError ? err.status : 500;
    console.error("[Apoie/create]", err.message);
    res.status(status).json({ error: err.message });
  }
});

// Consulta o status da cobrança — é este endpoint (e só ele) que o front-end
// chama a cada 5s. Repassa 1:1 o status da Z.PAY, que já credita o saldo
// sozinha quando o Pix cai; não fazemos approve automático aqui.
app.get("/api/donations/:paymentId", requireAuth, async (req, res) => {
  try {
    const payment = await zpay.getPaymentStatus(req.params.paymentId);
    res.json(payment);
  } catch (err) {
    const status = err instanceof zpay.ZPayError ? err.status : 500;
    console.error("[Apoie/status]", err.message);
    res.status(status).json({ error: err.message });
  }
});

// Ranking dos maiores apoiadores — SOMENTE doações feitas pelo site.
// O endpoint /top-donates da Z.PAY não tem parâmetro de tag (só /donations
// tem), então em vez de usá-lo, buscamos as doações pagas com a tag do site
// e somamos por pagador aqui mesmo. Cobre até 50 doações pagas mais recentes
// (limite máximo por página da API) - dá conta tranquilo do uso normal do site.
app.get("/api/support/top", requireAuth, async (req, res) => {
  try {
    const limit = req.query.limit ? Math.min(Math.max(parseInt(req.query.limit, 10) || 5, 1), 50) : 5;

    const { items } = await zpay.listDonations({
      status: "paid",
      limit: 50,
      page: 1,
      tag: SITE_DONATION_TAG,
    });

    const byPayer = new Map();
    for (const d of items) {
      const key = d.payerName || "Anônimo";
      const entry = byPayer.get(key) || {
        payerName: key,
        totalAmount: 0,
        donationsCount: 0,
        lastDescription: null,
        lastPaidAt: null,
      };
      entry.totalAmount += Number(d.amount) || 0;
      entry.donationsCount += 1;
      if (!entry.lastPaidAt || new Date(d.paidAt) > new Date(entry.lastPaidAt)) {
        entry.lastPaidAt = d.paidAt;
        entry.lastDescription = d.description || entry.lastDescription;
      }
      byPayer.set(key, entry);
    }

    const ranking = Array.from(byPayer.values())
      .sort((a, b) => b.totalAmount - a.totalAmount)
      .slice(0, limit);

    res.json({ tag: SITE_DONATION_TAG, items: ranking });
  } catch (err) {
    const status = err instanceof zpay.ZPayError ? err.status : 500;
    console.error("[Apoie/top]", err.message);
    res.status(status).json({ error: err.message });
  }
});

// Feed de doações pagas — SOMENTE doações feitas pelo site (mesma tag).
app.get("/api/support/feed", requireAuth, async (req, res) => {
  try {
    const data = await zpay.listDonations({
      status: "paid",
      limit: req.query.limit ? parseInt(req.query.limit, 10) : 10,
      page: req.query.page ? parseInt(req.query.page, 10) : 1,
      tag: SITE_DONATION_TAG,
    });
    res.json(data);
  } catch (err) {
    const status = err instanceof zpay.ZPayError ? err.status : 500;
    console.error("[Apoie/feed]", err.message);
    res.status(status).json({ error: err.message });
  }
});

// Estatísticas gerais da conta (opcional, exibido no topo da aba Apoie).
app.get("/api/support/stats", requireAuth, async (req, res) => {
  try {
    const data = await zpay.getStats();
    res.json(data);
  } catch (err) {
    const status = err instanceof zpay.ZPayError ? err.status : 500;
    console.error("[Apoie/stats]", err.message);
    res.status(status).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------------- */
/* ARQUIVOS ESTÁTICOS DO FRONT-END                                        */
/* ---------------------------------------------------------------------- */
app.use(express.static(path.join(__dirname, "..", "public"), { index: "index.html" }));

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "..", "public", "index.html"));
});

/* ---------------------------------------------------------------------- */
/* SOCKET.IO - SINALIZAÇÃO WEBRTC (a "transmissão de tela" em si)         */
/* ---------------------------------------------------------------------- */
const io = new SocketIOServer(server, {
  cors: { origin: ALLOWED_ORIGIN, credentials: true },
  maxHttpBufferSize: 1e5, // limita tamanho de mensagens - evita flood
});

// Rastreia quem está com o site aberto agora (pra status online/offline dos
// amigos e pra saber pra quem entregar um convite em tempo real). Uma pessoa
// pode ter mais de uma aba/dispositivo aberto, por isso é um Set de sockets.
const socketsByUserId = new Map(); // discordId -> Set(socketId)
function isUserOnline(userId) {
  return (socketsByUserId.get(userId)?.size || 0) > 0;
}

// Rate limit simples por socket pra evitar spam de eventos
const socketEventCounts = new Map();
function socketRateLimited(socketId, max = 60, windowMs = 10_000) {
  const now = Date.now();
  const entry = socketEventCounts.get(socketId) || { count: 0, windowStart: now };
  if (now - entry.windowStart > windowMs) {
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count += 1;
  socketEventCounts.set(socketId, entry);
  return entry.count > max;
}

io.use((socket, next) => {
  // Autentica o socket usando o mesmo cookie de sessão do HTTP
  try {
    const cookieHeader = socket.handshake.headers.cookie || "";
    const match = cookieHeader.match(/zuk_session=([^;]+)/);
    if (!match) return next(new Error("Não autenticado."));
    const payload = jwt.verify(decodeURIComponent(match[1]), JWT_SECRET);
    socket.user = { id: payload.sub, name: payload.name };
    next();
  } catch (err) {
    next(new Error("Sessão inválida."));
  }
});

io.on("connection", (socket) => {
  let currentRoomCode = null;

  if (!socketsByUserId.has(socket.user.id)) socketsByUserId.set(socket.user.id, new Set());
  socketsByUserId.get(socket.user.id).add(socket.id);

  // Convite real pra um amigo entrar numa sala - só é entregue se os dois
  // forem amigos de verdade (aceitos) e se o amigo estiver online agora.
  socket.on("friend:invite", ({ targetUserId, roomCode } = {}) => {
    if (socketRateLimited(socket.id)) return;
    if (!targetUserId || !roomCode) return;
    if (!friends.areFriends(socket.user.id, targetUserId)) return;
    const targetSockets = socketsByUserId.get(targetUserId);
    if (!targetSockets || targetSockets.size === 0) return;
    targetSockets.forEach((sid) => {
      io.to(sid).emit("friend:invite-received", {
        fromId: socket.user.id,
        fromName: socket.user.name,
        roomCode,
      });
    });
  });

  socket.on("room:join", ({ code }) => {
    if (socketRateLimited(socket.id)) return;
    const room = rooms.getRoomByCode(code);
    if (!room) {
      socket.emit("room:error", { error: "Sala não encontrada." });
      return;
    }
    currentRoomCode = room.code;
    socket.join(room.code);

    const isHost = room.hostId === socket.user.id && !room.broadcasterSocketId;
    room.members.set(socket.id, { userId: socket.user.id, name: socket.user.name, isHost });
    if (isHost) room.broadcasterSocketId = socket.id;

    socket.to(room.code).emit("room:peer-joined", { socketId: socket.id, name: socket.user.name, isHost });
    socket.emit("room:joined", {
      code: room.code,
      name: room.name,
      isHost,
      broadcasterSocketId: room.broadcasterSocketId,
      peers: Array.from(room.members.entries())
        .filter(([id]) => id !== socket.id)
        .map(([id, m]) => ({ socketId: id, name: m.name, isHost: m.isHost })),
    });
  });

  // Sinalização WebRTC (offer/answer/ICE) — repassada só entre pares da MESMA sala
  ["webrtc:offer", "webrtc:answer", "webrtc:ice-candidate"].forEach((eventName) => {
    socket.on(eventName, (payload = {}) => {
      if (socketRateLimited(socket.id, 200)) return;
      const { targetSocketId } = payload;
      if (!currentRoomCode || !targetSocketId) return;
      const room = rooms.getRoomByCode(currentRoomCode);
      if (!room || !room.members.has(targetSocketId)) return; // só repassa dentro da sala
      io.to(targetSocketId).emit(eventName, { ...payload, fromSocketId: socket.id });
    });
  });

  socket.on("room:leave", () => leaveCurrentRoom());
  socket.on("disconnect", () => leaveCurrentRoom());

  function leaveCurrentRoom() {
    if (!currentRoomCode) return;
    const room = rooms.getRoomByCode(currentRoomCode);
    if (room) {
      room.members.delete(socket.id);
      if (room.broadcasterSocketId === socket.id) room.broadcasterSocketId = null;
      socket.to(room.code).emit("room:peer-left", { socketId: socket.id });
      rooms.destroyRoomIfEmpty(room.code);
    }
    socket.leave(currentRoomCode);
    currentRoomCode = null;
    socketEventCounts.delete(socket.id);
  }

  socket.on("disconnect", () => {
    const set = socketsByUserId.get(socket.user.id);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) socketsByUserId.delete(socket.user.id);
    }
  });
});

server.listen(PORT, () => {
  console.log(`ZUK SCREEN rodando em http://localhost:${PORT}`);
});

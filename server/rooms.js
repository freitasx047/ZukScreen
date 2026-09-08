const crypto = require("crypto");
const bcrypt = require("bcryptjs");

// Armazenamento em memória. Em produção isso seria um banco (Redis/Postgres),
// mas para o escopo deste projeto o Map já resolve e evita persistir
// senhas em texto claro em disco.
const roomsByCode = new Map(); // code -> room
const roomsByName = new Map(); // nomeNormalizado -> code

const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // sem 0/O/1/I pra evitar confusão

function generateRoomCode(length = 6) {
  let code;
  do {
    code = Array.from(crypto.randomFillSync(new Uint8Array(length)))
      .map((b) => CODE_CHARS[b % CODE_CHARS.length])
      .join("");
  } while (roomsByCode.has(code));
  return code;
}

function normalizeName(name) {
  return name.trim().toLowerCase();
}

function sanitizeRoomName(name) {
  if (typeof name !== "string") return "";
  // remove tags/scripts e limita tamanho - defesa básica contra XSS armazenado
  return name.replace(/<[^>]*>/g, "").trim().slice(0, 40);
}

async function createRoom({ name, password, hostId, hostName }) {
  const cleanName = sanitizeRoomName(name);
  if (!cleanName) {
    throw new Error("Nome da sala inválido.");
  }
  const normalized = normalizeName(cleanName);
  if (roomsByName.has(normalized)) {
    throw new Error("Já existe uma sala ativa com esse nome.");
  }

  const code = generateRoomCode();
  const hasPassword = typeof password === "string" && password.length > 0;
  const passwordHash = hasPassword ? await bcrypt.hash(password, 10) : null;

  const room = {
    code,
    name: cleanName,
    normalizedName: normalized,
    passwordHash,
    hasPassword,
    hostId,
    hostName,
    createdAt: Date.now(),
    members: new Map(), // socketId -> { userId, name, isHost }
    broadcasterSocketId: null,
  };

  roomsByCode.set(code, room);
  roomsByName.set(normalized, code);
  return room;
}

function getRoomByCode(code) {
  if (typeof code !== "string") return null;
  return roomsByCode.get(code.trim().toUpperCase()) || null;
}

async function joinByCode(code) {
  const room = getRoomByCode(code);
  if (!room) throw new Error("Sala não encontrada. Confira o código.");
  return room; // código já é suficiente, sem exigir senha
}

async function joinByNameAndPassword(name, password) {
  const normalized = normalizeName(sanitizeRoomName(name));
  const code = roomsByName.get(normalized);
  if (!code) throw new Error("Sala não encontrada. Confira o nome.");
  const room = roomsByCode.get(code);
  if (!room) throw new Error("Sala não encontrada.");

  if (room.hasPassword) {
    const ok = await bcrypt.compare(password || "", room.passwordHash);
    if (!ok) throw new Error("Senha incorreta.");
  }
  return room;
}

function destroyRoomIfEmpty(code) {
  const room = roomsByCode.get(code);
  if (room && room.members.size === 0) {
    roomsByCode.delete(code);
    roomsByName.delete(room.normalizedName);
  }
}

module.exports = {
  createRoom,
  getRoomByCode,
  joinByCode,
  joinByNameAndPassword,
  destroyRoomIfEmpty,
  sanitizeRoomName,
};

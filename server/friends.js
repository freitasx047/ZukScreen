// Sistema de amizade real dentro do ZUK SCREEN (em memória).
// Não confundir com "amigos do Discord" - o Discord não libera a lista de
// amigos de um usuário pra apps comuns (isso exige o escopo relationships.read,
// que é liberado só pra pouquíssimos apps aprovados manualmente pela própria
// Discord). Então aqui é uma lista de amigos própria do site: pedido, aceite,
// e pronto - os dois viram amigos de verdade dentro do ZUK SCREEN.

const outgoingByUser = new Map(); // userId -> Set(targetId)   pedidos que EU mandei
const incomingByUser = new Map(); // userId -> Set(requesterId) pedidos que eu RECEBI
const friendsByUser = new Map(); // userId -> Set(friendId)

function ensureSet(map, key) {
  if (!map.has(key)) map.set(key, new Set());
  return map.get(key);
}

function areFriends(a, b) {
  return friendsByUser.get(a)?.has(b) || false;
}

function sendRequest(fromId, toId) {
  if (!toId) throw new Error("Usuário inválido.");
  if (fromId === toId) throw new Error("Você não pode adicionar a si mesmo.");
  if (areFriends(fromId, toId)) throw new Error("Vocês já são amigos.");
  if (incomingByUser.get(toId)?.has(fromId)) {
    throw new Error("Pedido já enviado. Aguarde a pessoa aceitar.");
  }
  if (incomingByUser.get(fromId)?.has(toId)) {
    throw new Error("Essa pessoa já te mandou um pedido - aceite o dela na lista de pedidos recebidos.");
  }
  ensureSet(incomingByUser, toId).add(fromId);
  ensureSet(outgoingByUser, fromId).add(toId);
}

function acceptRequest(userId, requesterId) {
  if (!incomingByUser.get(userId)?.has(requesterId)) {
    throw new Error("Esse pedido não existe (talvez já tenha sido respondido).");
  }
  incomingByUser.get(userId).delete(requesterId);
  outgoingByUser.get(requesterId)?.delete(userId);
  ensureSet(friendsByUser, userId).add(requesterId);
  ensureSet(friendsByUser, requesterId).add(userId);
}

function declineRequest(userId, requesterId) {
  incomingByUser.get(userId)?.delete(requesterId);
  outgoingByUser.get(requesterId)?.delete(userId);
}

function getFriendIds(userId) {
  return Array.from(friendsByUser.get(userId) || []);
}

function getIncomingIds(userId) {
  return Array.from(incomingByUser.get(userId) || []);
}

function getOutgoingIds(userId) {
  return Array.from(outgoingByUser.get(userId) || []);
}

module.exports = {
  areFriends,
  sendRequest,
  acceptRequest,
  declineRequest,
  getFriendIds,
  getIncomingIds,
  getOutgoingIds,
};

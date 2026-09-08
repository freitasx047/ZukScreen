// Registro simples em memória de todo mundo que já logou pelo menos uma vez.
// É a partir daqui que a busca de "adicionar amigo" encontra as pessoas —
// não tem como buscar um usuário do Discord que nunca passou pelo nosso login.
const usersById = new Map(); // discordId -> { id, username, avatar, updatedAt }

function upsertUser({ id, username, avatar }) {
  if (!id) return;
  usersById.set(id, {
    id,
    username: username || "Usuário",
    avatar: avatar || null,
    updatedAt: Date.now(),
  });
}

function getUser(id) {
  return usersById.get(id) || null;
}

function searchUsers(query, excludeId, limit = 8) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return [];
  const results = [];
  for (const u of usersById.values()) {
    if (u.id === excludeId) continue;
    if (u.username.toLowerCase().includes(q)) {
      results.push(u);
      if (results.length >= limit) break;
    }
  }
  return results;
}

module.exports = { upsertUser, getUser, searchUsers };

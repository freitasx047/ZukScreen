/**
 * Integração Pix — Z.PAY Solutions
 * Docs oficiais: https://zpaysolution.com/docs/#payments-create
 *
 * Este módulo é a ÚNICA parte do site que fala diretamente com a Z.PAY.
 * A client-secret nunca sai daqui — o front-end (public/index.html) só
 * conversa com as rotas /api/donations/* do nosso próprio servidor
 * (ver server.js), que por sua vez chamam essas funções.
 *
 * Regras respeitadas:
 * - Só as rotas documentadas abaixo, nenhuma inventada.
 * - Auth (client-id/client-secret) sempre em headers, nunca em query string.
 * - GET /payments/{id} é o único endpoint usado no loop de status — é ele
 *   quem credita o saldo quando o Pix cai. approve NUNCA é chamado em loop.
 */

"use strict";

const BASE_URL = "https://zpaysolution.com/api/v1";

const CLIENT_ID = process.env.ZPAY_CLIENT_ID;
const CLIENT_SECRET = process.env.ZPAY_CLIENT_SECRET;

// Tag padrão para identificar doações do ZukScreen
const ZUK_SCREEN_TAG = "ZukScreen";

function isConfigured() {
  return Boolean(CLIENT_ID && CLIENT_SECRET);
}

function authHeaders(extra = {}) {
  return {
    "client-id": CLIENT_ID,
    "client-secret": CLIENT_SECRET,
    ...extra,
  };
}

// Traduz os códigos de erro conhecidos da API em mensagens úteis pro log/UI.
class ZPayError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ZPayError";
    this.status = status;
  }
}

async function parseErrorResponse(res) {
  let bodyText = "";
  try {
    bodyText = await res.text();
  } catch (_) {
    /* ignore */
  }

  switch (res.status) {
    case 400:
      return new ZPayError(400, `Corpo/valor inválido enviado à Z.PAY: ${bodyText}`);
    case 401:
      return new ZPayError(401, "client-id/client-secret inválidos ou ausentes.");
    case 404:
      return new ZPayError(404, "paymentId inexistente.");
    case 429:
      return new ZPayError(429, "Rate limit da Z.PAY atingido. Aguarde um pouco.");
    case 503:
      return new ZPayError(503, "Gateway da Z.PAY indisponível no momento.");
    default:
      return new ZPayError(res.status, `Erro inesperado da Z.PAY (HTTP ${res.status}): ${bodyText}`);
  }
}

/**
 * Cria uma cobrança Pix.
 * @param {{amount:number, payerName:string, description?:string, tag?:string}} params
 * @returns {Promise<{paymentId:string, status:string, copyPaste:string, qrCodeBase64:string, qrcodeUrl:string}>}
 */
async function createPayment({ amount, payerName, description, tag = ZUK_SCREEN_TAG }) {
  if (!isConfigured()) {
    throw new ZPayError(500, "ZPAY_CLIENT_ID/ZPAY_CLIENT_SECRET não configurados no servidor.");
  }
  if (typeof amount !== "number" || Number.isNaN(amount) || amount < 2.0 || amount > 2000.0) {
    throw new ZPayError(400, "amount deve ser um número entre 2.00 e 2000.00");
  }
  if (!payerName || typeof payerName !== "string") {
    throw new ZPayError(400, "payerName é obrigatório");
  }
  if (description && description.length > 200) {
    throw new ZPayError(400, "description deve ter no máximo 200 caracteres");
  }

  const body = { amount, payerName };
  if (description) body.description = description;
  if (tag) body.tag = tag;

  const res = await fetch(`${BASE_URL}/payments`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });

  if (!res.ok) throw await parseErrorResponse(res);
  return res.json();
}

/**
 * Consulta o status de uma cobrança. Sempre responde 200 (status vem no corpo).
 * status: pending | paid | failed | expired
 */
async function getPaymentStatus(paymentId) {
  if (!isConfigured()) {
    throw new ZPayError(500, "ZPAY_CLIENT_ID/ZPAY_CLIENT_SECRET não configurados no servidor.");
  }
  const res = await fetch(`${BASE_URL}/payments/${encodeURIComponent(paymentId)}`, {
    method: "GET",
    headers: authHeaders(),
  });

  if (!res.ok) throw await parseErrorResponse(res);
  return res.json();
}

/**
 * Approve — opcional, chamada única e pontual. Se o Pix ainda não caiu,
 * a Z.PAY responde 409 (não é um erro de sistema, é só "ainda não pago").
 */
async function approvePaymentOnce(paymentId) {
  if (!isConfigured()) {
    throw new ZPayError(500, "ZPAY_CLIENT_ID/ZPAY_CLIENT_SECRET não configurados no servidor.");
  }
  const res = await fetch(`${BASE_URL}/payments/${encodeURIComponent(paymentId)}/approve`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({}),
  });

  if (res.status === 409) {
    return { pending: true };
  }
  if (!res.ok) throw await parseErrorResponse(res);
  return res.json();
}

const VALID_DONATION_STATUSES = new Set(["pending", "paid", "expired", "failed", "all"]);

/**
 * Lista doações. Docs: https://zpaysolution.com/docs/#donations
 * GET /donations?status=paid&limit=10&page=1&tag=...
 * Retorna { items: [...], pagination: { page, limit, total, totalPages } }
 */
async function listDonations({ status = "paid", limit = 10, page = 1, tag = ZUK_SCREEN_TAG } = {}) {
  if (!isConfigured()) {
    throw new ZPayError(500, "ZPAY_CLIENT_ID/ZPAY_CLIENT_SECRET não configurados no servidor.");
  }
  if (!VALID_DONATION_STATUSES.has(status)) {
    throw new ZPayError(400, `status inválido. Use um de: ${[...VALID_DONATION_STATUSES].join(", ")}`);
  }

  const clampedLimit = Math.min(Math.max(parseInt(limit, 10) || 10, 1), 50);
  const clampedPage = Math.max(parseInt(page, 10) || 1, 1);

  const params = new URLSearchParams({
    status,
    limit: String(clampedLimit),
    page: String(clampedPage),
  });
  if (tag) params.set("tag", tag);

  const res = await fetch(`${BASE_URL}/donations?${params.toString()}`, {
    method: "GET",
    headers: authHeaders(),
  });

  if (!res.ok) throw await parseErrorResponse(res);
  return res.json();
}

/**
 * Ranking dos maiores apoiadores (doações pagas). Docs: mesma página de /donations.
 * GET /top-donates?limit=5  (1 a 100)
 */
async function getTopDonates({ limit = 5 } = {}) {
  if (!isConfigured()) {
    throw new ZPayError(500, "ZPAY_CLIENT_ID/ZPAY_CLIENT_SECRET não configurados no servidor.");
  }
  const clampedLimit = Math.min(Math.max(parseInt(limit, 10) || 5, 1), 100);

  const res = await fetch(`${BASE_URL}/top-donates?limit=${clampedLimit}`, {
    method: "GET",
    headers: authHeaders(),
  });

  if (!res.ok) throw await parseErrorResponse(res);
  return res.json();
}

/**
 * Estatísticas gerais da conta Z.PAY. GET /stats
 */
async function getStats() {
  if (!isConfigured()) {
    throw new ZPayError(500, "ZPAY_CLIENT_ID/ZPAY_CLIENT_SECRET não configurados no servidor.");
  }
  const res = await fetch(`${BASE_URL}/stats`, {
    method: "GET",
    headers: authHeaders(),
  });

  if (!res.ok) throw await parseErrorResponse(res);
  return res.json();
}

module.exports = {
  isConfigured,
  createPayment,
  getPaymentStatus,
  approvePaymentOnce,
  listDonations,
  getTopDonates,
  getStats,
  ZPayError,
};
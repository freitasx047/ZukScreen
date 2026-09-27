// Ponto de entrada serverless da Vercel. Só reaproveita o app Express que já
// existe em server/server.js — nenhuma rota foi duplicada ou reescrita aqui.
// /public continua servido direto pela Vercel (CDN), fora dessa função.
module.exports = require("../server/server.js");

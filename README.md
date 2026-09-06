# ZUK SCREEN

Site para transmitir tela em salas com nome, código e senha opcional, com convite
de amigos do Discord. Projeto dividido em **backend** (Node.js/Express) e
**frontend** (HTML/CSS/JS puro), do jeito certo — não é mais um único HTML solto.

## Estrutura

```
zukscreen/
├── server/
│   ├── server.js       -> API + autenticação + sinalização WebRTC (Socket.io)
│   ├── rooms.js         -> Lógica de salas (código, senha com hash, nome único)
│   └── package.json
└── public/
    └── index.html       -> Front-end (chama a API e o WebSocket do backend)
```

## Como rodar

1. Copie `server/.env.example` para `server/.env` e preencha com os dados
   do seu app em https://discord.com/developers/applications (Client ID,
   Client Secret e o Redirect URI que você cadastrou lá).
2. Instale e rode:

```bash
cd server
npm install
npm start
```

Acesse **http://localhost:3000** — o próprio Express já serve o front-end da
pasta `public/`, então é um único servidor rodando as duas pontas. O botão
"Entrar com Discord" agora faz o fluxo OAuth2 real: te leva pro Discord,
você autoriza, e volta logado com seu nome e avatar verdadeiros.

## O que é backend de verdade aqui

- **Autenticação**: sessão emitida via JWT guardado em cookie `httpOnly` —
  inacessível por JavaScript no navegador da vítima, mesmo em caso de XSS.
- **Salas**: guardadas em memória no servidor (`rooms.js`), nunca no
  navegador. Cada sala tem código único gerado com `crypto.randomFillSync`
  (não é `Math.random`, que não é seguro pra isso).
- **Senha da sala**: se você definir uma, ela é hasheada com **bcrypt**
  (`10 salt rounds`) antes de ser guardada — o servidor nunca armazena a
  senha em texto puro, nem o dono da sala consegue "ver" a senha depois.
- **Transmissão de tela**: usa **WebRTC** de verdade (`getDisplayMedia`).
  O servidor só participa da etapa de sinalização (trocar "endereços" entre
  quem transmite e quem assiste) via **Socket.io** — o vídeo em si viaja
  direto entre os dispositivos, sem passar pelo servidor.

## Proteções aplicadas (a parte que você pediu: "coloca proteção")

| Proteção | Onde | Pra quê |
|---|---|---|
| `helmet` com CSP | `server.js` | Bloqueia scripts/estilos de fontes não autorizadas, mitiga XSS |
| `cors` restrito a uma origem | `server.js` | Impede que outros sites façam requisições autenticadas em nome do usuário |
| Cookie `httpOnly` + `sameSite: lax` | `server.js` | Protege a sessão contra roubo via XSS e ataques CSRF básicos |
| `express-rate-limit` (geral e em login de sala) | `server.js` | Impede brute-force de senha de sala e flood de requisições |
| Hash de senha com `bcryptjs` | `rooms.js` | Senha de sala nunca fica em texto puro, nem em memória por muito tempo |
| Sanitização de nome de sala (`<[^>]*>`) | `rooms.js` | Evita HTML/script injetado no nome da sala (XSS armazenado) |
| Limite de tamanho de payload (`10kb`) e de mensagens Socket.io (`1e5`) | `server.js` | Evita ataques de payload gigante / DoS simples |
| Rate limit por socket | `server.js` | Evita spam de eventos de sinalização WebRTC |
| Código de sala aleatório e criptográfico | `rooms.js` | Difícil de adivinhar por força bruta |
| Sinalização só repassada dentro da mesma sala | `server.js` | Um usuário de uma sala não consegue interceptar sinal de outra sala |

## O que ainda depende de você pra virar produção

- **Login real do Discord**: já está implementado (`/api/auth/discord/login`
  e `/api/auth/discord/callback`) — só falta você preencher o `.env` com
  as credenciais do seu app.
- **Lista de amigos real**: a API do Discord não permite ler a lista de
  amigos de um usuário por questões de privacidade — só é possível convidar
  via DM/webhook se o próprio amigo autorizar o app ou estiver no mesmo
  servidor (guild) que um bot seu. A lista atual é só de demonstração.
- **HTTPS**: em produção, coloque atrás de um proxy (Nginx/Caddy) com
  certificado válido — sem HTTPS o WebRTC e os cookies seguros não
  funcionam corretamente entre domínios diferentes.
- **Banco de dados**: hoje as salas somem se o servidor reiniciar (ficam só
  em memória). Pra persistir, plugue um Redis ou Postgres em `rooms.js`.

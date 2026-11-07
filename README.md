# Memories — backend

Node.js **Express** REST API for the [Memories](https://github.com/gipsy/memories-fe) app: user authentication and CRUD for shared “memory” posts stored in **MongoDB** (Mongoose).

## What it does

- **Users** — register, sign in (bcrypt + JWT), or exchange a Google authorization code for tokens
- **Posts** — create, read, update, delete; paginated list; search by title and tags
- **Engagement** — like posts and append comments (authenticated routes use JWT middleware)

## Stack

- Express 4, ES modules
- Mongoose 7
- `jsonwebtoken`, `bcryptjs`, `google-auth-library`
- CORS enabled for browser clients

## Prerequisites

- Node.js 18+
- MongoDB Atlas (or any MongoDB) connection string

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Environment variables — either copy `.env.example` to `.env` and fill in values, or from the repo root run:

   ```bash
   ./scripts/pull-render-env.sh
   ```

   (`render login` required.) Remote service: **memories** on Render (`memories-hlg7.onrender.com`).

3. Start the API:

   ```bash
   npm start          # production: node index.js
   npm run dev        # local: nodemon
   ```

   Default port is **5000** (Render sets `PORT`).

## Deploy (Render)

| Setting | Value |
|--------|--------|
| Build | `npm install` |
| Start | `npm start` (`node index.js`) |
| Node | **20** — set `NODE_VERSION=20` in the dashboard (or `package.json` `engines` + `.nvmrc`) |
| `CONNECTION_URL` | Atlas **M0** URI for `cluster0…` (not the old `clustermemories` host) |

**Atlas:** [Network Access](https://www.mongodb.com/docs/atlas/security/ip-access-list/) must allow Render (often `0.0.0.0/0` on M0). Otherwise logs show *“IP isn’t whitelisted”* even when the URI is correct.

**If logs show Node 14 EOL:** an old deploy (pre-`657b04f`) — today’s **live** deploy uses Node 20 and connects to Mongo. See `render.yaml`.

## HTTP surface

| Prefix | Purpose |
|--------|---------|
| `GET /` | Health message |
| `/posts` | Post listing, search, CRUD, likes, comments |
| `/user` | Sign up / sign in |

Protected routes expect `Authorization: Bearer <token>`.

## Related repo

React client: [memories-fe](https://github.com/gipsy/memories-fe).

## Security / dependencies

Runtime dependencies are kept current via `npm audit fix` and version bumps in `package.json`. `npm overrides` pins `minimatch` for the `nodemon` dev dependency tree. Production installs should report **0 vulnerabilities** after `npm audit`.

> **Note:** Sign-in currently uses a placeholder JWT secret in code (`'test'`). Replace this with `process.env` before any real deployment.

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
   npm start
   ```

   Default port is **5000** (`nodemon` watches `index.js`).

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

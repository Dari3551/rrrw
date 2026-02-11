# ChatKick API (Railway-ready)

## Download + run
1) Create Postgres and run `schema.sql`.
2) Copy `.env.example` -> `.env` and fill values.
3) Run:
   - npm i
   - npm run dev
4) Health:
   - GET /health

## Deploy on Railway (Online)
1) New Railway Project
2) Add **PostgreSQL** plugin
3) Run `schema.sql` inside Railway Postgres (Query tab)
4) Deploy this code (upload zip to GitHub then connect, or use Railway's GitHub deploy)
5) Set Railway Variables:
   - DATABASE_URL (from Railway Postgres)
   - JWT_SECRET
   - CORS_ORIGIN (your frontend URL)
   - LIVEKIT_URL
   - LIVEKIT_API_KEY
   - LIVEKIT_API_SECRET
6) Test:
   - https://YOUR-RAILWAY-APP/health

## Endpoints (MVP)
- POST /auth/register {email, username, password}
- POST /auth/login {email, password}
- POST /auth/logout
- GET /me
- PATCH /me {username?, avatar_url?, settings?:{language}}
- GET /servers
- POST /servers {name, icon_url?}
- GET /servers/:serverId/roles
- POST /servers/:serverId/roles
- GET /servers/:serverId/channels
- POST /servers/:serverId/channels
- GET /channels/:channelId/messages
- POST /channels/:channelId/messages
- GET /friends
- POST /friends/request {username}
- POST /friends/accept {username}
- GET /voice/token?room=ROOM_NAME

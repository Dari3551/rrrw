# ChatKick API (Token Auth) — Free hosting friendly

This backend avoids cross-site cookie issues by using **Bearer tokens**.

## Deploy on Render (Free)
1. New → PostgreSQL (Free) → copy External Database URL.
2. New → Web Service → connect GitHub repo.
3. Env Vars:
   - DATABASE_URL
   - JWT_SECRET
   - CORS_ORIGINS (comma-separated, e.g. https://xxxx.netlify.app)
   - LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET
4. Run `schema.sql` in the database Query tool.

## Test
- GET /health
- POST /auth/register
- POST /auth/login

Use header: `Authorization: Bearer <token>` for protected routes.
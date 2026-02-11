import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import { z } from "zod";
import { pool } from "./db.js";
import { signToken, authMiddleware } from "./auth.js";
import { DEFAULT_PERMS, hasPerm } from "./permissions.js";
import { createServer } from "http";
import { Server as IOServer } from "socket.io";
import { AccessToken } from "livekit-server-sdk";

const app = express();
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));

app.get("/health", (_, res) => res.json({ ok: true, name: "chatkick-api" }));

// ---------- AUTH ----------
app.post("/auth/register", async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    username: z.string().min(3).max(24).regex(/^[a-zA-Z0-9_.]+$/),
    password: z.string().min(8).max(72)
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input", details: parsed.error.issues });

  const { email, username, password } = parsed.data;
  const hash = await bcrypt.hash(password, 12);

  try {
    const q = await pool.query(
      "insert into users(email, username, password_hash) values($1,$2,$3) returning id, email, username, avatar_url, settings",
      [email.toLowerCase(), username, hash]
    );
    const user = q.rows[0];
    const token = signToken(user);
    res.cookie("ck_token", token, { httpOnly: true, sameSite: "lax", secure: true });
    return res.json({ user });
  } catch (e) {
    const msg = String(e?.message || e);
    if (msg.includes("users_email_key")) return res.status(409).json({ error: "email_taken" });
    if (msg.includes("users_username_key")) return res.status(409).json({ error: "username_taken" });
    return res.status(500).json({ error: "server_error" });
  }
});

app.post("/auth/login", async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(1) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const { email, password } = parsed.data;
  const q = await pool.query("select id, email, username, password_hash, avatar_url, settings from users where email=$1", [email.toLowerCase()]);
  const user = q.rows[0];
  if (!user) return res.status(401).json({ error: "invalid_credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid_credentials" });

  const token = signToken(user);
  res.cookie("ck_token", token, { httpOnly: true, sameSite: "lax", secure: true });
  delete user.password_hash;
  return res.json({ user });
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie("ck_token");
  res.json({ ok: true });
});

app.get("/me", authMiddleware, async (req, res) => {
  const q = await pool.query("select id, email, username, avatar_url, settings from users where id=$1", [req.user.uid]);
  res.json({ user: q.rows[0] || null });
});

app.patch("/me", authMiddleware, async (req, res) => {
  const schema = z.object({
    username: z.string().min(3).max(24).regex(/^[a-zA-Z0-9_.]+$/).optional(),
    avatar_url: z.string().url().optional(),
    settings: z.object({ language: z.string().min(2).max(10) }).partial().optional()
  }).strict();
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const { username, avatar_url, settings } = parsed.data;
  try {
    if (username) await pool.query("update users set username=$1 where id=$2", [username, req.user.uid]);
    if (avatar_url) await pool.query("update users set avatar_url=$1 where id=$2", [avatar_url, req.user.uid]);
    if (settings?.language) await pool.query(
      "update users set settings = jsonb_set(settings, '{language}', to_jsonb($1::text), true) where id=$2",
      [settings.language, req.user.uid]
    );

    const q = await pool.query("select id, email, username, avatar_url, settings from users where id=$1", [req.user.uid]);
    return res.json({ user: q.rows[0] });
  } catch (e) {
    const msg = String(e?.message || e);
    if (msg.includes("users_username_key")) return res.status(409).json({ error: "username_taken" });
    return res.status(500).json({ error: "server_error" });
  }
});

// ---------- SERVERS ----------
app.get("/servers", authMiddleware, async (req, res) => {
  const q = await pool.query(
    `select s.*, sm.role_id, r.name as role_name, r.permissions as role_permissions
     from server_members sm
     join servers s on s.id = sm.server_id
     left join roles r on r.id = sm.role_id
     where sm.user_id = $1
     order by s.created_at desc`,
    [req.user.uid]
  );
  res.json({ servers: q.rows });
});

app.post("/servers", authMiddleware, async (req, res) => {
  const schema = z.object({ name: z.string().min(2).max(60), icon_url: z.string().url().optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const { name, icon_url } = parsed.data;
  const client = await pool.connect();
  try {
    await client.query("begin");
    const s = await client.query(
      "insert into servers(owner_id, name, icon_url) values($1,$2,$3) returning *",
      [req.user.uid, name, icon_url || null]
    );
    const server = s.rows[0];

    const ownerRole = await client.query(
      "insert into roles(server_id, name, position, permissions) values($1,$2,$3,$4) returning *",
      [server.id, "Owner", 100, { ...DEFAULT_PERMS, admin: true, manage_server: true, manage_roles: true, manage_channels: true }]
    );
    const memberRole = await client.query(
      "insert into roles(server_id, name, position, permissions) values($1,$2,$3,$4) returning *",
      [server.id, "Member", 1, DEFAULT_PERMS]
    );

    await client.query(
      "insert into server_members(server_id, user_id, role_id) values($1,$2,$3)",
      [server.id, req.user.uid, ownerRole.rows[0].id]
    );

    const ch = await client.query(
      "insert into channels(server_id, name, type) values ($1,$2,'text'),($1,$3,'text'),($1,$4,'voice') returning *",
      [server.id, "welcome", "general", "voice-lobby"]
    );

    await client.query("commit");
    res.json({ server, roles: { owner: ownerRole.rows[0], member: memberRole.rows[0] }, channels: ch.rows });
  } catch (e) {
    await client.query("rollback");
    res.status(500).json({ error: "server_error" });
  } finally {
    client.release();
  }
});

// ---------- ROLES ----------
app.get("/servers/:serverId/roles", authMiddleware, async (req, res) => {
  const { serverId } = req.params;
  const m = await pool.query("select 1 from server_members where server_id=$1 and user_id=$2", [serverId, req.user.uid]);
  if (!m.rows[0]) return res.status(403).json({ error: "forbidden" });

  const q = await pool.query("select * from roles where server_id=$1 order by position desc", [serverId]);
  res.json({ roles: q.rows });
});

app.post("/servers/:serverId/roles", authMiddleware, async (req, res) => {
  const { serverId } = req.params;
  const schema = z.object({
    name: z.string().min(2).max(40),
    position: z.number().int().min(0).max(999).optional(),
    permissions: z.record(z.boolean()).optional()
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const mm = await pool.query(
    `select r.permissions from server_members sm left join roles r on r.id=sm.role_id
     where sm.server_id=$1 and sm.user_id=$2`,
    [serverId, req.user.uid]
  );
  const perms = mm.rows[0]?.permissions || {};
  if (!hasPerm(perms, "manage_roles")) return res.status(403).json({ error: "forbidden" });

  const { name, position, permissions } = parsed.data;
  const q = await pool.query(
    "insert into roles(server_id,name,position,permissions) values($1,$2,$3,$4) returning *",
    [serverId, name, position ?? 10, permissions ?? DEFAULT_PERMS]
  );
  res.json({ role: q.rows[0] });
});

// ---------- CHANNELS (visibility filtered) ----------
app.get("/servers/:serverId/channels", authMiddleware, async (req, res) => {
  const { serverId } = req.params;

  const mm = await pool.query(
    `select sm.role_id, r.permissions
     from server_members sm left join roles r on r.id=sm.role_id
     where sm.server_id=$1 and sm.user_id=$2`,
    [serverId, req.user.uid]
  );
  if (!mm.rows[0]) return res.status(403).json({ error: "forbidden" });
  const roleId = mm.rows[0].role_id;

  if (mm.rows[0].permissions?.admin) {
    const q = await pool.query("select * from channels where server_id=$1 order by created_at asc", [serverId]);
    return res.json({ channels: q.rows });
  }

  const q = await pool.query(
    `select c.*
     from channels c
     left join channel_permissions cp_allow on cp_allow.channel_id=c.id and cp_allow.role_id=$2
     where c.server_id=$1
       and not exists (
         select 1 from channel_permissions cp_deny
         where cp_deny.channel_id=c.id and cp_deny.role_id=$2 and (cp_deny.deny->>'view_channel')::boolean = true
       )
       and (
         not exists (select 1 from channel_permissions cp2 where cp2.channel_id=c.id)
         or ((cp_allow.allow->>'view_channel')::boolean = true)
       )
     order by c.created_at asc`,
    [serverId, roleId]
  );
  res.json({ channels: q.rows });
});

app.post("/servers/:serverId/channels", authMiddleware, async (req, res) => {
  const { serverId } = req.params;
  const schema = z.object({ name: z.string().min(1).max(40), type: z.enum(["text","voice"]) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const mm = await pool.query(
    `select r.permissions from server_members sm left join roles r on r.id=sm.role_id
     where sm.server_id=$1 and sm.user_id=$2`,
    [serverId, req.user.uid]
  );
  const perms = mm.rows[0]?.permissions || {};
  if (!hasPerm(perms, "manage_channels")) return res.status(403).json({ error: "forbidden" });

  const q = await pool.query(
    "insert into channels(server_id,name,type) values($1,$2,$3) returning *",
    [serverId, parsed.data.name, parsed.data.type]
  );
  res.json({ channel: q.rows[0] });
});

// ---------- MESSAGES ----------
app.get("/channels/:channelId/messages", authMiddleware, async (req, res) => {
  const { channelId } = req.params;
  const m = await pool.query("select server_id from channels where id=$1", [channelId]);
  const serverId = m.rows[0]?.server_id;
  if (!serverId) return res.status(404).json({ error: "not_found" });

  const mem = await pool.query("select 1 from server_members where server_id=$1 and user_id=$2", [serverId, req.user.uid]);
  if (!mem.rows[0]) return res.status(403).json({ error: "forbidden" });

  const q = await pool.query("select * from messages where channel_id=$1 order by created_at asc limit 200", [channelId]);
  res.json({ messages: q.rows });
});

app.post("/channels/:channelId/messages", authMiddleware, async (req, res) => {
  const { channelId } = req.params;
  const schema = z.object({ content: z.string().min(1).max(2000) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const m = await pool.query("select server_id from channels where id=$1", [channelId]);
  const serverId = m.rows[0]?.server_id;
  if (!serverId) return res.status(404).json({ error: "not_found" });

  const mem = await pool.query("select 1 from server_members where server_id=$1 and user_id=$2", [serverId, req.user.uid]);
  if (!mem.rows[0]) return res.status(403).json({ error: "forbidden" });

  const q = await pool.query(
    "insert into messages(channel_id,user_id,content) values($1,$2,$3) returning *",
    [channelId, req.user.uid, parsed.data.content]
  );
  res.json({ message: q.rows[0] });
});

// ---------- FRIENDS ----------
app.post("/friends/request", authMiddleware, async (req, res) => {
  const schema = z.object({ username: z.string().min(3).max(24) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const u = await pool.query("select id, username from users where username=$1", [parsed.data.username]);
  const target = u.rows[0];
  if (!target) return res.status(404).json({ error: "user_not_found" });
  if (target.id === req.user.uid) return res.status(400).json({ error: "cannot_add_self" });

  try {
    const q = await pool.query(
      "insert into friendships(requester_id, addressee_id, status) values($1,$2,'pending') returning *",
      [req.user.uid, target.id]
    );
    res.json({ request: q.rows[0] });
  } catch {
    res.status(409).json({ error: "already_requested" });
  }
});

app.post("/friends/accept", authMiddleware, async (req, res) => {
  const schema = z.object({ username: z.string().min(3).max(24) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const u = await pool.query("select id from users where username=$1", [parsed.data.username]);
  const other = u.rows[0];
  if (!other) return res.status(404).json({ error: "user_not_found" });

  const q = await pool.query(
    `update friendships set status='accepted'
     where requester_id=$1 and addressee_id=$2 and status='pending'
     returning *`,
    [other.id, req.user.uid]
  );
  if (!q.rows[0]) return res.status(404).json({ error: "request_not_found" });
  res.json({ friendship: q.rows[0] });
});

app.get("/friends", authMiddleware, async (req, res) => {
  const q = await pool.query(
    `select f.status,
            u1.username as requester,
            u2.username as addressee
     from friendships f
     join users u1 on u1.id=f.requester_id
     join users u2 on u2.id=f.addressee_id
     where f.requester_id=$1 or f.addressee_id=$1
     order by f.created_at desc`,
    [req.user.uid]
  );
  res.json({ friends: q.rows });
});

// ---------- LIVEKIT TOKEN ----------
app.get("/voice/token", authMiddleware, async (req, res) => {
  const schema = z.object({ room: z.string().min(1).max(120), name: z.string().min(1).max(80).optional() });
  const parsed = schema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const { room } = parsed.data;
  const q = await pool.query("select username from users where id=$1", [req.user.uid]);
  const username = parsed.data.name || q.rows[0]?.username || "user";

  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  const lkUrl = process.env.LIVEKIT_URL;
  if (!apiKey || !apiSecret || !lkUrl) return res.status(500).json({ error: "livekit_env_missing" });

  const at = new AccessToken(apiKey, apiSecret, { identity: username });
  at.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true });
  const token = await at.toJwt();

  res.json({ token, url: lkUrl });
});

// ---------- SOCKET.IO ----------
const httpServer = createServer(app);
const io = new IOServer(httpServer, { cors: { origin: process.env.CORS_ORIGIN, credentials: true } });

io.on("connection", (socket) => {
  socket.on("joinChannel", ({ channelId }) => channelId && socket.join(`ch:${channelId}`));
  socket.on("leaveChannel", ({ channelId }) => channelId && socket.leave(`ch:${channelId}`));

  socket.on("sendMessage", async ({ channelId, content, userId }) => {
    if (!channelId || !content || !userId) return;
    const q = await pool.query(
      "insert into messages(channel_id,user_id,content) values($1,$2,$3) returning *",
      [channelId, userId, String(content).slice(0, 2000)]
    );
    io.to(`ch:${channelId}`).emit("message", q.rows[0]);
  });
});

const port = process.env.PORT || 8080;
httpServer.listen(port, () => console.log("ChatKick API listening on", port));

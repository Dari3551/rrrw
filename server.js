import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import bcrypt from "bcrypt";
import { z } from "zod";
import { pool } from "./db.js";
import { signToken, authMiddleware } from "./auth.js";
import { DEFAULT_PERMS, hasPerm } from "./permissions.js";
import { createServer } from "http";
import { Server as IOServer } from "socket.io";
import { AccessToken } from "livekit-server-sdk";

const app = express();
app.set("trust proxy", 1);
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());

const origins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (origins.length === 0) return cb(null, true);
      return cb(null, origins.includes(origin));
    },
    credentials: false,
  })
);

app.get("/health", (_, res) => res.json({ ok: true, name: "chatkick-api-token" }));

app.post("/auth/register", async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    username: z.string().min(3).max(24).regex(/^[a-zA-Z0-9_.]+$/),
    password: z.string().min(8).max(72),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success)
    return res.status(400).json({ error: "invalid_input", details: parsed.error.issues });

  const { email, username, password } = parsed.data;
  const hash = await bcrypt.hash(password, 12);

  try {
    const q = await pool.query(
      "insert into users(email, username, password_hash) values($1,$2,$3) returning id, email, username, avatar_url, settings",
      [email.toLowerCase(), username, hash]
    );
    const user = q.rows[0];
    const token = signToken(user);
    return res.json({ token, user });
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
  const q = await pool.query(
    "select id, email, username, password_hash, avatar_url, settings from users where email=$1",
    [email.toLowerCase()]
  );
  const user = q.rows[0];
  if (!user) return res.status(401).json({ error: "invalid_credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid_credentials" });

  const token = signToken(user);
  delete user.password_hash;
  return res.json({ token, user });
});

app.get("/me", authMiddleware, async (req, res) => {
  const q = await pool.query(
    "select id, email, username, avatar_url, settings from users where id=$1",
    [req.user.uid]
  );
  res.json({ user: q.rows[0] || null });
});

app.patch("/me", authMiddleware, async (req, res) => {
  const schema = z
    .object({
      username: z.string().min(3).max(24).regex(/^[a-zA-Z0-9_.]+$/).optional(),
      avatar_url: z.string().url().optional(),
      settings: z.object({ language: z.string().min(2).max(10) }).partial().optional(),
    })
    .strict();
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const { username, avatar_url, settings } = parsed.data;
  try {
    if (username) await pool.query("update users set username=$1 where id=$2", [username, req.user.uid]);
    if (avatar_url) await pool.query("update users set avatar_url=$1 where id=$2", [avatar_url, req.user.uid]);
    if (settings?.language)
      await pool.query(
        "update users set settings = jsonb_set(settings, '{language}', to_jsonb($1::text), true) where id=$2",
        [settings.language, req.user.uid]
      );

    const q = await pool.query(
      "select id, email, username, avatar_url, settings from users where id=$1",
      [req.user.uid]
    );
    return res.json({ user: q.rows[0] });
  } catch (e) {
    const msg = String(e?.message || e);
    if (msg.includes("users_username_key")) return res.status(409).json({ error: "username_taken" });
    return res.status(500).json({ error: "server_error" });
  }
});

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

    await client.query("insert into server_members(server_id, user_id, role_id) values($1,$2,$3)", [
      server.id,
      req.user.uid,
      ownerRole.rows[0].id,
    ]);

    const ch = await client.query(
      "insert into channels(server_id, name, type) values ($1,$2,'text'),($1,$3,'text'),($1,$4,'voice') returning *",
      [server.id, "welcome", "general", "voice-lobby"]
    );

    await client.query("commit");
    res.json({ server, roles: { owner: ownerRole.rows[0], member: memberRole.rows[0] }, channels: ch.rows });
  } catch {
    await client.query("rollback");
    res.status(500).json({ error: "server_error" });
  } finally {
    client.release();
  }
});

app.get("/servers/:serverId/channels", authMiddleware, async (req, res) => {
  const { serverId } = req.params;
  const mem = await pool.query(
    "select sm.role_id, r.permissions from server_members sm left join roles r on r.id=sm.role_id where sm.server_id=$1 and sm.user_id=$2",
    [serverId, req.user.uid]
  );
  if (!mem.rows[0]) return res.status(403).json({ error: "forbidden" });

  const q = await pool.query("select * from channels where server_id=$1 order by created_at asc", [serverId]);
  res.json({ channels: q.rows });
});

app.post("/servers/:serverId/channels", authMiddleware, async (req, res) => {
  const { serverId } = req.params;
  const schema = z.object({ name: z.string().min(1).max(40), type: z.enum(["text", "voice"]) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const mm = await pool.query(
    `select r.permissions from server_members sm left join roles r on r.id=sm.role_id
     where sm.server_id=$1 and sm.user_id=$2`,
    [serverId, req.user.uid]
  );
  const perms = mm.rows[0]?.permissions || {};
  if (!hasPerm(perms, "manage_channels")) return res.status(403).json({ error: "forbidden" });

  const q = await pool.query("insert into channels(server_id,name,type) values($1,$2,$3) returning *", [
    serverId,
    parsed.data.name,
    parsed.data.type,
  ]);
  res.json({ channel: q.rows[0] });
});

app.get("/channels/:channelId/messages", authMiddleware, async (req, res) => {
  const { channelId } = req.params;
  const q = await pool.query("select * from messages where channel_id=$1 order by created_at asc limit 200", [channelId]);
  res.json({ messages: q.rows });
});

app.post("/channels/:channelId/messages", authMiddleware, async (req, res) => {
  const { channelId } = req.params;
  const schema = z.object({ content: z.string().min(1).max(2000) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const q = await pool.query("insert into messages(channel_id,user_id,content) values($1,$2,$3) returning *", [
    channelId,
    req.user.uid,
    parsed.data.content,
  ]);
  res.json({ message: q.rows[0] });
});

app.get("/friends", authMiddleware, async (req, res) => {
  const q = await pool.query(
    `select f.status, u1.username as requester, u2.username as addressee
     from friendships f
     join users u1 on u1.id=f.requester_id
     join users u2 on u2.id=f.addressee_id
     where f.requester_id=$1 or f.addressee_id=$1
     order by f.created_at desc`,
    [req.user.uid]
  );
  res.json({ friends: q.rows });
});

app.post("/friends/request", authMiddleware, async (req, res) => {
  const schema = z.object({ username: z.string().min(3).max(24) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const u = await pool.query("select id from users where username=$1", [parsed.data.username]);
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

app.get("/voice/token", authMiddleware, async (req, res) => {
  const schema = z.object({ room: z.string().min(1).max(120) });
  const parsed = schema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });

  const room = parsed.data.room;
  const q = await pool.query("select username from users where id=$1", [req.user.uid]);
  const username = q.rows[0]?.username || "user";

  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  const lkUrl = process.env.LIVEKIT_URL;
  if (!apiKey || !apiSecret || !lkUrl) return res.status(500).json({ error: "livekit_env_missing" });

  const at = new AccessToken(apiKey, apiSecret, { identity: username });
  at.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true });
  const token = await at.toJwt();

  res.json({ token, url: lkUrl });
});

const httpServer = createServer(app);
const io = new IOServer(httpServer, { cors: { origin: origins.length ? origins : true } });

io.on("connection", (socket) => {
  socket.on("joinChannel", ({ channelId }) => channelId && socket.join(`ch:${channelId}`));
  socket.on("leaveChannel", ({ channelId }) => channelId && socket.leave(`ch:${channelId}`));
});

const port = process.env.PORT || 8080;
httpServer.listen(port, () => console.log("ChatKick API (token) on", port));
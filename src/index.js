/**
 * XMessager Social Controller — Cloudflare Worker
 * Users/auth, groups, pages, private chats (text in D1), media attachments
 * on Hugging Face (Spacklight/Social-Media) via the same LFS flow as videos.
 */

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_MEDIA_BYTES = 20 * 1024 * 1024;

const AFRICA_REGIONS = {
  DZ:"North Africa", EG:"North Africa", LY:"North Africa", MA:"North Africa", SD:"North Africa", TN:"North Africa",
  BJ:"West Africa", BF:"West Africa", CV:"West Africa", CI:"West Africa", GM:"West Africa", GH:"West Africa",
  GN:"West Africa", GW:"West Africa", LR:"West Africa", ML:"West Africa", MR:"West Africa", NE:"West Africa",
  NG:"West Africa", SN:"West Africa", SL:"West Africa", TG:"West Africa",
  AO:"Central Africa", CM:"Central Africa", CF:"Central Africa", TD:"Central Africa", CG:"Central Africa",
  CD:"Central Africa", GQ:"Central Africa", GA:"Central Africa",
  BI:"East Africa", KM:"East Africa", DJ:"East Africa", ER:"East Africa", ET:"East Africa", KE:"East Africa",
  MG:"East Africa", MU:"East Africa", RW:"East Africa", SC:"East Africa", SO:"East Africa", SS:"East Africa",
  TZ:"East Africa", UG:"East Africa",
  BW:"Southern Africa", SZ:"Southern Africa", LS:"Southern Africa", MW:"Southern Africa", MZ:"Southern Africa",
  NA:"Southern Africa", ZA:"Southern Africa", ZM:"Southern Africa", ZW:"Southern Africa",
};
function getRegion(continent, country) { if (continent === "AF" && country && AFRICA_REGIONS[country]) return AFRICA_REGIONS[country]; return null; }
function getLocation(request) {
  const continent = request.cf?.continent || null;
  const country = request.cf?.country || null;
  return { continent, country, region: getRegion(continent, country) };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    const p = url.pathname;
    const m = (pattern) => p.match(pattern);

    try {
      if (p === "/api/auth/signup" && request.method === "POST") return await handleSignup(request, env, cors);
      if (p === "/api/auth/login" && request.method === "POST") return await handleLogin(request, env, cors);
      if (p === "/api/me" && request.method === "GET") return await handleMe(request, env, cors);
      if (p === "/api/me" && request.method === "POST") return await handleUpdateMe(request, env, cors);

      if (p === "/api/users/search" && request.method === "GET") return await searchUser(request, env, cors);
      let mm = m(/^\/api\/users\/([a-f0-9-]+)$/);
      if (mm && request.method === "GET") return await getUser(mm[1], request, env, cors);

      if (p === "/api/media/upload" && request.method === "POST") return await handleMediaUpload(request, env, cors);

      if (p === "/api/groups" && request.method === "POST") return await createGroup(request, env, cors);
      if (p === "/api/groups" && request.method === "GET") return await listGroups(request, env, cors);
      if (p === "/api/my/groups" && request.method === "GET") return await listMyGroups(request, env, cors);
      mm = m(/^\/api\/groups\/([a-f0-9-]+)$/);
      if (mm && request.method === "GET") return await getGroup(mm[1], request, env, cors);
      mm = m(/^\/api\/groups\/([a-f0-9-]+)\/join$/);
      if (mm && request.method === "POST") return await joinGroup(mm[1], request, env, cors);
      mm = m(/^\/api\/groups\/([a-f0-9-]+)\/invite$/);
      if (mm && request.method === "POST") return await inviteToGroup(mm[1], request, env, cors);
      mm = m(/^\/api\/groups\/([a-f0-9-]+)\/messages$/);
      if (mm && request.method === "POST") return await postGroupMessage(mm[1], request, env, cors);
      if (mm && request.method === "GET") return await listGroupMessages(mm[1], request, env, cors);

      if (p === "/api/pages" && request.method === "POST") return await createPage(request, env, cors);
      if (p === "/api/pages" && request.method === "GET") return await listPages(request, env, cors);
      if (p === "/api/my/pages" && request.method === "GET") return await listMyPages(request, env, cors);
      mm = m(/^\/api\/pages\/([a-f0-9-]+)$/);
      if (mm && request.method === "GET") return await getPage(mm[1], request, env, cors);
      mm = m(/^\/api\/pages\/([a-f0-9-]+)\/follow$/);
      if (mm && request.method === "POST") return await followPage(mm[1], request, env, cors);
      mm = m(/^\/api\/pages\/([a-f0-9-]+)\/posts$/);
      if (mm && request.method === "POST") return await postPagePost(mm[1], request, env, cors);
      if (mm && request.method === "GET") return await listPagePosts(mm[1], request, env, cors);

      if (p === "/api/chats" && request.method === "POST") return await startChat(request, env, cors);
      if (p === "/api/chats" && request.method === "GET") return await listChats(request, env, cors);
      mm = m(/^\/api\/chats\/([a-f0-9-]+)\/messages$/);
      if (mm && request.method === "POST") return await postChatMessage(mm[1], request, env, cors);
      if (mm && request.method === "GET") return await listChatMessages(mm[1], request, env, cors);

      return json({ error: "Not found" }, 404, cors);
    } catch (err) {
      return json({ error: err.message || "Internal error" }, 500, cors);
    }
  },
};

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}
function bytesToHex(bytes) { return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(""); }
function hexToBytes(hex) { const b = new Uint8Array(hex.length / 2); for (let i=0;i<b.length;i++) b[i]=parseInt(hex.substr(i*2,2),16); return b; }
function timingSafeEqual(a, b) { if (a.length!==b.length) return false; let d=0; for (let i=0;i<a.length;i++) d|=a.charCodeAt(i)^b.charCodeAt(i); return d===0; }

async function handleSignup(request, env, cors) {
  const body = await request.json();
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  const displayName = (body.display_name || "").trim();
  if (!email || !password || !displayName) return json({ error: "email, password, and display_name are required" }, 400, cors);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Please use a valid email address" }, 400, cors);
  if (password.length < 8) return json({ error: "password must be at least 8 characters" }, 400, cors);

  const existing = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
  if (existing) return json({ error: "An account with this email already exists" }, 409, cors);

  const { hash, salt } = await hashPassword(password);
  const loc = getLocation(request);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.DB.prepare(
    `INSERT INTO users (id,email,password_hash,password_salt,display_name,bio,profile_picture_url,continent,region,country,created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(id, email, hash, salt, displayName, "", null, loc.continent, loc.region, loc.country, createdAt).run();

  const token = await createSession(env, id);
  return json({ token, user: { id, email, display_name: displayName, profile_picture_url: null, continent: loc.continent, region: loc.region, country: loc.country } }, 200, cors);
}

async function handleLogin(request, env, cors) {
  const body = await request.json();
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  const user = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
  if (!user) return json({ error: "Invalid email or password" }, 401, cors);
  const { hash } = await hashPassword(password, user.password_salt);
  if (!timingSafeEqual(hash, user.password_hash)) return json({ error: "Invalid email or password" }, 401, cors);
  const token = await createSession(env, user.id);
  return json({ token, user: { id: user.id, email: user.email, display_name: user.display_name, bio: user.bio, profile_picture_url: user.profile_picture_url } }, 200, cors);
}

async function handleMe(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  return json({ id: user.id, email: user.email, display_name: user.display_name, bio: user.bio, profile_picture_url: user.profile_picture_url, continent: user.continent, region: user.region, country: user.country }, 200, cors);
}

async function searchUser(request, env, cors) {
  const me = await requireAuth(request, env);
  if (!me) return json({ error: "Unauthorized" }, 401, cors);
  const url = new URL(request.url);
  const email = (url.searchParams.get("email") || "").trim().toLowerCase();
  if (!email) return json({ error: "email query param is required" }, 400, cors);
  const user = await env.DB.prepare(`SELECT id, display_name, profile_picture_url FROM users WHERE email = ?`).bind(email).first();
  if (!user) return json({ error: "No user found with that email" }, 404, cors);
  return json(user, 200, cors);
}

async function getUser(userId, request, env, cors) {
  const me = await requireAuth(request, env);
  if (!me) return json({ error: "Unauthorized" }, 401, cors);
  const user = await env.DB.prepare(`SELECT id, display_name, profile_picture_url, bio FROM users WHERE id = ?`).bind(userId).first();
  if (!user) return json({ error: "User not found" }, 404, cors);
  return json(user, 200, cors);
}

async function createSession(env, userId) {
  const token = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)`).bind(token, userId, now, now + SESSION_TTL_MS).run();
  return token;
}
async function requireAuth(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const session = await env.DB.prepare(`SELECT * FROM sessions WHERE token = ?`).bind(token).first();
  if (!session || session.expires_at < Date.now()) return null;
  return await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(session.user_id).first();
}

async function handleMediaUpload(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  if (!env.HF_TOKEN || !env.HF_MEDIA_REPO) return json({ error: "Server misconfigured: HF_TOKEN / HF_MEDIA_REPO not set" }, 500, cors);
  const form = await request.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") return json({ error: "No file provided (field name: 'file')" }, 400, cors);
  const buf = await file.arrayBuffer();
  if (buf.byteLength > MAX_MEDIA_BYTES) return json({ error: `File too large (${(buf.byteLength/1e6).toFixed(1)}MB, limit ${MAX_MEDIA_BYTES/1e6}MB)` }, 413, cors);
  const id = crypto.randomUUID();
  const nameParts = (file.name || "file.bin").split(".");
  const ext = (nameParts.length > 1 ? nameParts.pop() : "bin").toLowerCase();
  const path = `media/${id}.${ext}`;
  const mediaType = (file.type || "").startsWith("image/") ? "image" : (file.type || "").startsWith("video/") ? "video" : "file";
  let oid;
  try { ({ oid } = await uploadViaLfs(env, env.HF_MEDIA_REPO, buf, path)); }
  catch (err) { return json({ error: "Hugging Face LFS upload failed", details: err.message }, 502, cors); }
  const commitBody = JSON.stringify({ key: "header", value: { summary: `Upload media ${id}`, description: `uploader=${user.id}` } }) +
    "\n" + JSON.stringify({ key: "lfsFile", value: { path, algo: "sha256", oid, size: buf.byteLength } });
  const hfRes = await fetch(`https://huggingface.co/api/datasets/${env.HF_MEDIA_REPO}/commit/main`, {
    method: "POST", headers: { Authorization: `Bearer ${env.HF_TOKEN}`, "Content-Type": "application/x-ndjson" }, body: commitBody,
  });
  if (!hfRes.ok) return json({ error: "Hugging Face commit failed", details: await hfRes.text() }, hfRes.status, cors);
  const mediaUrl = `https://huggingface.co/datasets/${env.HF_MEDIA_REPO}/resolve/main/${path}`;
  return json({ media_url: mediaUrl, media_type: mediaType }, 200, cors);
}

async function uploadViaLfs(env, repo, buf, path) {
  const oid = await sha256Hex(buf);
  const size = buf.byteLength;
  const batchRes = await fetch(`https://huggingface.co/datasets/${repo}.git/info/lfs/objects/batch`, {
    method: "POST",
    headers: { Authorization: `Bearer ${env.HF_TOKEN}`, Accept: "application/vnd.git-lfs+json", "Content-Type": "application/vnd.git-lfs+json" },
    body: JSON.stringify({ operation: "upload", transfers: ["basic"], objects: [{ oid, size }], hash_algo: "sha256" }),
  });
  if (!batchRes.ok) throw new Error(`LFS batch request failed: ${await batchRes.text()}`);
  const batchJson = await batchRes.json();
  const obj = batchJson.objects && batchJson.objects[0];
  if (!obj) throw new Error("LFS batch response missing object info");
  if (obj.error) throw new Error(`LFS batch error: ${obj.error.message}`);
  if (obj.actions && obj.actions.upload) {
    const upload = obj.actions.upload;
    const putRes = await fetch(upload.href, { method: "PUT", headers: upload.header || {}, body: buf });
    if (!putRes.ok) throw new Error(`LFS object upload failed: ${putRes.status} ${await putRes.text()}`);
  }
  return { oid, size };
}
async function sha256Hex(buffer) {
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function createGroup(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const body = await request.json();
  const name = (body.name || "").trim();
  const description = (body.description || "").trim();
  const visibility = body.visibility === "private" ? "private" : "public";
  if (!name) return json({ error: "name is required" }, 400, cors);
  const loc = getLocation(request);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO groups (id,name,description,visibility,owner_id,continent,region,country,created_at) VALUES (?,?,?,?,?,?,?,?,?)`)
      .bind(id, name, description, visibility, user.id, loc.continent, loc.region, loc.country, createdAt),
    env.DB.prepare(`INSERT INTO group_members (group_id,user_id,role,joined_at) VALUES (?,?,?,?)`).bind(id, user.id, "owner", createdAt),
  ]);
  return json({ id, name, description, visibility, owner_id: user.id }, 200, cors);
}

async function listGroups(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const url = new URL(request.url);
  const continent = url.searchParams.get("continent");
  const stmt = continent
    ? env.DB.prepare(`SELECT id,name,description,visibility,owner_id,continent,region,country FROM groups WHERE visibility='public' AND continent=? ORDER BY created_at DESC LIMIT 50`).bind(continent)
    : env.DB.prepare(`SELECT id,name,description,visibility,owner_id,continent,region,country FROM groups WHERE visibility='public' ORDER BY created_at DESC LIMIT 50`);
  const { results } = await stmt.all();
  return json({ groups: results }, 200, cors);
}

async function listMyGroups(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const { results } = await env.DB.prepare(
    `SELECT g.*,
      (SELECT content FROM group_messages gm WHERE gm.group_id=g.id ORDER BY gm.created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM group_messages gm WHERE gm.group_id=g.id ORDER BY gm.created_at DESC LIMIT 1) as last_message_at
     FROM groups g JOIN group_members mem ON mem.group_id = g.id
     WHERE mem.user_id = ? ORDER BY last_message_at DESC`
  ).bind(user.id).all();
  return json({ groups: results }, 200, cors);
}

async function getGroupMembership(db, groupId, userId) { return await db.prepare(`SELECT * FROM group_members WHERE group_id=? AND user_id=?`).bind(groupId, userId).first(); }

async function getGroup(groupId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const group = await env.DB.prepare(`SELECT * FROM groups WHERE id=?`).bind(groupId).first();
  if (!group) return json({ error: "Group not found" }, 404, cors);
  if (group.visibility === "private") {
    const member = await getGroupMembership(env.DB, groupId, user.id);
    if (!member) return json({ error: "This group is private" }, 403, cors);
  }
  return json(group, 200, cors);
}

async function joinGroup(groupId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const group = await env.DB.prepare(`SELECT * FROM groups WHERE id=?`).bind(groupId).first();
  if (!group) return json({ error: "Group not found" }, 404, cors);
  if (group.visibility === "private") return json({ error: "This group is private — ask the owner to invite you" }, 403, cors);
  const existing = await getGroupMembership(env.DB, groupId, user.id);
  if (existing) return json({ ok: true, already_member: true }, 200, cors);
  await env.DB.prepare(`INSERT INTO group_members (group_id,user_id,role,joined_at) VALUES (?,?,?,?)`).bind(groupId, user.id, "member", Date.now()).run();
  return json({ ok: true }, 200, cors);
}

async function inviteToGroup(groupId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const group = await env.DB.prepare(`SELECT * FROM groups WHERE id=?`).bind(groupId).first();
  if (!group) return json({ error: "Group not found" }, 404, cors);
  if (group.owner_id !== user.id) return json({ error: "Only the group owner can invite members" }, 403, cors);
  const body = await request.json();
  const targetUserId = body.user_id;
  if (!targetUserId) return json({ error: "user_id is required" }, 400, cors);
  const existing = await getGroupMembership(env.DB, groupId, targetUserId);
  if (existing) return json({ ok: true, already_member: true }, 200, cors);
  await env.DB.prepare(`INSERT INTO group_members (group_id,user_id,role,joined_at) VALUES (?,?,?,?)`).bind(groupId, targetUserId, "member", Date.now()).run();
  return json({ ok: true }, 200, cors);
}

async function postGroupMessage(groupId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const member = await getGroupMembership(env.DB, groupId, user.id);
  if (!member) return json({ error: "You must be a member of this group to post" }, 403, cors);
  const body = await request.json();
  const content = (body.content || "").toString();
  const mediaUrl = body.media_url || null;
  const mediaType = body.media_type || null;
  if (!content && !mediaUrl) return json({ error: "content or media_url is required" }, 400, cors);
  const loc = getLocation(request);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.DB.prepare(
    `INSERT INTO group_messages (id,group_id,sender_id,content,media_url,media_type,continent,region,country,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(id, groupId, user.id, content, mediaUrl, mediaType, loc.continent, loc.region, loc.country, createdAt).run();
  return json({ id, group_id: groupId, sender_id: user.id, content, media_url: mediaUrl, media_type: mediaType, created_at: createdAt }, 200, cors);
}

async function listGroupMessages(groupId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const group = await env.DB.prepare(`SELECT * FROM groups WHERE id=?`).bind(groupId).first();
  if (!group) return json({ error: "Group not found" }, 404, cors);
  if (group.visibility === "private") {
    const member = await getGroupMembership(env.DB, groupId, user.id);
    if (!member) return json({ error: "This group is private" }, 403, cors);
  }
  const { results } = await env.DB.prepare(`SELECT * FROM group_messages WHERE group_id=? ORDER BY created_at ASC LIMIT 100`).bind(groupId).all();
  return json({ messages: results, group }, 200, cors);
}

async function createPage(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const body = await request.json();
  const name = (body.name || "").trim();
  const description = (body.description || "").trim();
  const visibility = body.visibility === "private" ? "private" : "public";
  if (!name) return json({ error: "name is required" }, 400, cors);
  const loc = getLocation(request);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.DB.prepare(
    `INSERT INTO pages (id,owner_id,name,description,visibility,profile_picture_url,continent,region,country,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(id, user.id, name, description, visibility, null, loc.continent, loc.region, loc.country, createdAt).run();
  return json({ id, name, description, visibility, owner_id: user.id }, 200, cors);
}

async function listPages(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const url = new URL(request.url);
  const continent = url.searchParams.get("continent");
  const stmt = continent
    ? env.DB.prepare(`SELECT id,name,description,visibility,owner_id,continent,region,country FROM pages WHERE visibility='public' AND continent=? ORDER BY created_at DESC LIMIT 50`).bind(continent)
    : env.DB.prepare(`SELECT id,name,description,visibility,owner_id,continent,region,country FROM pages WHERE visibility='public' ORDER BY created_at DESC LIMIT 50`);
  const { results } = await stmt.all();
  return json({ pages: results }, 200, cors);
}

async function listMyPages(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const { results: owned } = await env.DB.prepare(`SELECT *, 'owner' as my_role FROM pages WHERE owner_id=?`).bind(user.id).all();
  const { results: followed } = await env.DB.prepare(
    `SELECT p.*, 'follower' as my_role FROM pages p JOIN page_followers f ON f.page_id=p.id WHERE f.user_id=?`
  ).bind(user.id).all();
  return json({ pages: [...owned, ...followed] }, 200, cors);
}

async function isFollower(db, pageId, userId) { return await db.prepare(`SELECT * FROM page_followers WHERE page_id=? AND user_id=?`).bind(pageId, userId).first(); }

async function getPage(pageId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const page = await env.DB.prepare(`SELECT * FROM pages WHERE id=?`).bind(pageId).first();
  if (!page) return json({ error: "Page not found" }, 404, cors);
  if (page.visibility === "private" && page.owner_id !== user.id) {
    const follower = await isFollower(env.DB, pageId, user.id);
    if (!follower) return json({ error: "This page is private" }, 403, cors);
  }
  return json(page, 200, cors);
}

async function followPage(pageId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const page = await env.DB.prepare(`SELECT * FROM pages WHERE id=?`).bind(pageId).first();
  if (!page) return json({ error: "Page not found" }, 404, cors);
  if (page.visibility === "private" && page.owner_id !== user.id) return json({ error: "This page is private — only the owner can add followers directly" }, 403, cors);
  const existing = await isFollower(env.DB, pageId, user.id);
  if (existing) return json({ ok: true, already_following: true }, 200, cors);
  await env.DB.prepare(`INSERT INTO page_followers (page_id,user_id,followed_at) VALUES (?,?,?)`).bind(pageId, user.id, Date.now()).run();
  return json({ ok: true }, 200, cors);
}

async function postPagePost(pageId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const page = await env.DB.prepare(`SELECT * FROM pages WHERE id=?`).bind(pageId).first();
  if (!page) return json({ error: "Page not found" }, 404, cors);
  if (page.owner_id !== user.id) return json({ error: "Only the page owner can post" }, 403, cors);
  const body = await request.json();
  const content = (body.content || "").toString();
  const mediaUrl = body.media_url || null;
  const mediaType = body.media_type || null;
  if (!content && !mediaUrl) return json({ error: "content or media_url is required" }, 400, cors);
  const loc = getLocation(request);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.DB.prepare(
    `INSERT INTO page_posts (id,page_id,author_id,content,media_url,media_type,continent,region,country,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(id, pageId, user.id, content, mediaUrl, mediaType, loc.continent, loc.region, loc.country, createdAt).run();
  return json({ id, page_id: pageId, author_id: user.id, content, media_url: mediaUrl, media_type: mediaType, created_at: createdAt }, 200, cors);
}

async function listPagePosts(pageId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const page = await env.DB.prepare(`SELECT * FROM pages WHERE id=?`).bind(pageId).first();
  if (!page) return json({ error: "Page not found" }, 404, cors);
  if (page.visibility === "private" && page.owner_id !== user.id) {
    const follower = await isFollower(env.DB, pageId, user.id);
    if (!follower) return json({ error: "This page is private" }, 403, cors);
  }
  const { results } = await env.DB.prepare(`SELECT * FROM page_posts WHERE page_id=? ORDER BY created_at DESC LIMIT 50`).bind(pageId).all();
  return json({ posts: results, page }, 200, cors);
}

async function startChat(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const body = await request.json();
  const otherUserId = body.user_id;
  if (!otherUserId || otherUserId === user.id) return json({ error: "A valid other user_id is required" }, 400, cors);
  const [userA, userB] = [user.id, otherUserId].sort();
  let chat = await env.DB.prepare(`SELECT * FROM chats WHERE user_a=? AND user_b=?`).bind(userA, userB).first();
  if (!chat) {
    const id = crypto.randomUUID();
    const createdAt = Date.now();
    await env.DB.prepare(`INSERT INTO chats (id,user_a,user_b,created_at) VALUES (?,?,?,?)`).bind(id, userA, userB, createdAt).run();
    chat = { id, user_a: userA, user_b: userB, created_at: createdAt };
  }
  return json(chat, 200, cors);
}

async function listChats(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const { results } = await env.DB.prepare(
    `SELECT c.*,
      (SELECT content FROM chat_messages m WHERE m.chat_id=c.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM chat_messages m WHERE m.chat_id=c.id ORDER BY m.created_at DESC LIMIT 1) as last_message_at
     FROM chats c WHERE c.user_a=? OR c.user_b=? ORDER BY last_message_at DESC`
  ).bind(user.id, user.id).all();
  const enriched = await Promise.all(results.map(async (chat) => {
    const otherId = chat.user_a === user.id ? chat.user_b : chat.user_a;
    const other = await env.DB.prepare(`SELECT id, display_name, profile_picture_url FROM users WHERE id=?`).bind(otherId).first();
    return { ...chat, other_user: other };
  }));
  return json({ chats: enriched }, 200, cors);
}

async function assertChatParticipant(db, chatId, userId) {
  const chat = await db.prepare(`SELECT * FROM chats WHERE id=?`).bind(chatId).first();
  if (!chat) return null;
  if (chat.user_a !== userId && chat.user_b !== userId) return null;
  return chat;
}

async function postChatMessage(chatId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const chat = await assertChatParticipant(env.DB, chatId, user.id);
  if (!chat) return json({ error: "Chat not found or you're not a participant" }, 403, cors);
  const body = await request.json();
  const content = (body.content || "").toString();
  const mediaUrl = body.media_url || null;
  const mediaType = body.media_type || null;
  if (!content && !mediaUrl) return json({ error: "content or media_url is required" }, 400, cors);
  const loc = getLocation(request);
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  await env.DB.prepare(
    `INSERT INTO chat_messages (id,chat_id,sender_id,content,media_url,media_type,continent,region,country,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(id, chatId, user.id, content, mediaUrl, mediaType, loc.continent, loc.region, loc.country, createdAt).run();
  return json({ id, chat_id: chatId, sender_id: user.id, content, media_url: mediaUrl, media_type: mediaType, created_at: createdAt }, 200, cors);
}

async function listChatMessages(chatId, request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const chat = await assertChatParticipant(env.DB, chatId, user.id);
  if (!chat) return json({ error: "Chat not found or you're not a participant" }, 403, cors);
  const otherId = chat.user_a === user.id ? chat.user_b : chat.user_a;
  const other = await env.DB.prepare(`SELECT id, display_name, profile_picture_url FROM users WHERE id=?`).bind(otherId).first();
  const { results } = await env.DB.prepare(`SELECT * FROM chat_messages WHERE chat_id=? ORDER BY created_at ASC LIMIT 100`).bind(chatId).all();
  return json({ messages: results, other_user: other }, 200, cors);
}

async function handleUpdateMe(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  const body = await request.json();
  const displayName = body.display_name !== undefined ? body.display_name.trim() : user.display_name;
  const bio = body.bio !== undefined ? body.bio.toString() : user.bio;
  const profilePictureUrl = body.profile_picture_url !== undefined ? body.profile_picture_url : user.profile_picture_url;

  if (!displayName) return json({ error: "display_name cannot be empty" }, 400, cors);

  await env.DB.prepare(
    `UPDATE users SET display_name = ?, bio = ?, profile_picture_url = ? WHERE id = ?`
  ).bind(displayName, bio, profilePictureUrl, user.id).run();

  return json({ id: user.id, email: user.email, display_name: displayName, bio, profile_picture_url: profilePictureUrl }, 200, cors);
}

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });
}

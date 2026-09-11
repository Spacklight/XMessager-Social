/**
 * XMessager Social Controller — Cloudflare Worker
 * Handles: users/auth, groups, pages, private chats (text lives in D1,
 * media attachments live on Hugging Face — added in later steps).
 *
 * Bindings expected:
 *   env.DB            - D1 database (binding "DB")
 *   env.HF_TOKEN       - Hugging Face access token, secret (added later)
 *   env.HF_MEDIA_REPO  - e.g. "Spacklight/Social-Media"
 */

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// African region lookup (from the platform's geo spec). Other continents
// default to null for now and can be extended the same way later.
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

function getRegion(continent, country) {
  if (continent === "AF" && country && AFRICA_REGIONS[country]) return AFRICA_REGIONS[country];
  return null;
}

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

    try {
      if (url.pathname === "/api/auth/signup" && request.method === "POST") return await handleSignup(request, env, cors);
      if (url.pathname === "/api/auth/login" && request.method === "POST") return await handleLogin(request, env, cors);
      if (url.pathname === "/api/me" && request.method === "GET") return await handleMe(request, env, cors);

      return json({ error: "Not found" }, 404, cors);
    } catch (err) {
      return json({ error: err.message || "Internal error" }, 500, cors);
    }
  },
};

// ---------- password hashing (PBKDF2 via Web Crypto) ----------

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------- auth handlers ----------

async function handleSignup(request, env, cors) {
  const body = await request.json();
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  const displayName = (body.display_name || "").trim();

  if (!email || !password || !displayName) return json({ error: "email, password, and display_name are required" }, 400, cors);
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
  return json({ token, user: { id, email, display_name: displayName, continent: loc.continent, region: loc.region, country: loc.country } }, 200, cors);
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
  return json({
    token,
    user: { id: user.id, email: user.email, display_name: user.display_name, bio: user.bio, profile_picture_url: user.profile_picture_url },
  }, 200, cors);
}

async function handleMe(request, env, cors) {
  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, cors);
  return json({
    id: user.id, email: user.email, display_name: user.display_name, bio: user.bio,
    profile_picture_url: user.profile_picture_url, continent: user.continent, region: user.region, country: user.country,
  }, 200, cors);
}

async function createSession(env, userId) {
  const token = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)`)
    .bind(token, userId, now, now + SESSION_TTL_MS).run();
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

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });
}

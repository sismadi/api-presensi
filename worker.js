// ============================================================
// worker.js — api-presensi (Cloudflare Worker + D1)
// Presensi wajah dengan template biometrik terenkripsi.
// Pola & helper keamanan diambil dari api-lms (sesi HMAC, PBKDF2,
// captcha, rate limit D1, CORS allowlist, /public vs /api).
// ============================================================
// Alur biometrik:
//   1. ENROLL  (/api?view=face-enroll): klien mengirim 3-8 vektor 128-D
//      (hasil face-api.js) + persetujuan eksplisit + password. Server
//      memeriksa konsistensi antar-sampel, menyimpan maks. 5 vektor
//      TERENKRIPSI AES-256-GCM (kunci = secret TEMPLATE_KEY).
//   2. PRESENSI (attend-challenge -> attend): verifikasi 1:1 terhadap
//      template milik akun yang sedang login. Jarak Euclidean median
//      <= MATCH_THRESHOLD => hadir/terlambat.
//   Gambar wajah tidak pernah menyentuh server. Template tidak pernah
//   dikembalikan ke klien oleh endpoint mana pun.
// Secret/variable (lihat README.md):
//   wrangler secret put SESSION_SECRET   (32+ karakter acak)
//   wrangler secret put TEMPLATE_KEY     (base64url dari 32 byte acak)
// ============================================================

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 100_000;       // batas WebCrypto Workers
const CAPTCHA_TTL_MS = 5 * 60 * 1000;
const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const CHALLENGE_MIN_MS = 1500;           // respons secepat itu = skrip, bukan manusia

const USERNAME_RE = /^[a-z0-9._-]{3,40}$/;
const CODE_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ROLES = new Set(['mahasiswa', 'dosen', 'admin']);
const MANUAL_STATUS = new Set(['hadir', 'terlambat', 'izin', 'sakit', 'alpa']);
const LIVENESS_KINDS = ['blink', 'turn_left', 'turn_right'];

const DIM = 128;                         // dimensi descriptor face-api.js
const MODEL_ID = 'faceapi-128';
const ENROLL_MIN = 3, ENROLL_MAX = 8, STORE_MAX = 5;
const ATTEND_MIN = 2, ATTEND_MAX = 5;
const ENROLL_MAX_PAIR_DIST = 0.5;        // sampel enroll harus orang yang sama
const DEFAULT_MATCH_THRESHOLD = 0.5;     // riset memakai <=0.60; 0.50 lebih ketat utk presensi
const KEY_ID = 'k1';

const DEFAULT_ORIGINS = [
  'https://presensi.piawai.id',
  'http://localhost:8080',
  'http://127.0.0.1:8080',
];

function genId(prefix) {
  return prefix + '_' + Date.now().toString(36) + crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extraHeaders,
    },
  });
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0].trim()
    || 'unknown';
}

function corsHeaders(request, env) {
  const allowed = String(env.ALLOWED_ORIGINS || DEFAULT_ORIGINS.join(','))
    .split(',').map(s => s.trim()).filter(Boolean);
  const origin = request.headers.get('Origin') || '';
  const h = {
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
  if (origin && allowed.includes(origin)) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

// ------------------------------------------------------------
// Util dasar (base64url, perbandingan waktu-konstan)
// ------------------------------------------------------------
const enc = new TextEncoder();

function b64urlEncode(bytes) {
  let s = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ------------------------------------------------------------
// [KRITIS] Hashing password — PBKDF2-SHA256 lewat Web Crypto.
// ------------------------------------------------------------
async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$sha256$${PBKDF2_ITERATIONS}$${b64urlEncode(salt)}$${b64urlEncode(hash)}`;
}
async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 5 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[2], 10);
  if (!Number.isFinite(iterations) || iterations < 1000 || iterations > 100_000) return false;
  const salt = b64urlDecode(parts[3]);
  const expected = b64urlDecode(parts[4]);
  const actual = await pbkdf2(password, salt, iterations);
  return timingSafeEqual(actual, expected);
}

// ------------------------------------------------------------
// [KRITIS] Token bertanda tangan server — HMAC-SHA256, generik.
// `typ` mencegah satu jenis token dipakai ulang sebagai jenis lain.
// ------------------------------------------------------------
async function hmacKey(env) {
  const secret = env.SESSION_SECRET || '';
  if (secret.length < 16) throw new HttpError(500, 'Server belum dikonfigurasi (SESSION_SECRET).');
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signToken(env, typ, payload, ttlMs) {
  const key = await hmacKey(env);
  const full = { ...payload, typ, iat: Date.now(), exp: Date.now() + ttlMs };
  const data = b64urlEncode(enc.encode(JSON.stringify(full)));
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return { token: `${data}.${b64urlEncode(sig)}`, payload: full };
}
async function verifyToken(env, typ, token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  let key;
  try { key = await hmacKey(env); } catch (e) { return null; }
  const valid = await crypto.subtle.verify('HMAC', key, b64urlDecode(sig), enc.encode(data)).catch(() => false);
  if (!valid) return null;
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(b64urlDecode(data))); } catch (e) { return null; }
  if (!payload?.exp || Date.now() > payload.exp) return null;
  if (payload.typ !== typ) return null;
  return payload;
}
async function signSession(env, payload) { return signToken(env, 'session', payload, SESSION_TTL_MS); }
async function verifySession(env, token) { return verifyToken(env, 'session', token); }

/** Ambil sesi dari header Authorization; lempar 401 kalau tidak sah. */
async function requireSession(request, env) {
  const raw = request.headers.get('Authorization') || '';
  const token = raw.startsWith('Bearer ') ? raw.slice(7).trim() : '';
  const session = await verifySession(env, token);
  if (!session) throw new HttpError(401, 'Sesi tidak valid atau sudah berakhir. Silakan masuk kembali.');
  return session;
}
function requireRole(session, ...roles) {
  if (!roles.includes(session.role)) throw new HttpError(403, 'Anda tidak berhak mengakses fitur ini.');
}

// ------------------------------------------------------------
// [TINGGI] Captcha matematika, diverifikasi di server (lihat api-lms
// untuk penjelasan trade-off lengkap: bukan pertahanan anti-bot
// canggih, cukup untuk menyaring spam form otomatis generik).
// ------------------------------------------------------------
async function generateMathCaptcha(env) {
  const a = 1 + Math.floor(Math.random() * 9);
  const b = 1 + Math.floor(Math.random() * 9);
  const { token } = await signToken(env, 'captcha', { a, b }, CAPTCHA_TTL_MS);
  return { challenge: `${a} + ${b} = ?`, token };
}
async function verifyMathCaptcha(env, db, token, answer, ip) {
  const key = `captcha:ip:${ip}`;
  await rateLimitCheck(db, key, { max: 10, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
  const payload = await verifyToken(env, 'captcha', token);
  const given = Number(answer);
  const correct = payload && Number.isFinite(given) && (payload.a + payload.b) === given;
  if (!correct) {
    await rateLimitHit(db, key);
    throw new HttpError(400, 'Jawaban captcha salah atau soal sudah kedaluwarsa. Muat ulang soal dan coba lagi.');
  }
}

// ------------------------------------------------------------
// [TINGGI] Rate limiting nyata di D1.
// ------------------------------------------------------------
async function rateLimitCheck(db, key, { max, windowMs, blockMs }) {
  const now = Date.now();
  const row = await db.prepare(`SELECT * FROM rate_limit WHERE key = ?`).bind(key).first();
  if (row && row.blockedUntil > now) {
    throw new HttpError(429, `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil((row.blockedUntil - now) / 1000)} detik.`);
  }
  if (!row || (now - row.windowStart) > windowMs) {
    await db.prepare(
      `INSERT INTO rate_limit (key, count, windowStart, blockedUntil) VALUES (?, 0, ?, 0)
       ON CONFLICT(key) DO UPDATE SET count = 0, windowStart = ?, blockedUntil = 0`
    ).bind(key, now, now).run();
    return;
  }
  if (row.count >= max) {
    const until = now + blockMs;
    await db.prepare(`UPDATE rate_limit SET blockedUntil = ?, count = 0, windowStart = ? WHERE key = ?`)
      .bind(until, now, key).run();
    throw new HttpError(429, `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil(blockMs / 1000)} detik.`);
  }
}
async function rateLimitHit(db, key) {
  const now = Date.now();
  await db.prepare(
    `INSERT INTO rate_limit (key, count, windowStart, blockedUntil) VALUES (?, 1, ?, 0)
     ON CONFLICT(key) DO UPDATE SET count = count + 1`
  ).bind(key, now).run();
}
async function rateLimitReset(db, key) {
  await db.prepare(`DELETE FROM rate_limit WHERE key = ?`).bind(key).run().catch(() => {});
}

// ------------------------------------------------------------
// Util teks & DB
// ------------------------------------------------------------
function plainText(value, max) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
}
async function insertRow(db, table, record) {
  const cols = Object.keys(record);
  await db.prepare(`INSERT INTO ${table} (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`)
    .bind(...cols.map(c => record[c])).run();
  return record;
}
async function updateRow(db, table, id, patch) {
  const cols = Object.keys(patch);
  if (!cols.length) return;
  await db.prepare(`UPDATE ${table} SET ${cols.map(c => `${c} = ?`).join(', ')} WHERE id = ?`)
    .bind(...cols.map(c => patch[c]), id).run();
}
async function audit(db, actor, action, target, detail) {
  await db.prepare(`INSERT INTO auditLog (id, at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(genId('au'), Date.now(), actor, action, target ?? null, detail ? String(detail).slice(0, 300) : null)
    .run().catch(() => {});
}
function sessionUserView(p) { return { username: p.username, name: p.name, role: p.role }; }

// ------------------------------------------------------------
// [KRITIS] Template biometrik: validasi vektor, enkripsi, jarak.
// ------------------------------------------------------------
/** Validasi 1 vektor dari klien -> Float32Array(128). Menolak NaN/Inf, nilai
 *  ekstrem, dan vektor nol (descriptor face-api.js berkisar sekitar [-0.5, 0.5]). */
function parseVector(raw) {
  if (!Array.isArray(raw) || raw.length !== DIM) throw new HttpError(400, `Setiap sampel harus berisi ${DIM} angka.`);
  const v = new Float32Array(DIM);
  let norm = 0;
  for (let i = 0; i < DIM; i++) {
    const x = raw[i];
    if (typeof x !== 'number' || !Number.isFinite(x) || Math.abs(x) > 3) throw new HttpError(400, 'Sampel wajah tidak valid.');
    v[i] = x; norm += x * x;
  }
  if (Math.sqrt(norm) < 0.1) throw new HttpError(400, 'Sampel wajah tidak valid.');
  return v;
}
function parseSamples(raw, min, max) {
  if (!Array.isArray(raw) || raw.length < min || raw.length > max) {
    throw new HttpError(400, `Kirim ${min}-${max} sampel wajah.`);
  }
  return raw.map(parseVector);
}
function euclid(a, b) {
  let s = 0;
  for (let i = 0; i < DIM; i++) { const d = a[i] - b[i]; s += d * d; }
  return Math.sqrt(s);
}
function median(arr) {
  const s = [...arr].sort((x, y) => x - y);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
/** Ambil sampel yang tersebar merata bila lebih dari `max`. */
function spread(list, max) {
  if (list.length <= max) return list;
  return Array.from({ length: max }, (_, i) => list[Math.round(i * (list.length - 1) / (max - 1))]);
}

async function templateKey(env) {
  let raw;
  try { raw = b64urlDecode(String(env.TEMPLATE_KEY || '')); } catch (e) { raw = new Uint8Array(0); }
  if (raw.length !== 32) throw new HttpError(500, 'Server belum dikonfigurasi (TEMPLATE_KEY).');
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
/** AAD = userId: template yang disalin ke baris akun lain tidak akan bisa didekripsi. */
async function sealTemplate(env, userId, vectors) {
  const buf = new Float32Array(vectors.length * DIM);
  vectors.forEach((v, i) => buf.set(v, i * DIM));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(userId) }, await templateKey(env), buf.buffer);
  return { ciphertext: b64urlEncode(ct), iv: b64urlEncode(iv) };
}
async function openTemplate(env, userId, row) {
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64urlDecode(row.iv), additionalData: enc.encode(userId) },
      await templateKey(env), b64urlDecode(row.ciphertext));
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(500, 'Template wajah tidak dapat dibuka. Hubungi admin untuk pendaftaran ulang.');
  }
  const all = new Float32Array(plain.slice(0));
  const out = [];
  for (let i = 0; i + DIM <= all.length; i += DIM) out.push(all.subarray(i, i + DIM));
  return out;
}
function matchThreshold(env) {
  const t = Number(env.MATCH_THRESHOLD);
  return Number.isFinite(t) && t > 0.2 && t < 0.8 ? t : DEFAULT_MATCH_THRESHOLD;
}

// ============================================================
// /public — captcha, login, registrasi (peran SELALU 'mahasiswa')
// ============================================================
async function handlePublic(request, env) {
  const url = new URL(request.url);
  const view = url.searchParams.get('view');
  const db = env.DB;

  if (view === 'health') return json({ ok: true, model: MODEL_ID, dim: DIM });
  if (view === 'captcha') return json(await generateMathCaptcha(env));

  if (view === 'login' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    const ip = clientIp(request);

    await rateLimitCheck(db, `login:ip:${ip}`, { max: 20, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
    await rateLimitCheck(db, `login:acc:${username}`, { max: 5, windowMs: 15 * 60_000, blockMs: 15 * 60_000 });
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);
    if (!username || !password) throw new HttpError(400, 'Username dan password wajib diisi.');

    const user = await db.prepare(`SELECT * FROM users WHERE username = ?`).bind(username).first();
    const ok = await verifyPassword(password, user?.passwordHash || `pbkdf2$sha256$${PBKDF2_ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`);
    if (!user || !ok) {
      await rateLimitHit(db, `login:ip:${ip}`);
      await rateLimitHit(db, `login:acc:${username}`);
      throw new HttpError(401, 'Username atau password salah.');
    }
    await rateLimitReset(db, `login:acc:${username}`);
    const { token, payload } = await signSession(env, { uid: user.id, username: user.username, name: user.name, role: user.role });
    return json({ token, expiresAt: payload.exp, user: sessionUserView(payload) });
  }

  if (view === 'register' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const ip = clientIp(request);
    await rateLimitCheck(db, `register:ip:${ip}`, { max: 5, windowMs: 60 * 60_000, blockMs: 60 * 60_000 });
    await verifyMathCaptcha(env, db, body.captchaToken, body.captchaAnswer, ip);
    await rateLimitHit(db, `register:ip:${ip}`);

    const username = String(body.username || '').trim().toLowerCase();
    const name = plainText(body.name, 80);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const idNumber = plainText(body.idNumber, 30) || null;
    if (!username || !name || !email || !password) throw new HttpError(400, 'Semua field wajib diisi.');
    if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Username 3-40 karakter: huruf kecil, angka, titik, garis bawah, atau strip.');
    if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Format email tidak valid.');
    if (password.length < 8) throw new HttpError(400, 'Password minimal 8 karakter.');
    const existing = await db.prepare(`SELECT id FROM users WHERE username = ? OR email = ?`).bind(username, email).first();
    if (existing) throw new HttpError(409, 'Username atau email sudah dipakai.');

    const record = { id: genId('usr'), username, passwordHash: await hashPassword(password), name, role: 'mahasiswa', email, idNumber };
    await insertRow(db, 'users', record);
    const { token, payload } = await signSession(env, { uid: record.id, username, name, role: 'mahasiswa' });
    return json({ token, expiresAt: payload.exp, user: sessionUserView(payload) }, 201);
  }

  throw new HttpError(400, 'Permintaan tidak dikenal.');
}

// ============================================================
// /api — wajib sesi
// ============================================================
async function requireOwnedClass(db, classId, session) {
  const cls = await db.prepare(`SELECT * FROM classes WHERE id = ? AND deleted = 0`).bind(classId).first();
  if (!cls) throw new HttpError(404, 'Kelas tidak ditemukan.');
  if (session.role !== 'admin' && cls.instructorUsername !== session.username) {
    throw new HttpError(403, 'Ini bukan kelas Anda.');
  }
  return cls;
}
async function requireOwnedMeeting(db, meetingId, session) {
  const m = await db.prepare(`SELECT * FROM meetings WHERE id = ?`).bind(meetingId).first();
  if (!m) throw new HttpError(404, 'Pertemuan tidak ditemukan.');
  const cls = await requireOwnedClass(db, m.classId, session);
  return { meeting: m, cls };
}
const isOpen = (m, now = Date.now()) => m.status === 'open' && now >= m.startsAt && now <= m.endsAt;
const meetingView = m => ({
  id: m.id, classId: m.classId, title: m.title, startsAt: m.startsAt, endsAt: m.endsAt,
  lateAfterMin: m.lateAfterMin, status: m.status, open: isOpen(m),
});

async function handleApi(request, env) {
  const url = new URL(request.url);
  const view = url.searchParams.get('view');
  const method = request.method;
  const db = env.DB;
  const session = await requireSession(request, env);
  const readBody = () => request.json().catch(() => ({}));

  // ---------- Akun sendiri ----------
  if (view === 'me' && method === 'GET') {
    const u = await db.prepare(`SELECT id, username, name, role, email, idNumber FROM users WHERE id = ?`).bind(session.uid).first();
    if (!u) throw new HttpError(401, 'Akun tidak ditemukan.');
    return json({ user: u });
  }
  if (view === 'profile' && method === 'PATCH') {
    const body = await readBody();
    const patch = {};
    if (body.name !== undefined) { patch.name = plainText(body.name, 80); if (!patch.name) throw new HttpError(400, 'Nama wajib diisi.'); }
    if (body.email !== undefined) {
      const email = String(body.email).trim().toLowerCase();
      if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Format email tidak valid.');
      const dup = await db.prepare(`SELECT id FROM users WHERE email = ? AND id != ?`).bind(email, session.uid).first();
      if (dup) throw new HttpError(409, 'Email sudah dipakai.');
      patch.email = email;
    }
    if (body.idNumber !== undefined) patch.idNumber = plainText(body.idNumber, 30) || null;
    await updateRow(db, 'users', session.uid, patch);
    return json({ ok: true });
  }

  // ---------- Biometrik: status / enroll / hapus ----------
  if (view === 'face-status' && method === 'GET') {
    const t = await db.prepare(`SELECT sampleCount, model, consentAt, createdAt, updatedAt FROM faceTemplates WHERE userId = ?`).bind(session.uid).first();
    return json({ enrolled: !!t, template: t || null, threshold: matchThreshold(env) });
  }

  if (view === 'face-enroll' && method === 'POST') {
    const body = await readBody();
    if (body.consent !== true) {
      throw new HttpError(400, 'Persetujuan eksplisit pemrosesan data biometrik wajib diberikan.');
    }
    await rateLimitCheck(db, `enroll:${session.uid}`, { max: 10, windowMs: 60 * 60_000, blockMs: 30 * 60_000 });
    await rateLimitHit(db, `enroll:${session.uid}`);

    // Konfirmasi password: sesi curian tidak cukup untuk menimpa template.
    const user = await db.prepare(`SELECT passwordHash FROM users WHERE id = ?`).bind(session.uid).first();
    if (!user || !(await verifyPassword(String(body.password || ''), user.passwordHash))) {
      throw new HttpError(401, 'Password salah. Pendaftaran wajah membutuhkan konfirmasi password.');
    }

    const samples = parseSamples(body.samples, ENROLL_MIN, ENROLL_MAX);
    for (let i = 0; i < samples.length; i++) for (let j = i + 1; j < samples.length; j++) {
      if (euclid(samples[i], samples[j]) > ENROLL_MAX_PAIR_DIST) {
        throw new HttpError(422, 'Sampel wajah tidak konsisten (mungkin lebih dari satu orang atau gambar kurang jelas). Ulangi pendaftaran.');
      }
    }
    const keep = spread(samples, STORE_MAX);
    const { ciphertext, iv } = await sealTemplate(env, session.uid, keep);
    const now = Date.now();
    const existing = await db.prepare(`SELECT createdAt FROM faceTemplates WHERE userId = ?`).bind(session.uid).first();
    await db.prepare(
      `INSERT INTO faceTemplates (userId, ciphertext, iv, kid, sampleCount, dim, model, consentAt, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(userId) DO UPDATE SET ciphertext = excluded.ciphertext, iv = excluded.iv, kid = excluded.kid,
         sampleCount = excluded.sampleCount, dim = excluded.dim, model = excluded.model,
         consentAt = excluded.consentAt, updatedAt = excluded.updatedAt`
    ).bind(session.uid, ciphertext, iv, KEY_ID, keep.length, DIM, MODEL_ID, now, existing?.createdAt || now, now).run();
    await audit(db, session.username, existing ? 'face_reenroll' : 'face_enroll', session.username, `samples=${keep.length}`);
    return json({ ok: true, sampleCount: keep.length }, existing ? 200 : 201);
  }

  if (view === 'face-delete' && method === 'DELETE') {
    await db.prepare(`DELETE FROM faceTemplates WHERE userId = ?`).bind(session.uid).run();
    await audit(db, session.username, 'face_delete', session.username, 'self (penarikan persetujuan)');
    return json({ ok: true });
  }

  // ---------- Kelas ----------
  if (view === 'classes' && method === 'GET') {
    let sql, binds = [];
    if (session.role === 'admin') sql = `SELECT c.* FROM classes c WHERE c.deleted = 0`;
    else if (session.role === 'dosen') { sql = `SELECT c.* FROM classes c WHERE c.deleted = 0 AND c.instructorUsername = ?`; binds = [session.username]; }
    else { sql = `SELECT c.* FROM classes c JOIN classMembers m ON m.classId = c.id WHERE c.deleted = 0 AND m.username = ?`; binds = [session.username]; }
    const { results } = await db.prepare(sql + ' ORDER BY c.createdAt DESC').bind(...binds).all();
    return json({ classes: results.map(c => ({ id: c.id, code: c.code, name: c.name, instructorUsername: c.instructorUsername })) });
  }
  if (view === 'class-create' && method === 'POST') {
    requireRole(session, 'dosen', 'admin');
    const body = await readBody();
    const code = String(body.code || '').trim().toLowerCase();
    const name = plainText(body.name, 120);
    if (!CODE_RE.test(code)) throw new HttpError(400, 'Kode kelas 2-40 karakter: huruf kecil, angka, strip.');
    if (!name) throw new HttpError(400, 'Nama kelas wajib diisi.');
    if (await db.prepare(`SELECT id FROM classes WHERE code = ?`).bind(code).first()) throw new HttpError(409, 'Kode kelas sudah dipakai.');
    const rec = { id: genId('cls'), code, name, instructorUsername: session.username, createdAt: Date.now() };
    await insertRow(db, 'classes', rec);
    return json({ id: rec.id, code, name }, 201);
  }
  if (view === 'class-members') {
    requireRole(session, 'dosen', 'admin');
    const classId = url.searchParams.get('classId') || '';
    await requireOwnedClass(db, classId, session);
    if (method === 'GET') {
      const { results } = await db.prepare(
        `SELECT u.username, u.name, u.idNumber, (t.userId IS NOT NULL) AS enrolled
           FROM classMembers m JOIN users u ON u.username = m.username
           LEFT JOIN faceTemplates t ON t.userId = u.id
          WHERE m.classId = ? ORDER BY u.name`).bind(classId).all();
      return json({ members: results.map(r => ({ ...r, enrolled: !!r.enrolled })) });
    }
    if (method === 'POST') {
      const body = await readBody();
      const names = [...new Set((Array.isArray(body.usernames) ? body.usernames : []).map(s => String(s).trim().toLowerCase()).filter(Boolean))].slice(0, 200);
      if (!names.length) throw new HttpError(400, 'Daftar username kosong.');
      const added = [], notFound = [];
      for (const n of names) {
        const u = await db.prepare(`SELECT username FROM users WHERE username = ? AND role = 'mahasiswa'`).bind(n).first();
        if (!u) { notFound.push(n); continue; }
        await db.prepare(`INSERT OR IGNORE INTO classMembers (classId, username) VALUES (?, ?)`).bind(classId, n).run();
        added.push(n);
      }
      return json({ added, notFound });
    }
    if (method === 'DELETE') {
      const username = String(url.searchParams.get('username') || '').toLowerCase();
      await db.prepare(`DELETE FROM classMembers WHERE classId = ? AND username = ?`).bind(classId, username).run();
      return json({ ok: true });
    }
  }

  // ---------- Pertemuan ----------
  if (view === 'meetings' && method === 'GET') {
    const classId = url.searchParams.get('classId') || '';
    if (session.role === 'mahasiswa') {
      const mem = await db.prepare(`SELECT 1 FROM classMembers WHERE classId = ? AND username = ?`).bind(classId, session.username).first();
      if (!mem) throw new HttpError(403, 'Anda bukan anggota kelas ini.');
    } else await requireOwnedClass(db, classId, session);
    const { results } = await db.prepare(
      `SELECT m.*, a.status AS myStatus FROM meetings m
         LEFT JOIN attendance a ON a.meetingId = m.id AND a.username = ?
        WHERE m.classId = ? ORDER BY m.startsAt DESC LIMIT 100`).bind(session.username, classId).all();
    return json({ meetings: results.map(m => ({ ...meetingView(m), myStatus: m.myStatus || null })) });
  }
  if (view === 'meeting-open' && method === 'POST') {
    requireRole(session, 'dosen', 'admin');
    const body = await readBody();
    await requireOwnedClass(db, String(body.classId || ''), session);
    const title = plainText(body.title, 120);
    const dur = Math.round(Number(body.durationMin));
    const late = Math.round(Number(body.lateAfterMin ?? 15));
    if (!title) throw new HttpError(400, 'Judul pertemuan wajib diisi.');
    if (!(dur >= 5 && dur <= 600)) throw new HttpError(400, 'Durasi 5-600 menit.');
    if (!(late >= 0 && late <= dur)) throw new HttpError(400, 'Batas terlambat harus 0 sampai durasi.');
    const now = Date.now();
    const rec = { id: genId('mtg'), classId: body.classId, title, startsAt: now, endsAt: now + dur * 60_000,
      lateAfterMin: late, status: 'open', createdBy: session.username, createdAt: now };
    await insertRow(db, 'meetings', rec);
    return json(meetingView(rec), 201);
  }
  if (view === 'meeting-close' && method === 'PATCH') {
    requireRole(session, 'dosen', 'admin');
    const { meeting } = await requireOwnedMeeting(db, url.searchParams.get('id') || '', session);
    await updateRow(db, 'meetings', meeting.id, { status: 'closed', endsAt: Math.min(meeting.endsAt, Date.now()) });
    return json({ ok: true });
  }
  if (view === 'meeting-report' && method === 'GET') {
    requireRole(session, 'dosen', 'admin');
    const { meeting, cls } = await requireOwnedMeeting(db, url.searchParams.get('id') || '', session);
    const { results } = await db.prepare(
      `SELECT u.username, u.name, u.idNumber, a.status, a.method, a.distance, a.note, a.createdAt
         FROM classMembers m JOIN users u ON u.username = m.username
         LEFT JOIN attendance a ON a.meetingId = ? AND a.username = m.username
        WHERE m.classId = ? ORDER BY u.name`).bind(meeting.id, cls.id).all();
    return json({ meeting: meetingView(meeting), class: { code: cls.code, name: cls.name }, rows: results });
  }
  if (view === 'manual-mark' && method === 'POST') {
    requireRole(session, 'dosen', 'admin');
    const body = await readBody();
    const { meeting, cls } = await requireOwnedMeeting(db, String(body.meetingId || ''), session);
    const username = String(body.username || '').toLowerCase();
    const status = String(body.status || '');
    if (!MANUAL_STATUS.has(status)) throw new HttpError(400, 'Status tidak dikenal.');
    const note = plainText(body.note, 200);
    if (!note) throw new HttpError(400, 'Catatan alasan wajib diisi untuk override manual.');
    const mem = await db.prepare(`SELECT 1 FROM classMembers WHERE classId = ? AND username = ?`).bind(cls.id, username).first();
    if (!mem) throw new HttpError(404, 'Mahasiswa bukan anggota kelas ini.');
    await db.prepare(
      `INSERT INTO attendance (id, meetingId, username, status, method, distance, markedBy, note, createdAt)
       VALUES (?, ?, ?, ?, 'manual', NULL, ?, ?, ?)
       ON CONFLICT(meetingId, username) DO UPDATE SET status = excluded.status, method = 'manual',
         distance = NULL, markedBy = excluded.markedBy, note = excluded.note`
    ).bind(genId('att'), meeting.id, username, status, session.username, note, Date.now()).run();
    await audit(db, session.username, 'manual_mark', username, `${meeting.id}:${status}:${note}`);
    return json({ ok: true });
  }

  // ---------- Presensi wajah ----------
  if (view === 'attend-challenge' && method === 'POST') {
    const body = await readBody();
    const meeting = await loadAttendableMeeting(db, String(body.meetingId || ''), session);
    const t = await db.prepare(`SELECT 1 FROM faceTemplates WHERE userId = ?`).bind(session.uid).first();
    if (!t) throw new HttpError(409, 'Wajah Anda belum didaftarkan. Daftarkan wajah terlebih dahulu.');
    await rateLimitCheck(db, `chal:${session.uid}`, { max: 20, windowMs: 10 * 60_000, blockMs: 10 * 60_000 });
    await rateLimitHit(db, `chal:${session.uid}`);
    const now = Date.now();
    const kind = LIVENESS_KINDS[crypto.getRandomValues(new Uint8Array(1))[0] % LIVENESS_KINDS.length];
    const rec = { id: genId('ch'), userId: session.uid, meetingId: meeting.id, kind, createdAt: now, expiresAt: now + CHALLENGE_TTL_MS, used: 0 };
    await insertRow(db, 'challenges', rec);
    return json({ challengeId: rec.id, kind, expiresAt: rec.expiresAt });
  }

  if (view === 'attend' && method === 'POST') {
    const body = await readBody();
    const meeting = await loadAttendableMeeting(db, String(body.meetingId || ''), session);
    const key = `attend:${session.uid}`;
    await rateLimitCheck(db, key, { max: 6, windowMs: 10 * 60_000, blockMs: 10 * 60_000 });

    const samples = parseSamples(body.samples, ATTEND_MIN, ATTEND_MAX);
    if (body.livenessPassed !== true) throw new HttpError(400, 'Tantangan liveness belum diselesaikan.');

    // Tantangan: sekali pakai, milik akun ini, untuk pertemuan ini, belum kedaluwarsa.
    const now = Date.now();
    const ch = await db.prepare(`SELECT * FROM challenges WHERE id = ?`).bind(String(body.challengeId || '')).first();
    if (!ch || ch.userId !== session.uid || ch.meetingId !== meeting.id || ch.used || now > ch.expiresAt) {
      throw new HttpError(400, 'Tantangan tidak valid atau kedaluwarsa. Mulai ulang presensi.');
    }
    if (now - ch.createdAt < CHALLENGE_MIN_MS) throw new HttpError(400, 'Respons terlalu cepat. Mulai ulang presensi.');
    const claimed = await db.prepare(`UPDATE challenges SET used = 1 WHERE id = ? AND used = 0`).bind(ch.id).run();
    if (!claimed.meta?.changes) throw new HttpError(400, 'Tantangan sudah dipakai.');

    const row = await db.prepare(`SELECT * FROM faceTemplates WHERE userId = ?`).bind(session.uid).first();
    if (!row) throw new HttpError(409, 'Wajah Anda belum didaftarkan.');
    const stored = await openTemplate(env, session.uid, row);
    const dists = samples.map(s => Math.min(...stored.map(t => euclid(s, t))));
    const distance = median(dists);
    const threshold = matchThreshold(env);

    if (distance > threshold) {
      await rateLimitHit(db, key);
      await audit(db, session.username, 'attend_fail', meeting.id, `d=${distance.toFixed(3)}`);
      // Jarak sengaja TIDAK dikembalikan ke klien (mencegah hill-climbing terhadap template).
      throw new HttpError(403, 'Wajah tidak cocok dengan data terdaftar. Coba lagi dengan pencahayaan lebih baik.');
    }

    const late = now > meeting.startsAt + meeting.lateAfterMin * 60_000;
    const status = late ? 'terlambat' : 'hadir';
    try {
      await insertRow(db, 'attendance', {
        id: genId('att'), meetingId: meeting.id, username: session.username, status, method: 'face',
        distance: Number(distance.toFixed(4)), markedBy: null, note: null, createdAt: now,
      });
    } catch (e) {
      throw new HttpError(409, 'Anda sudah tercatat presensi pada pertemuan ini.');
    }
    await rateLimitReset(db, key);
    await audit(db, session.username, 'attend_ok', meeting.id, `d=${distance.toFixed(3)}`);
    return json({ ok: true, status, at: now });
  }

  if (view === 'my-attendance' && method === 'GET') {
    const { results } = await db.prepare(
      `SELECT a.status, a.method, a.createdAt, m.title, m.startsAt, c.code AS classCode, c.name AS className
         FROM attendance a JOIN meetings m ON m.id = a.meetingId JOIN classes c ON c.id = m.classId
        WHERE a.username = ? ORDER BY m.startsAt DESC LIMIT 200`).bind(session.username).all();
    return json({ attendance: results });
  }

  // ---------- Admin ----------
  if (view === 'admin-stats' && method === 'GET') {
    requireRole(session, 'admin');
    const one = async sql => (await db.prepare(sql).first()).n;
    const { results: users } = await db.prepare(
      `SELECT u.id, u.username, u.name, u.role, u.email, (t.userId IS NOT NULL) AS enrolled
         FROM users u LEFT JOIN faceTemplates t ON t.userId = u.id ORDER BY u.role, u.name`).all();
    return json({
      counts: {
        users: await one(`SELECT COUNT(*) n FROM users`), templates: await one(`SELECT COUNT(*) n FROM faceTemplates`),
        classes: await one(`SELECT COUNT(*) n FROM classes WHERE deleted = 0`), meetings: await one(`SELECT COUNT(*) n FROM meetings`),
        attendance: await one(`SELECT COUNT(*) n FROM attendance`),
      },
      users: users.map(u => ({ ...u, enrolled: !!u.enrolled })),
    });
  }
  if (view === 'admin-create-account' && method === 'POST') {
    requireRole(session, 'admin');
    const body = await readBody();
    const username = String(body.username || '').trim().toLowerCase();
    const name = plainText(body.name, 80);
    const role = String(body.role || '');
    const password = String(body.password || '');
    const email = body.email ? String(body.email).trim().toLowerCase() : null;
    if (!username || !name || !password || !ROLES.has(role)) throw new HttpError(400, 'Semua field wajib diisi dengan benar.');
    if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Username 3-40 karakter: huruf kecil, angka, titik, garis bawah, atau strip.');
    if (password.length < 8) throw new HttpError(400, 'Password minimal 8 karakter.');
    if (email && !EMAIL_RE.test(email)) throw new HttpError(400, 'Format email tidak valid.');
    const dup = await db.prepare(`SELECT id FROM users WHERE username = ?${email ? ' OR email = ?' : ''}`).bind(...(email ? [username, email] : [username])).first();
    if (dup) throw new HttpError(409, 'Username atau email sudah dipakai.');
    const rec = { id: genId('usr'), username, passwordHash: await hashPassword(password), name, role, email, idNumber: plainText(body.idNumber, 30) || null };
    await insertRow(db, 'users', rec);
    await audit(db, session.username, 'admin_create_account', username, role);
    return json({ id: rec.id, username, name, role }, 201);
  }
  if (view === 'admin-set-role' && method === 'PATCH') {
    requireRole(session, 'admin');
    const id = url.searchParams.get('id') || '';
    const role = String((await readBody()).role || '');
    if (!ROLES.has(role)) throw new HttpError(400, 'Peran tidak dikenal.');
    if (id === session.uid) throw new HttpError(400, 'Tidak bisa mengubah peran akun sendiri.');
    if (!(await db.prepare(`SELECT id FROM users WHERE id = ?`).bind(id).first())) throw new HttpError(404, 'Akun tidak ditemukan.');
    await updateRow(db, 'users', id, { role });
    await audit(db, session.username, 'admin_set_role', id, role);
    return json({ ok: true });
  }
  if (view === 'admin-set-password' && method === 'PATCH') {
    requireRole(session, 'admin');
    const id = url.searchParams.get('id') || '';
    const password = String((await readBody()).password || '');
    if (password.length < 8) throw new HttpError(400, 'Password minimal 8 karakter.');
    if (!(await db.prepare(`SELECT id FROM users WHERE id = ?`).bind(id).first())) throw new HttpError(404, 'Akun tidak ditemukan.');
    await updateRow(db, 'users', id, { passwordHash: await hashPassword(password) });
    await audit(db, session.username, 'admin_set_password', id, null);
    return json({ ok: true });
  }
  if (view === 'admin-face-reset' && method === 'DELETE') {
    requireRole(session, 'admin');
    const username = String(url.searchParams.get('username') || '').toLowerCase();
    const u = await db.prepare(`SELECT id FROM users WHERE username = ?`).bind(username).first();
    if (!u) throw new HttpError(404, 'Akun tidak ditemukan.');
    await db.prepare(`DELETE FROM faceTemplates WHERE userId = ?`).bind(u.id).run();
    await audit(db, session.username, 'admin_face_reset', username, null);
    return json({ ok: true });
  }

  throw new HttpError(400, 'Permintaan tidak dikenal.');
}

/** Pertemuan harus terbuka & pemanggil harus anggota kelasnya & belum presensi. */
async function loadAttendableMeeting(db, meetingId, session) {
  const meeting = await db.prepare(`SELECT * FROM meetings WHERE id = ?`).bind(meetingId).first();
  if (!meeting) throw new HttpError(404, 'Pertemuan tidak ditemukan.');
  const mem = await db.prepare(`SELECT 1 FROM classMembers WHERE classId = ? AND username = ?`).bind(meeting.classId, session.username).first();
  if (!mem) throw new HttpError(403, 'Anda bukan anggota kelas ini.');
  if (!isOpen(meeting)) throw new HttpError(409, 'Pertemuan ini tidak sedang dibuka.');
  const done = await db.prepare(`SELECT status FROM attendance WHERE meetingId = ? AND username = ?`).bind(meeting.id, session.username).first();
  if (done) throw new HttpError(409, 'Anda sudah tercatat presensi pada pertemuan ini.');
  return meeting;
}

// ============================================================
export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try {
      if (url.pathname === '/api') return withHeaders(await handleApi(request, env), cors);
      if (url.pathname === '/public') return withHeaders(await handlePublic(request, env), cors);
    } catch (err) {
      if (err instanceof HttpError) return withHeaders(json({ error: err.message }, err.status), cors);
      console.error('api-presensi error:', err?.stack || err);
      return withHeaders(json({ error: 'Terjadi kesalahan di server.' }, 500), cors);
    }
    return withHeaders(json({ error: 'Not found. Gunakan /api?... atau /public?view=...' }, 404), cors);
  },
};
function withHeaders(res, headers) {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(headers)) out.headers.set(k, v);
  return out;
}

export const __test__ = { euclid, median, spread, parseVector, sealTemplate, openTemplate, hashPassword, verifyPassword };

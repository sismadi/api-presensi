-- ============================================================
-- schema.sql — Skema Cloudflare D1 untuk api-presensi (Presensi Wajah)
-- ============================================================
-- Prinsip biometrik:
--   * Gambar/video wajah TIDAK PERNAH dikirim ke server dan TIDAK ada
--     kolom untuk menyimpannya. Klien (face-api.js) mengekstrak vektor
--     fitur 128-D; hanya vektor itu (template) yang dikirim.
--   * Template disimpan TERENKRIPSI (AES-256-GCM, kunci di secret
--     TEMPLATE_KEY — bukan di D1). Dump database saja tidak cukup untuk
--     membaca template.
--   * Tidak ada endpoint yang mengembalikan template ke klien.
-- Jalankan:
--   wrangler d1 execute presensi-db --file=./schema.sql            (lokal)
--   wrangler d1 execute presensi-db --file=./schema.sql --remote   (production)
-- PERINGATAN: file ini DROP semua tabel — jangan dijalankan ulang di production.
-- ============================================================

DROP TABLE IF EXISTS rate_limit;
DROP TABLE IF EXISTS auditLog;
DROP TABLE IF EXISTS challenges;
DROP TABLE IF EXISTS attendance;
DROP TABLE IF EXISTS meetings;
DROP TABLE IF EXISTS classMembers;
DROP TABLE IF EXISTS classes;
DROP TABLE IF EXISTS faceTemplates;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    passwordHash TEXT NOT NULL,            -- pbkdf2$sha256$<iter>$<salt>$<hash>
    name         TEXT NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
    email        TEXT UNIQUE,
    idNumber     TEXT                      -- NIM / NIP (opsional)
);

-- Satu template per akun. Re-enroll = ganti (UPSERT).
-- ciphertext = Float32 little-endian (sampleCount x 128) dienkripsi AES-GCM,
-- AAD = userId (template tidak bisa "dipindah" ke akun lain di DB).
CREATE TABLE faceTemplates (
    userId      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ciphertext  TEXT NOT NULL,
    iv          TEXT NOT NULL,
    kid         TEXT NOT NULL DEFAULT 'k1', -- id kunci, untuk rotasi TEMPLATE_KEY
    sampleCount INTEGER NOT NULL,
    dim         INTEGER NOT NULL DEFAULT 128,
    model       TEXT NOT NULL DEFAULT 'faceapi-128',
    consentAt   INTEGER NOT NULL,           -- persetujuan eksplisit (UU PDP)
    createdAt   INTEGER NOT NULL,
    updatedAt   INTEGER NOT NULL
);

CREATE TABLE classes (
    id                 TEXT PRIMARY KEY,
    code               TEXT NOT NULL UNIQUE,
    name               TEXT NOT NULL,
    instructorUsername TEXT NOT NULL REFERENCES users(username),
    createdAt          INTEGER NOT NULL,
    deleted            INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_classes_instructor ON classes(instructorUsername);

CREATE TABLE classMembers (
    classId  TEXT NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    username TEXT NOT NULL REFERENCES users(username),
    PRIMARY KEY (classId, username)
);
CREATE INDEX idx_classMembers_username ON classMembers(username);

-- Pertemuan (sesi presensi). status 'open' hanya berlaku sebelum endsAt.
CREATE TABLE meetings (
    id           TEXT PRIMARY KEY,
    classId      TEXT NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    startsAt     INTEGER NOT NULL,
    endsAt       INTEGER NOT NULL,
    lateAfterMin INTEGER NOT NULL DEFAULT 15,
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
    createdBy    TEXT NOT NULL,
    createdAt    INTEGER NOT NULL
);
CREATE INDEX idx_meetings_class ON meetings(classId);

-- distance = jarak Euclidean median (hanya untuk method 'face'); makin kecil
-- makin mirip. Disimpan untuk audit/kalibrasi, BUKAN data biometrik.
CREATE TABLE attendance (
    id        TEXT PRIMARY KEY,
    meetingId TEXT NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
    username  TEXT NOT NULL REFERENCES users(username),
    status    TEXT NOT NULL CHECK (status IN ('hadir','terlambat','izin','sakit','alpa')),
    method    TEXT NOT NULL CHECK (method IN ('face','manual')),
    distance  REAL,
    markedBy  TEXT,
    note      TEXT,
    createdAt INTEGER NOT NULL,
    UNIQUE (meetingId, username)
);
CREATE INDEX idx_attendance_username ON attendance(username);

-- Tantangan liveness sekali pakai (anti-replay request).
CREATE TABLE challenges (
    id        TEXT PRIMARY KEY,
    userId    TEXT NOT NULL,
    meetingId TEXT NOT NULL,
    kind      TEXT NOT NULL,
    createdAt INTEGER NOT NULL,
    expiresAt INTEGER NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0
);

-- Jejak audit: enroll, hapus template, presensi gagal/berhasil, override manual.
CREATE TABLE auditLog (
    id     TEXT PRIMARY KEY,
    at     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);
CREATE INDEX idx_auditLog_at ON auditLog(at);

CREATE TABLE rate_limit (
    key          TEXT PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 0,
    windowStart  INTEGER NOT NULL DEFAULT 0,
    blockedUntil INTEGER NOT NULL DEFAULT 0
);

-- --- Akun demo (GANTI/HAPUS sebelum produksi) ---
--   admin / admin123   dosen / dosen123   mahasiswa / peserta123
INSERT INTO users (id, username, passwordHash, name, role, email) VALUES
 ('u_admin', 'admin', 'pbkdf2$sha256$100000$NIxjLRZcjpNxTL4fErb5Cg$cUFJoq8vPtsPhvNO-nfXGQFFo3OUJqE1AGPQ258kryg', 'Administrator', 'admin', 'admin@presensi.demo'),
 ('u_dosen', 'dosen', 'pbkdf2$sha256$100000$nHhKhdZLwqKrcWJke48stQ$sfmvInol6GDo4OMTuZOPfsbkOPXHlmnctGB-EZKVAMs', 'Dosen Demo', 'dosen', 'dosen@presensi.demo'),
 ('u_mhs', 'mahasiswa', 'pbkdf2$sha256$100000$MOxMUXFGMUtmepTHNtSiXQ$Gxvolz1t55g_Yu6h63VKgrqBfJ7D9EuDmFOez77hp5Q', 'Mahasiswa Demo', 'mahasiswa', 'mahasiswa@presensi.demo');

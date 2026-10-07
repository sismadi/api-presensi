# api-presensi

Backend presensi wajah: Cloudflare Worker + D1. Pasangan frontend: `app-presensi`.
Pola mengikuti `api-lms` (`/public` tanpa sesi, `/api` wajib `Authorization: Bearer`, sesi HMAC, PBKDF2, captcha, rate limit di D1).

**Biometrik:** hanya vektor fitur wajah 128-D (hasil face-api.js di peramban) yang dikirim dan disimpan — terenkripsi AES-256-GCM.
Tidak ada gambar/video di server, tidak ada endpoint yang mengembalikan template. Detail: `SECURITY.md`.

## Setup

```bash
wrangler d1 create presensi-db                 # salin database_id ke wrangler.toml
wrangler d1 execute presensi-db --file=./schema.sql --remote     # HANYA sekali (schema memuat DROP TABLE)

wrangler secret put SESSION_SECRET             # 32+ karakter acak
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
wrangler secret put TEMPLATE_KEY               # tempel hasil di atas; SIMPAN backup-nya (hilang = semua template tak terbaca)

wrangler deploy
```
Sesuaikan `ALLOWED_ORIGINS` dan `MATCH_THRESHOLD` di `wrangler.toml`. Akun demo (`admin/admin123`, `dosen/dosen123`, `mahasiswa/peserta123`) **harus diganti/dihapus** sebelum produksi (`node hash-password.mjs "PasswordBaru"`).

## Endpoint ringkas

`/public`: `captcha`, `login`, `register` (selalu peran mahasiswa), `health`.

`/api` (semua wajib sesi):

| View | Method | Peran | Keterangan |
|---|---|---|---|
| `me`, `profile` | GET / PATCH | semua | Profil sendiri |
| `face-status` | GET | semua | Status pendaftaran wajah (tanpa data template) |
| `face-enroll` | POST | semua | `{consent:true, password, samples:[[128]×3..8]}` — maks. 5 vektor disimpan terenkripsi |
| `face-delete` | DELETE | semua | Hapus template sendiri (tarik persetujuan) |
| `classes` | GET | semua | Kelas milik/diikuti |
| `class-create` | POST | dosen/admin | `{code, name}` |
| `class-members` | GET / POST / DELETE | dosen pemilik/admin | Anggota + status enroll; tambah `{usernames:[]}`; `?username=` untuk keluarkan |
| `meetings` | GET | anggota / pemilik | `?classId=` |
| `meeting-open` | POST | dosen/admin | `{classId,title,durationMin,lateAfterMin}` |
| `meeting-close` | PATCH | dosen/admin | `?id=` |
| `meeting-report` | GET | dosen/admin | `?id=` — status, metode, jarak per anggota |
| `manual-mark` | POST | dosen/admin | Override izin/sakit/alpa… (catatan wajib, diaudit) |
| `attend-challenge` | POST | anggota | `{meetingId}` → `{challengeId, kind}` (blink / turn_left / turn_right) |
| `attend` | POST | anggota | `{meetingId, challengeId, livenessPassed:true, samples:[[128]×2..5]}` |
| `my-attendance` | GET | semua | Riwayat sendiri |
| `admin-stats`, `admin-create-account`, `admin-set-role`, `admin-set-password`, `admin-face-reset` | — | admin | Kelola akun & template |

## Pencocokan

Verifikasi **1:1** terhadap template akun yang sedang login: jarak Euclidean tiap sampel ke vektor tersimpan terdekat, lalu **median** ≤ `MATCH_THRESHOLD` (default 0.5; riset PDP memakai ≤ 0.60). Jarak tidak dikembalikan ke klien saat gagal. 5× gagal/10 menit → akun diblokir sementara.

## Uji

```bash
# terminal 1 (butuh .dev.vars berisi SESSION_SECRET & TEMPLATE_KEY)
wrangler d1 execute presensi-db --local --file=./schema.sql && wrangler dev --local
# terminal 2
node test/e2e.mjs        # 33 pemeriksaan: auth, otorisasi per peran, enroll, presensi, anti-replay, override, hapus
```
Uji memakai vektor sintetis; belum ada uji dengan wajah/kamera nyata (lihat catatan di `SECURITY.md`).

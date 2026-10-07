# SECURITY / PRIVASI — api-presensi

Data biometrik wajah adalah **data pribadi yang bersifat spesifik** menurut UU No. 27 Tahun 2022 (UU PDP). Pastikan dasar pemrosesan (persetujuan eksplisit), pemberitahuan privasi, retensi, dan prosedur hak subjek data ditangani institusi Anda; dokumen ini hanya menjelaskan kontrol teknis.

## Yang diterapkan
- **Tanpa data mentah.** Tidak ada kolom/endpoint untuk gambar. Hanya vektor 128-D.
- **Enkripsi at-rest.** Template = AES-256-GCM, kunci di secret `TEMPLATE_KEY` (di luar D1), AAD = `userId` (baris tak bisa dipindah ke akun lain). `kid` mendukung rotasi kunci.
- **Template tidak pernah dikembalikan.** `face-status` hanya memberi jumlah sampel & tanggal.
- **Persetujuan eksplisit** (`consent:true`, `consentAt` tersimpan) + **konfirmasi password** untuk enroll/ganti template (sesi curian tidak cukup menimpa template).
- **Penarikan persetujuan:** `face-delete` (mandiri) dan `admin-face-reset`.
- **Validasi sampel:** 128 angka finite, rentang wajar, sampel enroll harus saling konsisten (≤ 0.5) → satu orang.
- **Anti-replay:** tantangan liveness sekali pakai, terikat akun+pertemuan, TTL 2 menit, minimal 1.5 dtk sebelum dijawab.
- **Anti brute-force:** rate limit di D1 untuk login, captcha, enroll, challenge, dan presensi; jarak tidak dibocorkan saat gagal.
- **Otorisasi di server:** dosen hanya kelas miliknya; mahasiswa hanya kelas yang diikuti; presensi ganda ditolak (UNIQUE).
- **Audit:** `auditLog` (enroll, hapus, presensi ok/gagal, override manual, aksi admin). Override manual wajib catatan.

## Batasan yang harus Anda ketahui
1. **Liveness dievaluasi di klien.** Server hanya memastikan tantangan diterbitkan & dijawab tepat waktu; ia tidak dapat memverifikasi bahwa kedipan/tolehan benar-benar terjadi, karena server tidak menerima gambar (pilihan desain privasi). Ini penangkal foto/layar sederhana, **bukan** presentation-attack-detection yang kuat. Untuk risiko tinggi, kombinasikan dengan kontrol lain (presensi hanya di kelas yang diawasi dosen, pembatasan jaringan/lokasi, atau verifikasi acak oleh dosen via `manual-mark`).
2. **Pendaftaran wajah pertama tidak diawasi.** Penyerang yang memegang password korban dapat mendaftarkan wajahnya lebih dulu. Mitigasi: enroll di bawah pengawasan dosen/admin, atau tinjau status enroll lewat `class-members` dan `admin-face-reset`.
3. **Akurasi belum dikalibrasi dengan data nyata.** `MATCH_THRESHOLD` 0.5 adalah titik awal konservatif; ukur FAR/FRR pada populasi Anda (instrumen `app-riset-pdp` dapat dipakai) sebelum produksi. Akurasi face-api.js dapat berbeda antar etnis, usia, pencahayaan, dan kamera.
4. **Kehilangan `TEMPLATE_KEY` = semua template tak terbaca** (pengguna harus enroll ulang). Simpan cadangan di tempat aman.
5. Akun demo di `schema.sql` berpassword publik — hapus sebelum produksi.
6. Bersihkan `rate_limit`, `challenges`, dan `auditLog` berkala (mis. Cron Trigger) sesuai kebijakan retensi.

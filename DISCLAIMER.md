# ⚠️ Disclaimer Hukum & Etika

Paket ini dibuat **hanya untuk tujuan defensif**: membantu pemilik sistem menemukan
dan memperbaiki kerentanan pada aplikasinya sendiri.

## Kamu HANYA boleh memakai ini untuk:
- Aplikasi/website/kode yang **kamu miliki**, atau
- Target yang memberimu **izin tertulis** untuk diuji (mis. kontrak pentest,
  program bug bounty dengan scope yang jelas).

## Dilarang:
- Memindai, menguji, atau menyerang sistem **milik orang/organisasi lain** tanpa izin.
- Menjalankan payload **destruktif**: menghapus/mengubah data, brute force masif,
  DoS/flooding, deface, mass-exploit.
- Mengakses, menyalin, atau menyebarkan data pribadi (mis. data pasien/PII) milik
  orang lain.

## Tanggung jawab
Akses atau pengujian komputer tanpa izin melanggar hukum di banyak negara
(di Indonesia a.l. UU ITE). Pengguna bertanggung jawab penuh atas tindakannya.
Penulis/kontributor repo ini tidak bertanggung jawab atas penyalahgunaan.

## Praktik aman
- Uji di lingkungan **staging / salinan**, bukan produksi — terutama untuk aplikasi
  dengan data sensitif.
- Gunakan **rate limit** agar tidak membebani server.
- Sensor PII di laporan; simpan temuan secara rahasia dan laporkan ke pihak yang berwenang.

Dengan memakai paket ini, kamu menyatakan setuju memakainya secara legal dan etis.

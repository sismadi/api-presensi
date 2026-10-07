const B=process.env.API||'http://localhost:8787';
let fails=0; const ok=(c,m)=>{console.log((c?'PASS ':'FAIL ')+m); if(!c) fails++;};
const rnd=()=>{let u=0,v=0;while(!u)u=Math.random();while(!v)v=Math.random();return Math.sqrt(-2*Math.log(u))*Math.cos(2*Math.PI*v)};
const person=()=>Array.from({length:128},()=>rnd()*0.09);
const noisy=(p,s=0.02)=>p.map(x=>x+rnd()*s);
async function call(path,{method='GET',body,token}={}){const r=await fetch(B+path,{method,headers:{...(body?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});let d=null;try{d=await r.json()}catch{};return {s:r.status,d}}
async function login(u,p){const c=(await call('/public?view=captcha')).d;const pl=JSON.parse(Buffer.from(c.token.split('.')[0].replace(/-/g,'+').replace(/_/g,'/'),'base64').toString());
 const r=await call('/public?view=login',{method:'POST',body:{username:u,password:p,captchaToken:c.token,captchaAnswer:pl.a+pl.b}});return r}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

const mhs=(await login('mahasiswa','peserta123')); ok(mhs.s===200,'login mahasiswa'); const T=mhs.d.token;
const dos=(await login('dosen','dosen123')); ok(dos.s===200,'login dosen'); const D=dos.d.token;
const adm=(await login('admin','admin123')); const A=adm.d.token;
ok((await login('mahasiswa','salah')).s===401,'login password salah ditolak');
ok((await call('/api?view=me')).s===401,'/api tanpa sesi 401');

const cls=await call('/api?view=class-create',{method:'POST',token:D,body:{code:'pbo-a',name:'PBO Kelas A'}}); ok(cls.s===201,'dosen buat kelas');
ok((await call('/api?view=class-create',{method:'POST',token:T,body:{code:'x1',name:'x'}})).s===403,'mahasiswa tak boleh buat kelas');
const add=await call(`/api?view=class-members&classId=${cls.d.id}`,{method:'POST',token:D,body:{usernames:['mahasiswa','tidakada']}}); ok(add.d.added[0]==='mahasiswa'&&add.d.notFound[0]==='tidakada','tambah anggota + notFound');
const mtg=await call('/api?view=meeting-open',{method:'POST',token:D,body:{classId:cls.d.id,title:'Pertemuan 1',durationMin:60,lateAfterMin:30}}); ok(mtg.s===201,'buka pertemuan');
const M=mtg.d.id;

const me=person(); const S=[1,2,3,4,5,6].map(()=>noisy(me));
ok((await call('/api?view=face-status',{token:T})).d.enrolled===false,'belum enroll');
ok((await call('/api?view=attend-challenge',{method:'POST',token:T,body:{meetingId:M}})).s===409,'challenge ditolak sebelum enroll');
ok((await call('/api?view=face-enroll',{method:'POST',token:T,body:{password:'peserta123',samples:S}})).s===400,'enroll tanpa consent 400');
ok((await call('/api?view=face-enroll',{method:'POST',token:T,body:{consent:true,password:'salah',samples:S}})).s===401,'enroll password salah 401');
ok((await call('/api?view=face-enroll',{method:'POST',token:T,body:{consent:true,password:'peserta123',samples:[...S.slice(0,3),person()]}})).s===422,'enroll sampel tak konsisten 422');
ok((await call('/api?view=face-enroll',{method:'POST',token:T,body:{consent:true,password:'peserta123',samples:[S[0],S[1]]}})).s===400,'enroll <3 sampel 400');
const bad=[...S.slice(0,3)]; bad[0]=bad[0].slice(0,100);
ok((await call('/api?view=face-enroll',{method:'POST',token:T,body:{consent:true,password:'peserta123',samples:bad}})).s===400,'vektor panjang salah 400');
const en=await call('/api?view=face-enroll',{method:'POST',token:T,body:{consent:true,password:'peserta123',samples:S}}); ok(en.s===201&&en.d.sampleCount===5,'enroll sukses (simpan 5)');
const fs=(await call('/api?view=face-status',{token:T})).d; ok(fs.enrolled&&!('ciphertext' in (fs.template||{})),'status tanpa membocorkan template');

// presensi: terlalu cepat
let ch=await call('/api?view=attend-challenge',{method:'POST',token:T,body:{meetingId:M}}); ok(ch.s===200&&['blink','turn_left','turn_right'].includes(ch.d.kind),'challenge terbit');
let fast=await call('/api?view=attend',{method:'POST',token:T,body:{meetingId:M,challengeId:ch.d.challengeId,livenessPassed:true,samples:[noisy(me),noisy(me),noisy(me)]}}); ok(fast.s===400,'attend terlalu cepat ditolak');
// challenge baru; orang lain
ch=await call('/api?view=attend-challenge',{method:'POST',token:T,body:{meetingId:M}}); await sleep(1700);
const other=await call('/api?view=attend',{method:'POST',token:T,body:{meetingId:M,challengeId:ch.d.challengeId,livenessPassed:true,samples:[person(),person(),person()]}}); ok(other.s===403&&!JSON.stringify(other.d).match(/\d\.\d{3}/),'wajah orang lain ditolak (tanpa bocor jarak)');
const reuse=await call('/api?view=attend',{method:'POST',token:T,body:{meetingId:M,challengeId:ch.d.challengeId,livenessPassed:true,samples:[noisy(me),noisy(me),noisy(me)]}}); ok(reuse.s===400,'challenge tak bisa dipakai ulang');
ch=await call('/api?view=attend-challenge',{method:'POST',token:T,body:{meetingId:M}}); await sleep(1700);
ok((await call('/api?view=attend',{method:'POST',token:T,body:{meetingId:M,challengeId:ch.d.challengeId,livenessPassed:false,samples:[noisy(me),noisy(me),noisy(me)]}})).s===400,'liveness=false ditolak');
ch=await call('/api?view=attend-challenge',{method:'POST',token:T,body:{meetingId:M}}); await sleep(1700);
const good=await call('/api?view=attend',{method:'POST',token:T,body:{meetingId:M,challengeId:ch.d.challengeId,livenessPassed:true,samples:[noisy(me),noisy(me),noisy(me)]}}); ok(good.s===200&&good.d.status==='hadir','presensi wajah cocok -> hadir');
ok((await call('/api?view=attend-challenge',{method:'POST',token:T,body:{meetingId:M}})).s===409,'presensi ganda ditolak');

const rep=await call(`/api?view=meeting-report&id=${M}`,{token:D}); const row=rep.d.rows.find(r=>r.username==='mahasiswa'); ok(row.status==='hadir'&&row.method==='face'&&row.distance<0.5,'laporan dosen memuat hadir + jarak '+row.distance);
ok((await call(`/api?view=meeting-report&id=${M}`,{token:T})).s===403,'mahasiswa tak bisa lihat laporan');
ok((await call('/api?view=manual-mark',{method:'POST',token:D,body:{meetingId:M,username:'mahasiswa',status:'izin',note:''}})).s===400,'override manual wajib catatan');
ok((await call('/api?view=manual-mark',{method:'POST',token:D,body:{meetingId:M,username:'mahasiswa',status:'izin',note:'surat dokter'}})).s===200,'override manual');
const ma=await call('/api?view=my-attendance',{token:T}); ok(ma.d.attendance[0].status==='izin','my-attendance mencerminkan override');
// dosen lain tak boleh akses kelas dosen
const cm=await call(`/api?view=class-members&classId=${cls.d.id}`,{token:A}); ok(cm.s===200&&cm.d.members[0].enrolled===true,'admin lihat anggota + status enroll');
const st=await call('/api?view=admin-stats',{token:A}); ok(st.d.counts.templates===1,'admin-stats templates=1');
ok((await call('/api?view=admin-stats',{token:D})).s===403,'admin-stats dosen 403');
ok((await call('/api?view=face-delete',{method:'DELETE',token:T})).s===200&&(await call('/api?view=face-status',{token:T})).d.enrolled===false,'hapus template (tarik persetujuan)');
console.log(fails?`\n${fails} GAGAL`:'\nSEMUA LULUS');

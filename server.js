const express = require('express'), http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const { Server } = require('socket.io');
const app = express(), srv = http.createServer(app);
app.set('trust proxy', true);
const io = new Server(srv, { maxHttpBufferSize: 8e6 });
app.use(express.static(path.join(__dirname, 'public')));

// ---- Kayıt dosyaları (DATA_DIR ile kalıcı diske yönlendirilebilir) ----
const DIR = process.env.DATA_DIR || __dirname, MAX = 5000;
const ld = (f, d) => { try { return JSON.parse(fs.readFileSync(path.join(DIR, f))); } catch (e) { return d; } };
let users = ld('users.json', {}), profiles = ld('profiles.json', {}), ips = ld('ips.json', {}), messages = ld('messages.json', []);
const tm = {};
const save = (f, v) => { clearTimeout(tm[f]); tm[f] = setTimeout(() => fs.writeFile(path.join(DIR, f), JSON.stringify(v), () => {}), 1500); };
const CH = [{ id: 'genel', name: 'genel' }, { id: 'sohbet', name: 'sohbet' }, { id: 'medya', name: 'medya' }];

const ipOf = (hd, fb) => String(hd['x-forwarded-for'] || fb || '').split(',')[0].trim();
const hip = ip => crypto.createHash('sha256').update(ip).digest('hex').slice(0, 24);
const hashPw = (p, salt) => crypto.scryptSync(p, salt, 32).toString('hex');
const fails = {};

// Bu IP daha önce giriş/kayıt yaptı mı?
app.get('/api/check', (q, r) => r.json({ known: !!ips[hip(ipOf(q.headers, q.socket.remoteAddress))] }));

io.use((s, next) => {
  const a = s.handshake.auth || {}, ip = hip(ipOf(s.handshake.headers, s.handshake.address));
  const f = fails[ip];
  if (f && f.n >= 8 && Date.now() - f.t < 6e5) return next(new Error('Çok fazla deneme, 10 dakika sonra tekrar dene'));
  const name = String(a.username || '').trim(), key = name.toLowerCase(), pw = String(a.password || '');
  if (a.mode === 'register') {
    if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) return next(new Error('Kullanıcı adı 3-16 karakter; harf, rakam veya _ olmalı'));
    if (pw.length < 6) return next(new Error('Şifre en az 6 karakter olmalı'));
    if (users[key]) return next(new Error('Bu kullanıcı adı alınmış'));
    const salt = crypto.randomBytes(16).toString('hex');
    users[key] = { name, salt, hash: hashPw(pw, salt) };
    profiles[name] = { color: '#ffffff', avatar: '', bio: '', owner: Object.keys(users).length === 1 };
    save('users.json', users); save('profiles.json', profiles);
    s.user = name;
  } else {
    const u = users[key];
    if (!u || !crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt), 'hex'), Buffer.from(u.hash, 'hex'))) {
      fails[ip] = { n: (f?.n || 0) + 1, t: Date.now() };
      return next(new Error('Kullanıcı adı veya şifre hatalı'));
    }
    s.user = u.name;
  }
  delete fails[ip]; ips[ip] = 1; save('ips.json', ips);
  next();
});

const online = new Map(), voice = new Set(), sharing = new Set();
const presence = () => io.emit('presence', {
  online: [...new Set(online.values())],
  voice: [...voice].map(id => ({ id, name: online.get(id), sharing: sharing.has(id) }))
});
const store = m => {
  messages.push(m); while (messages.length > MAX) messages.shift();
  save('messages.json', messages); io.emit('msg', m);
};
const mid = () => Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
const sys = (kind, who, text) => store({ id: mid(), ch: 'genel', type: 'sys', kind, who, text, time: Date.now() });
const okCh = c => CH.some(x => x.id === c);

io.on('connection', s => {
  online.set(s.id, s.user);
  s.emit('init', { me: s.user, channels: CH, profiles });
  presence();

  const push = m => store({ ...m, id: mid(), user: s.user, time: Date.now() });
  s.on('text', ({ ch, text } = {}) => {
    text = String(text || '').slice(0, 2000).trim();
    if (text && okCh(ch)) push({ ch, type: 'text', text });
  });
  s.on('image', ({ ch, data } = {}) => {
    if (okCh(ch) && typeof data === 'string' && data.startsWith('data:image/') && data.length < 3e6) push({ ch, type: 'image', data });
  });
  s.on('history', ({ ch, before } = {}) => {
    if (!okCh(ch)) return;
    let l = messages.filter(m => m.ch === ch);
    if (before) { const i = l.findIndex(m => m.id === before); if (i >= 0) l = l.slice(0, i); }
    const list = l.slice(-100);
    s.emit('history', { ch, before: !!before, list, more: l.length > list.length });
  });
  s.on('del', id => {
    const i = messages.findIndex(m => m.id === id); if (i < 0) return;
    if (messages[i].user !== s.user && !profiles[s.user]?.owner) return;
    messages.splice(i, 1); save('messages.json', messages); io.emit('del', id);
  });
  s.on('profile', p => {
    p = p || {}; const cur = profiles[s.user] || {};
    const color = /^#[0-9a-f]{6}$/i.test(p.color) ? p.color : (cur.color || '#ffffff');
    const avatar = typeof p.avatar === 'string' && (p.avatar === '' || (p.avatar.startsWith('data:image/') && p.avatar.length < 80000)) ? p.avatar : (cur.avatar || '');
    profiles[s.user] = { ...cur, color, avatar, bio: String(p.bio || '').slice(0, 60) };
    save('profiles.json', profiles); io.emit('profiles', profiles);
  });

  s.on('voice:join', () => {
    if (voice.has(s.id)) return;
    const others = [...voice]; voice.add(s.id);
    s.emit('voice:peers', others);
    others.forEach(id => io.to(id).emit('voice:joined', s.id));
    sys('join', s.user, `${s.user} sese katıldı`); presence();
  });
  const leave = () => {
    if (voice.delete(s.id)) {
      sharing.delete(s.id);
      voice.forEach(id => io.to(id).emit('voice:left', s.id));
      sys('leave', s.user, `${s.user} sesten ayrıldı`); presence();
    }
  };
  s.on('voice:leave', leave);
  s.on('screen', on => {
    if (!voice.has(s.id)) return;
    if (on) { sharing.add(s.id); sys('screen', s.user, `${s.user} ekran paylaşmaya başladı`); } else sharing.delete(s.id);
    presence();
  });
  s.on('signal', ({ to, data }) => io.to(to).emit('signal', { from: s.id, data }));
  s.on('disconnect', () => { leave(); online.delete(s.id); presence(); });
});

const PORT = process.env.PORT || 3000;
srv.listen(PORT, () => console.log('⚚ PHANDORA OWNER\'s çalışıyor: http://localhost:' + PORT));

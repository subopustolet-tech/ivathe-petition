const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'votes.json');
const INDEX_FILE = path.join(__dirname, 'index.html');
const sessions = new Map();
const attempts = new Map();

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error('Set ADMIN_PASSWORD to a random password of at least 12 characters.');
  process.exit(1);
}
fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', { mode: 0o600 });
function readVotes() { try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return []; } }
function writeVotes(votes) { fs.writeFileSync(DATA_FILE, JSON.stringify(votes, null, 2), { mode: 0o600 }); }
function send(res, status, data, headers={}) { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', ...headers }); res.end(JSON.stringify(data)); }
function body(req) { return new Promise((resolve,reject)=>{ let raw=''; req.on('data',chunk=>{raw+=chunk; if(raw.length>10000){reject(new Error('Слишком большой запрос'));req.destroy();}}); req.on('end',()=>{try{resolve(JSON.parse(raw||'{}'));}catch{reject(new Error('Некорректный JSON'));}}); req.on('error',reject); }); }
function rateLimit(req,res,key,limit=10,windowMs=60000){const ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').toString().split(',')[0].trim();const now=Date.now();const k=key+':'+ip;const arr=(attempts.get(k)||[]).filter(t=>now-t<windowMs);if(arr.length>=limit){send(res,429,{error:'Слишком много попыток. Попробуй позже.'});return false;}arr.push(now);attempts.set(k,arr);return true;}
function isAdmin(req){const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');const expiry=sessions.get(token);if(!expiry||expiry<Date.now()){sessions.delete(token);return false;}return true;}
const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://localhost');
  if(req.method==='GET' && (url.pathname==='/'||url.pathname==='/index.html')){try{const html=fs.readFileSync(INDEX_FILE);res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"});res.end(html);}catch{res.writeHead(500);res.end('index.html not found');}return;}
  if(req.method==='GET' && url.pathname==='/api/stats'){const votes=readVotes();return send(res,200,{total:votes.length,yes:votes.filter(v=>v.vote==='yes').length,no:votes.filter(v=>v.vote==='no').length});}
  if(req.method==='POST' && url.pathname==='/api/vote'){
    if(!rateLimit(req,res,'vote',15))return;
    try{const b=await body(req);const username=String(b.username||'').replace(/^@/,'').trim().toLowerCase();const vote=String(b.vote||'');if(!/^[a-z0-9_]{5,32}$/.test(username))return send(res,400,{error:'Укажи корректный Telegram @username (5–32 символа).'});if(!['yes','no'].includes(vote))return send(res,400,{error:'Выбери Да или Нет.'});const votes=readVotes();if(votes.some(v=>v.username.toLowerCase()===username))return send(res,409,{error:'С этого @username голос уже записан.'});votes.push({username,vote,createdAt:new Date().toISOString()});writeVotes(votes);return send(res,201,{ok:true,message:'Голос сохранён. Спасибо за участие.'});}catch(e){return send(res,400,{error:e.message||'Не удалось сохранить голос.'});}
  }
  if(req.method==='POST' && url.pathname==='/api/admin/login'){
    if(!rateLimit(req,res,'login',5,300000))return;
    try{const b=await body(req);const provided=Buffer.from(String(b.password||''));const expected=Buffer.from(ADMIN_PASSWORD);if(provided.length!==expected.length||!crypto.timingSafeEqual(provided,expected))return send(res,401,{error:'Неверный пароль.'});const token=crypto.randomBytes(32).toString('hex');sessions.set(token,Date.now()+8*60*60*1000);return send(res,200,{token,expiresIn:28800});}catch(e){return send(res,400,{error:e.message});}
  }
  if(req.method==='GET' && url.pathname==='/api/admin/votes'){if(!isAdmin(req))return send(res,401,{error:'Сессия истекла. Войди снова.'});const votes=readVotes().sort((a,b)=>b.createdAt.localeCompare(a.createdAt));return send(res,200,{votes});}
  send(res,404,{error:'Не найдено'});
});
server.listen(PORT,'0.0.0.0',()=>console.log(`Petition app listening on ${PORT}`));

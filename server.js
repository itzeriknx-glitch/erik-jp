const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATA_FILE = path.join(ROOT, 'data.json');
const sessions = new Map();
const attempts = new Map();

if (!ADMIN_USER || !ADMIN_PASSWORD || !SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Configure ADMIN_USER, ADMIN_PASSWORD e SESSION_SECRET (mínimo 32 caracteres).');
  process.exit(1);
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function readData() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return { categories: [
    {id:'cat-gta',name:'GTA RP'}, {id:'cat-live',name:'Lives'},
    {id:'cat-shorts',name:'Vídeos curtos'}, {id:'cat-outros',name:'Outros'}
  ], links: [] }; }
}
function writeData(data) {
  const temp = DATA_FILE + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(data, null, 2), {mode:0o600});
  fs.renameSync(temp, DATA_FILE);
}
function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim()).filter(Boolean).map(x => {
    const i=x.indexOf('='); return [x.slice(0,i), decodeURIComponent(x.slice(i+1))];
  }));
}
function isAdmin(req) {
  const token = cookies(req).erikjp_session;
  if (!token) return false;
  const session = sessions.get(token);
  if (!session || session.expires < Date.now()) { sessions.delete(token); return false; }
  return true;
}
function send(res, status, body, headers={}) {
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve,reject)=>{
    let raw='', size=0;
    req.on('data',chunk=>{size+=chunk.length;if(size>12*1024*1024){reject(new Error('Arquivo enviado excede 12 MB.'));req.destroy();return;}raw+=chunk;});
    req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{});}catch{reject(new Error('JSON inválido.'));}});
    req.on('error',reject);
  });
}
const mime = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.webp':'image/webp','.svg':'image/svg+xml','.txt':'text/plain; charset=utf-8'};
const server = http.createServer(async (req,res)=>{
  const url = new URL(req.url,'http://localhost');
  const ip = req.socket.remoteAddress || 'unknown';

  if (req.method==='POST' && url.pathname==='/api/login') {
    const state=attempts.get(ip)||{count:0,until:0};
    if(state.until>Date.now()){send(res,429,{error:'Muitas tentativas. Aguarde alguns minutos.'});return;}
    try {
      const body=await readBody(req);
      if(safeEqual(body.username||'',ADMIN_USER) && safeEqual(body.password||'',ADMIN_PASSWORD)) {
        attempts.delete(ip);
        const token=crypto.randomBytes(32).toString('hex');
        sessions.set(token,{expires:Date.now()+8*60*60*1000});
        const secure=process.env.NODE_ENV==='production'?'; Secure':'';
        send(res,200,{ok:true},{'Set-Cookie':`erikjp_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`});
      } else {
        state.count++;
        if(state.count>=6){state.count=0;state.until=Date.now()+10*60*1000;}
        attempts.set(ip,state);
        send(res,401,{error:'Usuário ou senha incorretos.'});
      }
    } catch(e){send(res,400,{error:e.message});}
    return;
  }
  if (req.method==='POST' && url.pathname==='/api/logout') {
    const token=cookies(req).erikjp_session;
    if(token)sessions.delete(token);
    send(res,200,{ok:true},{'Set-Cookie':'erikjp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});
    return;
  }
  if (req.method==='GET' && url.pathname==='/api/me') {send(res,200,{authenticated:isAdmin(req)});return;}
  if (req.method==='GET' && url.pathname==='/api/data') {send(res,200,{data:readData()});return;}
  if (req.method==='PUT' && url.pathname==='/api/data') {
    if(!isAdmin(req)){send(res,401,{error:'Acesso não autorizado. Faça login novamente.'});return;}
    try {
      const data=await readBody(req);
      if(!data || !Array.isArray(data.categories) || !Array.isArray(data.links)){send(res,400,{error:'Formato de dados inválido.'});return;}
      writeData(data); send(res,200,{ok:true});
    } catch(e){send(res,400,{error:e.message});}
    return;
  }

  if(req.method!=='GET' && req.method!=='HEAD'){send(res,405,{error:'Método não permitido.'});return;}
  let requested=decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname);
  const file=path.resolve(ROOT,'.'+requested);
  if(!file.startsWith(ROOT+path.sep) || path.basename(file).startsWith('.')){res.writeHead(403);res.end('Forbidden');return;}
  fs.readFile(file,(err,content)=>{
    if(err){res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});res.end('Não encontrado');return;}
    res.writeHead(200,{'Content-Type':mime[path.extname(file).toLowerCase()]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin'});
    if(req.method==='HEAD')res.end();else res.end(content);
  });
});
server.listen(PORT,()=>console.log(`ERIK.JP rodando em http://localhost:${PORT}`));

const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=UTF-8","Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"Content-Type","Access-Control-Allow-Methods":"GET, POST, PUT, DELETE, OPTIONS"}});


const SESSION_HOURS = 12;
const encoder = new TextEncoder();

function hexToBytes(hex){
  const out=new Uint8Array(hex.length/2);
  for(let i=0;i<out.length;i++) out[i]=parseInt(hex.slice(i*2,i*2+2),16);
  return out;
}
function bytesToHex(bytes){return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("");}
async function sha256Hex(value){return bytesToHex(await crypto.subtle.digest("SHA-256",encoder.encode(value)));}
async function passwordHash(password,saltHex){
  const key=await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:hexToBytes(saltHex),iterations:100000},key,256);
  return bytesToHex(bits);
}
function secureEqual(a,b){
  if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;
  let diff=0; for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i); return diff===0;
}
function getCookie(request,name){
  const raw=request.headers.get("Cookie")||"";
  for(const part of raw.split(";")){const [k,...v]=part.trim().split("=");if(k===name)return decodeURIComponent(v.join("="));}
  return null;
}
async function getAuth(request,env){
  const token=getCookie(request,"terral_session"); if(!token)return null;
  const tokenHash=await sha256Hex(token);
  const row=await env.DB.prepare(`SELECT u.id,u.username,u.role,u.employee_id,e.name AS employee_name,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN employees e ON e.id=u.employee_id WHERE s.token_hash=? AND u.active=1 AND datetime(s.expires_at) > datetime('now')`).bind(tokenHash).first();
  if(!row)return null;
  return {id:row.id,username:row.username,role:row.role,employee_id:row.employee_id,name:row.employee_name||row.username};
}
function loginPage(message=""){
return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TERRAL | CONTROLE DE OBRAS</title><link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAACc0lEQVR4nO3cPU7DYBAGYYOoQEpJyw24Freg4IgcgzIStFCgSEYkIXbifRfPPBfA3+5g50fK1dPw8DkI6zp9AcoyADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAu0lfwCH3t5v0JVzc28c2fQm/tApgjUsfG5+vSwwtAlj74vfZnTkdQvw1AHH5Y+nzRwNIH76L5BxiAbj8n1LziATg8vdLzKU8AJd/XPV8SgNw+aepnFNZAC5/mqp5xd8GKqskAP/756mYW4tPAo95eX9NX8LZnu8e05dwUOtHwBqWPwy9z7F4AHNvY52HNsfc8yz9GGh9B9DyDADOAOAMAM4A4AwAzgDgDADOAODaBtD58/M5up6nbQDD0HdoU3U+R/tvAy8xvHO+V+i8vEtofQfQ8gwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDABu8QDePrZL/4k/zf2xxw4/Ern0/DB3gKnL7LD8Cu1/KvaSKEudouQO0OEx8B9VzA3zCNB+ZQF4F5imal6ldwAjOE3lnMofAUZwXPV8Iq8BjGC/xFxiLwKN4KfUPKLvAozgW3IO8beB9AjS52/xSeBuCPe3m/CV1EkvfqdFADvjoawxhi5LH2sVwFjHYa1R/DWAsgwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADuC1o5ZrPxplRWAAAAAElFTkSuQmCC"><style>
:root{--wine:#690020;--wine2:#8a1237;--bg:#f3f4f6;--text:#202631;--muted:#6d7480}*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Arial,Helvetica,sans-serif;background:linear-gradient(135deg,#f6f6f7,#eceef1);display:grid;place-items:center;color:var(--text);padding:22px}.card{width:min(430px,100%);background:#fff;border-radius:18px;box-shadow:0 18px 50px #0f172a1c;overflow:hidden}.head{background:linear-gradient(100deg,#570019,var(--wine2));color:#fff;padding:27px 30px}.brand{font-size:26px;font-weight:800}.project{font-size:13px;opacity:.9;margin-top:6px}.body{padding:30px}.body h1{font-size:23px;margin:0 0 7px}.body p{color:var(--muted);font-size:14px;margin:0 0 22px}label{display:block;font-size:12px;font-weight:800;margin:14px 0 6px}input{width:100%;padding:12px 13px;border:1px solid #ccd2d9;border-radius:9px;font-size:15px;text-transform:none}button{width:100%;border:0;background:linear-gradient(100deg,#590019,var(--wine2));color:#fff;border-radius:9px;padding:13px;margin-top:20px;font-weight:800;font-size:15px;cursor:pointer}.error{display:none;background:#fff0f1;color:#a61b32;border:1px solid #f3c7cf;border-radius:8px;padding:10px;margin-top:14px;font-size:13px}.foot{text-align:center;color:#858b94;font-size:11px;margin-top:18px}button,a,select,label,.module,.user-btn,.menu-link,.menu-action,.btn,.upload,.emp-card{cursor:pointer!important}button *,a *,label *,.module *,.user-btn *,.menu-link *,.menu-action *,.btn *,.upload *,.emp-card *{cursor:pointer!important}button,button *,a,a *,select,select *,label,label *,.module,.module *,.user-btn,.user-btn *,.menu-link,.menu-link *,.menu-action,.menu-action *,.btn,.btn *,.upload,.upload *,.emp-card,.emp-card *{cursor:pointer!important}</style></head><body><div class="card"><div class="head"><div class="brand">Terral Incorporadora</div><div class="project">CONTROLE DE OBRAS</div></div><div class="body"><h1>Controle de Obras</h1><p>Entre com seu usuário e senha para acessar as obras liberadas para o seu perfil.</p><form id="login"><label>Usuário</label><input id="username" autocomplete="username" required placeholder="NOME.SOBRENOME"><label>Senha</label><input id="password" type="password" autocomplete="current-password" required><button>Entrar</button><div style="text-align:right;margin-top:10px"><a href="/recuperar-senha" style="font-size:12px;color:#7d0b2f;text-decoration:none">Esqueci minha senha</a></div><div id="err" class="error"></div></form><div class="foot">Acesso restrito • Terral Incorporadora</div></div></div><script>login.onsubmit=async(e)=>{e.preventDefault();err.style.display='none';const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:username.value,password:password.value})});const d=await r.json().catch(()=>({}));if(r.ok){location.href='/';return;}err.textContent=d.error||'Não foi possível entrar.';err.style.display='block';};</script></body></html>`;
}


function randomHex(bytes=16){
  const a=new Uint8Array(bytes);crypto.getRandomValues(a);return bytesToHex(a);
}
async function ensureAdminSchema(env){
  try{await env.DB.prepare("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''").run();}catch(e){
    if(!String(e&&e.message||e).toLowerCase().includes('duplicate column')) console.log('email schema:',String(e&&e.message||e));
  }
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`).run();
}
function isAdmin(auth){return auth && auth.role==='admin';}
function safeText(v){return String(v??'').replace(/[&<>\"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[m]));}



async function createPasswordReset(env,userId){
  await ensureAdminSchema(env);
  const token=randomHex(32);
  const tokenHash=await sha256Hex(token);
  await env.DB.prepare("DELETE FROM password_resets WHERE user_id=? OR datetime(expires_at)<=datetime('now')").bind(userId).run();
  await env.DB.prepare("INSERT INTO password_resets (user_id,token_hash,expires_at,used) VALUES (?,?,datetime('now','+30 minutes'),0)").bind(userId,tokenHash).run();
  return token;
}

async function sendPasswordResetEmail(env,to,name,resetUrl){
  if(!env.RESEND_API_KEY || !env.RESET_FROM_EMAIL){
    throw new Error("Envio de e-mail ainda não configurado. Configure RESEND_API_KEY e RESET_FROM_EMAIL no Cloudflare.");
  }
  const subject="Recuperação de senha | TERRAL Controle de Obras";
  const safeName=safeText(name||"Usuário");
  const html=`<div style="font-family:Arial,sans-serif;color:#202631;line-height:1.55"><h2 style="color:#690020">TERRAL | Controle de Obras</h2><p>Olá, <b>${safeName}</b>.</p><p>Foi solicitado um link para redefinir sua senha de acesso.</p><p><a href="${resetUrl}" style="display:inline-block;background:#790229;color:white;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:700">Redefinir minha senha</a></p><p style="color:#68717e;font-size:13px">Este link é válido por 30 minutos e pode ser usado uma única vez.</p><p style="color:#68717e;font-size:12px">Se você não solicitou esta alteração, ignore este e-mail.</p></div>`;
  const r=await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{"Authorization":"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},
    body:JSON.stringify({from:env.RESET_FROM_EMAIL,to:[to],subject,html})
  });
  const d=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(d.message||"Não foi possível enviar o e-mail de recuperação.");
  return d;
}
function adminPage(){
return String.raw`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TERRAL | ADMINISTRAÇÃO</title>
<style>
:root{--wine:#690020;--wine2:#8a1237;--wine3:#540018;--bg:#f4f4f5;--text:#202631;--muted:#68717e;--line:#e1e4e8;--green:#167c43;--red:#b42318;--soft:#f7edf1}
*{box-sizing:border-box}body{margin:0;background:var(--bg);font-family:Arial,Helvetica,sans-serif;color:var(--text)}button,a,input,select,label{font:inherit}button,a,.btn,.user-card,.tab,.project-check{cursor:pointer!important}
header{height:70px;background:linear-gradient(90deg,#5b001a,var(--wine2));color:#fff;padding:0 28px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 10px #0002}header h1{font-size:20px;margin:0}header small{opacity:.9}header a{color:#fff;text-decoration:none;font-weight:700}
.wrap{max-width:1240px;margin:28px auto;padding:0 22px}.intro{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:18px}.intro h2{font-size:29px;margin:0 0 4px}.intro p{margin:0;color:var(--muted)}
.stats{display:flex;gap:9px;flex-wrap:wrap}.stat{background:#fff;border:1px solid var(--line);border-radius:999px;padding:8px 13px;font-size:12px;color:var(--muted)}.stat b{color:var(--wine)}
.layout{display:grid;grid-template-columns:350px 1fr;gap:18px;align-items:start}.card{background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:0 8px 24px #0f172a0c;padding:20px}.card h3{margin:0 0 4px;color:var(--wine)}.hint{font-size:12px;color:var(--muted);line-height:1.45;margin-bottom:16px}
label{display:block;font-size:12px;font-weight:800;margin:12px 0 6px}input,select{width:100%;padding:11px 12px;border:1px solid #cfd4da;border-radius:8px;background:#fff;font-size:14px;outline:none}input:focus,select:focus{border-color:#9d4963;box-shadow:0 0 0 3px #8a123713}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.btn{border:0;border-radius:8px;padding:10px 13px;font-weight:800}.primary{background:linear-gradient(90deg,#60001c,var(--wine2));color:#fff}.wide{width:100%;margin-top:17px}.ghost{background:#f2f3f5;color:var(--text)}.danger{background:#fff0f0;color:var(--red)}.outline{background:#fff;border:1px solid var(--line);color:var(--wine)}
.msg{display:none;margin-top:12px;border-radius:8px;padding:10px;font-size:12px}.msg.ok{display:block;background:#eff9f2;color:#13733d;border:1px solid #b7ddc2}.msg.err{display:block;background:#fff0f1;color:#a61b32;border:1px solid #f3c7cf}
.list-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:13px}.search{max-width:370px}.user-list{display:flex;flex-direction:column;gap:9px}.user-card{border:1px solid var(--line);border-radius:11px;padding:13px 14px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;transition:.15s;background:#fff}.user-card:hover{border-color:#c8a1ae;box-shadow:0 5px 15px #5f10200d}.user-main{min-width:0}.user-name{font-weight:800;font-size:14px}.user-meta{font-size:12px;color:var(--muted);margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.badges{display:flex;gap:6px;align-items:center;margin-top:8px}.badge{font-size:10px;padding:4px 7px;border-radius:999px;background:var(--soft);color:var(--wine);font-weight:800}.badge.active{background:#eaf7ef;color:var(--green)}.badge.off{background:#eee;color:#777}.manage{background:#690020;color:#fff;border:0;border-radius:8px;padding:9px 13px;font-weight:800;white-space:nowrap}.empty{text-align:center;color:var(--muted);padding:30px}
.modal{position:fixed;inset:0;background:#1119;display:none;align-items:center;justify-content:center;padding:22px;z-index:50}.modal.open{display:flex}.modalbox{width:min(780px,100%);max-height:90vh;overflow:auto;background:#fff;border-radius:16px;box-shadow:0 25px 80px #0004}.modalhead{padding:20px 22px 15px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:15px;align-items:flex-start}.modalhead h3{margin:0;color:var(--wine);font-size:20px}.modalhead p{margin:4px 0 0;color:var(--muted);font-size:12px}.close{border:0;background:#f3f3f4;width:34px;height:34px;border-radius:50%;font-size:19px}.tabs{display:flex;padding:0 22px;border-bottom:1px solid var(--line);gap:5px}.tab{border:0;background:transparent;padding:14px 12px;font-weight:800;color:#777;border-bottom:3px solid transparent}.tab.active{color:var(--wine);border-bottom-color:var(--wine)}.panel{display:none;padding:22px}.panel.active{display:block}.section-title{font-size:15px;font-weight:800;color:var(--wine);margin-bottom:4px}.panel-note{font-size:12px;color:var(--muted);margin-bottom:16px}
.projects-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.project-check{border:1px solid var(--line);border-radius:10px;padding:11px 12px;display:flex;align-items:center;gap:10px;background:#fff}.project-check:has(input:checked){border-color:#a25a70;background:#fbf4f7}.project-check input{width:18px;height:18px;margin:0}.project-check span{font-size:12px;font-weight:700}.actions-row{display:flex;justify-content:flex-end;gap:8px;margin-top:18px;flex-wrap:wrap}.security-block{border:1px solid var(--line);border-radius:11px;padding:16px;margin-bottom:14px}.security-block h4{margin:0 0 4px;color:var(--wine)}.security-block p{margin:0 0 14px;font-size:12px;color:var(--muted);line-height:1.45}.inline-actions{display:flex;gap:8px;align-items:flex-end}.inline-actions>div{flex:1}.inline-actions .btn{min-height:41px}.danger-zone{border-top:1px solid var(--line);margin-top:20px;padding-top:18px}
@media(max-width:900px){.layout{grid-template-columns:1fr}.intro{align-items:flex-start;flex-direction:column}.projects-grid{grid-template-columns:1fr}.row{grid-template-columns:1fr}.list-head{align-items:flex-start;flex-direction:column}.search{max-width:none}.inline-actions{flex-direction:column;align-items:stretch}.user-card{grid-template-columns:1fr}.manage{width:100%}}
</style></head><body>
<header><div><h1>Administração</h1><small>Usuários, obras e segurança • TERRAL CONTROLE DE OBRAS</small></div><a href="/">← Voltar às obras</a></header>
<main class="wrap">
  <div class="intro"><div><h2>Usuários e Acessos</h2><p>Crie acessos e controle quais obras cada login pode visualizar.</p></div><div class="stats"><span class="stat"><b id="sTotal">0</b> usuários</span><span class="stat"><b id="sActive">0</b> ativos</span><span class="stat"><b id="sAdmin">0</b> administrador(es)</span></div></div>
  <div class="layout">
    <section class="card"><h3>Criar novo acesso</h3><div class="hint">Depois de criar o login, clique em <b>Gerenciar</b> para liberar uma ou mais obras.</div>
      <form id="createForm"><label>Funcionário</label><select id="employee" required><option value="">Carregando...</option></select><label>Usuário</label><input id="username" required placeholder="NOME.SOBRENOME" autocomplete="off"><label>E-mail</label><input id="email" type="email" placeholder="nome@terral.com.br"><div class="row"><div><label>Senha inicial</label><input id="password" type="password" required minlength="4" autocomplete="new-password"></div><div><label>Tipo de acesso</label><select id="role"><option value="common">Comum</option><option value="admin">Administrador</option></select></div></div><button class="btn primary wide" type="submit">Criar usuário</button><div id="formMsg" class="msg"></div></form>
    </section>
    <section class="card"><div class="list-head"><div><h3>Usuários cadastrados</h3><div class="hint" style="margin:3px 0 0">Clique em Gerenciar para editar dados, obras e senha.</div></div><input id="search" class="search" placeholder="Buscar usuário, funcionário ou e-mail..."></div><div id="userList" class="user-list"><div class="empty">Carregando...</div></div></section>
  </div>
</main>

<div id="manageModal" class="modal"><div class="modalbox">
  <div class="modalhead"><div><h3 id="mName">Usuário</h3><p id="mUser">USUARIO</p></div><button class="close" type="button" onclick="closeManage()">×</button></div>
  <div class="tabs"><button class="tab active" data-tab="data" type="button">Dados</button><button class="tab" data-tab="projects" type="button">Obras liberadas</button><button class="tab" data-tab="security" type="button">Segurança</button></div>
  <div id="panel-data" class="panel active"><div class="section-title">Dados do acesso</div><div class="panel-note">Atualize e-mail, perfil e status deste login.</div><div class="row"><div><label>E-mail</label><input id="mEmail" type="email"></div><div><label>Tipo de acesso</label><select id="mRole"><option value="common">Comum</option><option value="admin">Administrador</option></select></div></div><label>Status</label><select id="mActive"><option value="1">Ativo</option><option value="0">Inativo</option></select><div class="actions-row"><button class="btn primary" type="button" onclick="saveData()">Salvar dados</button></div><div id="dataMsg" class="msg"></div><div class="danger-zone"><button id="deleteBtn" class="btn danger" type="button" onclick="deleteManaged()">Excluir acesso</button></div></div>
  <div id="panel-projects" class="panel"><div class="section-title">Obras liberadas</div><div class="panel-note">O usuário comum verá somente os cards marcados abaixo. Administradores enxergam todas as obras automaticamente.</div><div id="projectsGrid" class="projects-grid"></div><div class="actions-row"><button class="btn primary" type="button" onclick="saveProjects()">Salvar acessos às obras</button></div><div id="projectsMsg" class="msg"></div></div>
  <div id="panel-security" class="panel"><div class="section-title">Segurança</div><div class="panel-note">O Administrador pode redefinir a senha sem informar a senha antiga.</div><div class="security-block"><h4>Definir nova senha</h4><p>A nova senha passa a valer imediatamente e as sessões abertas desse usuário serão encerradas.</p><div class="row"><div><label>Nova senha</label><input id="newPass" type="password" minlength="4" autocomplete="new-password"></div><div><label>Confirmar nova senha</label><input id="newPass2" type="password" minlength="4" autocomplete="new-password"></div></div><div class="actions-row"><button class="btn primary" type="button" onclick="savePassword()">Alterar senha</button></div><div id="passMsg" class="msg"></div></div><div class="security-block"><h4>Recuperação por e-mail</h4><p>Envia um link de uso único, válido por 30 minutos, para o e-mail cadastrado do usuário.</p><div id="recoveryEmail" style="font-weight:800;font-size:13px;margin-bottom:12px">—</div><button class="btn outline" type="button" onclick="sendRecovery()">Enviar link de recuperação</button><div id="emailMsg" class="msg"></div></div></div>
</div></div>
<script>
let users=[],employees=[],projects=[],currentUser=null,managed=null,managedProjectIds=[];
const esc=s=>String(s??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
async function api(url,opt={}){const r=await fetch(url,opt);const d=await r.json().catch(()=>({}));if(r.status===401){location.href='/login';throw new Error('Sessão expirada');}if(!r.ok)throw new Error(d.error||'Erro na operação.');return d;}
function setMsg(id,text,ok){const e=document.getElementById(id);e.textContent=text;e.className='msg '+(ok?'ok':'err');}
function clearMsg(id){const e=document.getElementById(id);e.className='msg';e.textContent='';}
async function load(){const me=await api('/api/me');currentUser=me.user;employees=await api('/api/employees');employee.innerHTML='<option value="">Selecione o funcionário</option>'+employees.map(e=>'<option value="'+e.id+'">'+esc(e.name)+' — '+esc(e.role)+'</option>').join('');projects=(await api('/api/admin/projects')).items||[];await loadUsers();}
async function loadUsers(){users=(await api('/api/admin/users')).users||[];document.getElementById('sTotal').textContent=users.length;document.getElementById('sActive').textContent=users.filter(u=>Number(u.active)===1).length;document.getElementById('sAdmin').textContent=users.filter(u=>u.role==='admin').length;renderUsers();}
function renderUsers(){const q=search.value.toLowerCase().trim();const list=users.filter(u=>!q||[u.username,u.employee_name,u.email].some(v=>String(v||'').toLowerCase().includes(q)));userList.innerHTML=list.length?list.map(u=>'<div class="user-card"><div class="user-main"><div class="user-name">'+esc(u.employee_name||'Sem vínculo')+'</div><div class="user-meta">'+esc(u.username)+' • '+esc(u.email||'Sem e-mail cadastrado')+'</div><div class="badges"><span class="badge">'+(u.role==='admin'?'Administrador':'Comum')+'</span><span class="badge '+(Number(u.active)===1?'active':'off')+'">'+(Number(u.active)===1?'Ativo':'Inativo')+'</span></div></div><button class="manage" type="button" onclick="openManage('+u.id+')">Gerenciar</button></div>').join(''):'<div class="empty">Nenhum usuário encontrado.</div>';}
search.oninput=renderUsers;
createForm.onsubmit=async e=>{e.preventDefault();clearMsg('formMsg');try{await api('/api/admin/users',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({employee_id:Number(employee.value),username:username.value,email:email.value,password:password.value,role:role.value})});setMsg('formMsg','Usuário criado com sucesso. Agora use Gerenciar para liberar as obras.',true);createForm.reset();await loadUsers();}catch(err){setMsg('formMsg',err.message,false);}};
async function openManage(id){managed=users.find(u=>Number(u.id)===Number(id));if(!managed)return;mName.textContent=managed.employee_name||managed.username;mUser.textContent=managed.username;mEmail.value=managed.email||'';mRole.value=managed.role;mActive.value=String(Number(managed.active));recoveryEmail.textContent=managed.email||'Nenhum e-mail cadastrado';deleteBtn.style.display=Number(managed.id)===Number(currentUser.id)?'none':'inline-block';clearMsg('dataMsg');clearMsg('projectsMsg');clearMsg('passMsg');clearMsg('emailMsg');newPass.value='';newPass2.value='';await loadManagedProjects();switchTab('data');manageModal.classList.add('open');}
function closeManage(){manageModal.classList.remove('open');managed=null;}
function switchTab(name){document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===name));document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('active',p.id==='panel-'+name));}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>switchTab(b.dataset.tab));manageModal.addEventListener('click',e=>{if(e.target===manageModal)closeManage()});
async function loadManagedProjects(){if(!managed)return;const d=await api('/api/admin/users/'+managed.id+'/projects');managedProjectIds=(d.project_ids||[]).map(Number);renderProjectChecks();}
function renderProjectChecks(){projectsGrid.innerHTML=projects.map(p=>'<label class="project-check"><input type="checkbox" value="'+p.id+'" '+(managedProjectIds.includes(Number(p.id))?'checked':'')+' '+(managed&&managed.role==='admin'?'disabled':'')+'><span>'+esc(p.name)+'</span></label>').join('')+(managed&&managed.role==='admin'?'<div class="panel-note" style="grid-column:1/-1;margin:4px 0 0">Administrador tem acesso automático a todas as obras.</div>':'');}
async function saveProjects(){if(!managed)return;clearMsg('projectsMsg');try{const ids=[...projectsGrid.querySelectorAll('input[type=checkbox]:checked')].map(x=>Number(x.value));await api('/api/admin/users/'+managed.id+'/projects',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({project_ids:ids})});managedProjectIds=ids;setMsg('projectsMsg','Acessos às obras atualizados.',true);}catch(e){setMsg('projectsMsg',e.message,false);}}
async function saveData(){if(!managed)return;clearMsg('dataMsg');try{await api('/api/admin/users/'+managed.id,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({email:mEmail.value.trim(),role:mRole.value,active:Number(mActive.value)})});setMsg('dataMsg','Dados atualizados.',true);await loadUsers();managed=users.find(u=>Number(u.id)===Number(managed.id));if(managed){recoveryEmail.textContent=managed.email||'Nenhum e-mail cadastrado';renderProjectChecks();}}catch(e){setMsg('dataMsg',e.message,false);}}
async function savePassword(){if(!managed)return;clearMsg('passMsg');if(newPass.value.length<4)return setMsg('passMsg','A senha deve ter pelo menos 4 caracteres.',false);if(newPass.value!==newPass2.value)return setMsg('passMsg','As senhas não conferem.',false);try{await api('/api/admin/users/'+managed.id+'/password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:newPass.value})});newPass.value='';newPass2.value='';setMsg('passMsg','Senha alterada com sucesso.',true);}catch(e){setMsg('passMsg',e.message,false);}}
async function sendRecovery(){if(!managed)return;clearMsg('emailMsg');if(!managed.email)return setMsg('emailMsg','Cadastre um e-mail antes de enviar a recuperação.',false);try{await api('/api/admin/users/'+managed.id+'/send-reset',{method:'POST'});setMsg('emailMsg','E-mail de recuperação enviado para '+managed.email+'.',true);}catch(e){setMsg('emailMsg',e.message,false);}}
async function deleteManaged(){if(!managed||Number(managed.id)===Number(currentUser.id))return;if(!confirm('Excluir o acesso de '+managed.username+'?'))return;try{await api('/api/admin/users/'+managed.id,{method:'DELETE'});closeManage();await loadUsers();}catch(e){alert(e.message);}}
load().catch(e=>userList.innerHTML='<div class="empty">'+esc(e.message)+'</div>');
</script></body></html>`;
}

function normalizePersonName(value){
  return String(value||"").normalize("NFD").replace(/[\u0300-\u036f]/g,"").toUpperCase().replace(/[^A-Z0-9]+/g," ").trim().replace(/\s+/g," ");
}
async function ensureTimeImportSchema(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS time_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT, competence TEXT NOT NULL UNIQUE,
    file_name TEXT NOT NULL DEFAULT '', file_size INTEGER NOT NULL DEFAULT 0,
    page_count INTEGER NOT NULL DEFAULT 0, employee_count INTEGER NOT NULL DEFAULT 0,
    matched_count INTEGER NOT NULL DEFAULT 0, unmatched_count INTEGER NOT NULL DEFAULT 0,
    imported_by_user_id INTEGER NOT NULL, imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (imported_by_user_id) REFERENCES users(id)
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS monthly_time_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT, import_id INTEGER NOT NULL, employee_id INTEGER NOT NULL,
    competence TEXT NOT NULL, source_name TEXT NOT NULL DEFAULT '', source_registration TEXT NOT NULL DEFAULT '',
    extra50_minutes INTEGER NOT NULL DEFAULT 0, extra100_minutes INTEGER NOT NULL DEFAULT 0,
    absence_count INTEGER NOT NULL DEFAULT 0, medical_count INTEGER NOT NULL DEFAULT 0,
    delay_minutes INTEGER NOT NULL DEFAULT 0, night_minutes INTEGER NOT NULL DEFAULT 0,
    bank_minutes INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(employee_id, competence), FOREIGN KEY (import_id) REFERENCES time_imports(id),
    FOREIGN KEY (employee_id) REFERENCES employees(id)
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_time_summary_competence ON monthly_time_summary(competence)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_time_summary_employee ON monthly_time_summary(employee_id)").run();
}


function pointPage(auth){
return String.raw`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TERRAL | CARTÃO DE PONTO</title><link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAACc0lEQVR4nO3cPU7DYBAGYYOoQEpJyw24Freg4IgcgzIStFCgSEYkIXbifRfPPBfA3+5g50fK1dPw8DkI6zp9AcoyADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAu0lfwCH3t5v0JVzc28c2fQm/tApgjUsfG5+vSwwtAlj74vfZnTkdQvw1AHH5Y+nzRwNIH76L5BxiAbj8n1LziATg8vdLzKU8AJd/XPV8SgNw+aepnFNZAC5/mqp5xd8GKqskAP/756mYW4tPAo95eX9NX8LZnu8e05dwUOtHwBqWPwy9z7F4AHNvY52HNsfc8yz9GGh9B9DyDADOAOAMAM4A4AwAzgDgDADOAODaBtD58/M5up6nbQDD0HdoU3U+R/tvAy8xvHO+V+i8vEtofQfQ8gwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDABu8QDePrZL/4k/zf2xxw4/Ern0/DB3gKnL7LD8Cu1/KvaSKEudouQO0OEx8B9VzA3zCNB+ZQF4F5imal6ldwAjOE3lnMofAUZwXPV8Iq8BjGC/xFxiLwKN4KfUPKLvAozgW3IO8beB9AjS52/xSeBuCPe3m/CV1EkvfqdFADvjoawxhi5LH2sVwFjHYa1R/DWAsgwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADuC1o5ZrPxplRWAAAAAElFTkSuQmCC">
<style>
:root{--wine:#690020;--wine2:#8a1237;--wine3:#5b001a;--bg:#f3f4f6;--text:#202631;--muted:#6d7480;--line:#e4e7eb;--green:#167c43;--red:#b42318;--amber:#a15c00}*{box-sizing:border-box}body{margin:0;background:var(--bg);font-family:Arial,Helvetica,sans-serif;color:var(--text)}header{background:linear-gradient(90deg,var(--wine3),var(--wine2));color:#fff;padding:16px 28px;display:flex;align-items:center;justify-content:space-between;gap:15px}header h1{font-size:20px;margin:0}header small{opacity:.9}header a{color:#fff;text-decoration:none;font-weight:700}.wrap{max-width:1200px;margin:27px auto;padding:0 20px}.toprow{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:18px;flex-wrap:wrap}.toprow h2{font-size:28px;margin:0 0 5px}.toprow p{margin:0;color:var(--muted)}.card{background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:0 8px 27px #0f172a0d;padding:20px;margin-bottom:17px}.card h3{margin:0 0 5px;color:var(--wine)}.hint{font-size:12px;color:var(--muted);line-height:1.5}.filters select{padding:10px 12px;border:1px solid #ccd2d9;border-radius:8px;background:#fff}.btn{border:0;border-radius:8px;padding:10px 14px;font-weight:800;cursor:pointer}.primary{background:linear-gradient(90deg,#5d001b,var(--wine2));color:#fff}.ghost{background:#f0f2f4;color:#28303a}.danger{background:#fff0f0;color:var(--red)}.upload{border:2px dashed #c9b1ba;border-radius:13px;padding:30px;text-align:center;background:#fcfafb;display:block;cursor:pointer!important;user-select:none;transition:.15s}.upload:hover{border-color:#8a1237;background:#fbf4f7}.upload.drag{border-color:#690020!important;background:#f7e9ef!important;box-shadow:0 0 0 3px rgba(105,0,32,.08)}.upload-button{display:inline-block}.upload.drag{border-color:var(--wine);background:#f8eef2}.upload strong{display:block;font-size:18px;color:var(--wine);margin-bottom:6px}.upload input{display:none}.progress{height:8px;background:#eee;border-radius:99px;overflow:hidden;margin-top:13px;display:none}.progress span{display:block;height:100%;width:0;background:var(--wine)}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:15px 0}.metric{border:1px solid var(--line);border-radius:10px;padding:12px;background:#fafafa}.metric small{color:var(--muted);display:block}.metric b{font-size:20px;color:var(--wine)}table{width:100%;border-collapse:collapse}th,td{padding:10px 9px;border-bottom:1px solid var(--line);text-align:left;font-size:12px}th{background:#fafafb;text-transform:uppercase;font-size:10px;color:#6b7280}.ok{color:var(--green);font-weight:800}.warn{color:var(--amber);font-weight:800}.scroll{overflow:auto}.pill{display:inline-block;border-radius:999px;padding:4px 7px;background:#f3e7ec;color:var(--wine);font-size:10px;font-weight:800}select.map{max-width:240px;padding:7px;border:1px solid #cfd4da;border-radius:7px}.admin-only{display:none}.is-admin .admin-only{display:block}.msg{display:none;margin-top:12px;padding:11px;border-radius:8px;font-size:13px}.msg.show{display:block}.msg.success{background:#eff9f2;color:#13733d;border:1px solid #b7ddc2}.msg.error{background:#fff0f1;color:#a61b32;border:1px solid #f3c7cf}.history-row{display:grid;grid-template-columns:130px 1fr 160px 110px;gap:10px;padding:11px 0;border-bottom:1px solid var(--line);align-items:center;font-size:13px}.summary-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:9px;margin:14px 0}.sum{background:#fafafa;border:1px solid var(--line);border-radius:9px;padding:11px}.sum small{display:block;color:var(--muted);font-size:10px}.sum b{display:block;margin-top:4px;color:var(--wine);font-size:17px}@media(max-width:800px){.metrics,.summary-grid{grid-template-columns:1fr 1fr}.history-row{grid-template-columns:1fr}.wrap{padding:0 12px}}
button,a,select,label,.module,.user-btn,.menu-link,.menu-action,.btn,.upload,.emp-card{cursor:pointer!important}button *,a *,label *,.module *,.user-btn *,.menu-link *,.menu-action *,.btn *,.upload *,.emp-card *{cursor:pointer!important}button,button *,a,a *,select,select *,label,label *,.module,.module *,.user-btn,.user-btn *,.menu-link,.menu-link *,.menu-action,.menu-action *,.btn,.btn *,.upload,.upload *,.emp-card,.emp-card *{cursor:pointer!important}</style></head><body class="${auth && auth.role==='admin' ? 'is-admin' : '' }">
<header><div><h1>Cartão de Ponto</h1><small>EMIRATES PARQUE FLAMBOYANT</small></div><a href="/">← Voltar ao painel</a></header><main class="wrap">
<div class="toprow"><div><h2>Cartão de Ponto</h2><p>Consulta mensal e importação do cartão de ponto.</p></div><div class="filters"><label>Competência <select id="competence"><option value="">Selecione</option></select></label></div></div>
<section id="adminImport" class="card admin-only"><h3>Importar PDF do cartão de ponto</h3><div class="hint">Somente Administrador. O PDF é lido localmente; ao confirmar, apenas os resultados são gravados no D1.</div><label id="drop" class="upload" for="file" style="margin-top:14px"><strong>Arraste o PDF aqui</strong><span>ou clique em qualquer lugar desta área para selecionar.</span><br><br><span class="btn primary upload-button">Selecionar PDF</span><input id="file" type="file" accept="application/pdf,.pdf"><div id="fileName" class="hint" style="margin-top:12px"></div><div id="progress" class="progress"><span id="bar"></span></div></label>
<div id="importMetrics" class="metrics" style="display:none"><div class="metric"><small>Competência</small><b id="mComp">—</b></div><div class="metric"><small>Páginas lidas</small><b id="mPages">0</b></div><div class="metric"><small>Encontrados</small><b id="mMatched">0</b></div><div class="metric"><small>Conferir</small><b id="mUnmatched">0</b></div></div>
<div id="previewWrap" style="display:none"><h3 style="margin-top:18px">Prévia da leitura</h3><div class="hint">Não encontrados podem ser vinculados manualmente ou ignorados.</div><div class="scroll"><table><thead><tr><th>Funcionário no PDF</th><th>Matrícula</th><th>HE 50%</th><th>HE 100%</th><th>Faltas</th><th>Atestados</th><th>Atrasos</th><th>Status / vínculo</th></tr></thead><tbody id="preview"></tbody></table></div><div style="display:flex;justify-content:flex-end;gap:8px;margin-top:14px"><button id="clearBtn" class="btn ghost" type="button">Limpar</button><button id="confirmBtn" class="btn primary" type="button">Confirmar importação</button></div></div><div id="importMsg" class="msg"></div></section>
<section class="card"><h3>Resumo da competência</h3><div class="hint">Faltas e atestados seguem a quantidade registrada no resumo do próprio cartão.</div><div class="summary-grid"><div class="sum"><small>HE 50%</small><b id="tot50">0h00</b></div><div class="sum"><small>HE 100%</small><b id="tot100">0h00</b></div><div class="sum"><small>Faltas</small><b id="totF">0</b></div><div class="sum"><small>Atestados</small><b id="totA">0</b></div><div class="sum"><small>Atrasos</small><b id="totD">0h00</b></div><div class="sum"><small>Adic. noturno</small><b id="totN">0h00</b></div></div><div class="scroll"><table><thead><tr><th>Funcionário</th><th>Função</th><th>HE 50%</th><th>HE 100%</th><th>Faltas</th><th>Atestados</th><th>Atrasos</th><th>Adic. noturno</th></tr></thead><tbody id="summaryRows"><tr><td colspan="8">Selecione uma competência.</td></tr></tbody></table></div></section>
<section id="historyCard" class="card admin-only"><h3>Histórico de importações</h3><div class="hint">Guarda competência, nome do arquivo, data e responsável. O PDF original não é armazenado nesta versão.</div><div id="history"></div></section></main>
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script type="module">
const $=id=>document.getElementById(id);
console.log("TERRAL_CARTAO_PONTO_JS_OK");let me=null,employees=[],parsedRows=[],selectedFile=null;
const normalize=s=>String(s||"").normalize("NFD").replace(/[\u0300-\u036f]/g,"").toUpperCase().replace(/[^A-Z0-9]+/g," ").trim().replace(/\s+/g," ");
const hm=m=>{m=Number(m||0);return Math.floor(m/60)+"h"+String(m%60).padStart(2,"0")};
const esc=s=>String(s??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
const months={janeiro:"01",fevereiro:"02",março:"03",marco:"03",abril:"04",maio:"05",junho:"06",julho:"07",agosto:"08",setembro:"09",outubro:"10",novembro:"11",dezembro:"12"};
const showMsg=(t,ok=false)=>{const e=$("importMsg");e.textContent=t;e.className="msg show "+(ok?"success":"error")};
async function api(url,opt={}){const r=await fetch(url,{headers:{"content-type":"application/json",...(opt.headers||{})},...opt}),d=await r.json().catch(()=>({}));if(!r.ok){const e=new Error(d.error||"Erro na operação.");e.status=r.status;e.data=d;throw e}return d}
const formatComp=c=>{if(!c)return "—";const [y,m]=c.split("-");return m+"/"+y};
async function init(){const d=await api("/api/me");me=d.user;employees=await api("/api/employees");if(me.role==="admin")document.querySelectorAll(".admin-only").forEach(x=>x.style.display="block");await loadCompetences();if(me.role==="admin")await loadHistory()}
async function loadCompetences(){const d=await api("/api/time/competences"),old=$("competence").value;$("competence").innerHTML='<option value="">Selecione</option>'+d.items.map(x=>'<option value="'+x.competence+'">'+formatComp(x.competence)+'</option>').join("");if(old&&d.items.some(x=>x.competence===old))$("competence").value=old;else if(d.items[0])$("competence").value=d.items[0].competence;if($("competence").value)await loadSummary()}
$("competence").onchange=loadSummary;
async function loadSummary(){const c=$("competence").value;if(!c){$("summaryRows").innerHTML='<tr><td colspan="8">Selecione uma competência.</td></tr>';return}const d=await api("/api/time/summary?competence="+encodeURIComponent(c)),rows=d.items||[];$("summaryRows").innerHTML=rows.length?rows.map(r=>'<tr><td><b>'+esc(r.name)+'</b></td><td>'+esc(r.role)+'</td><td>'+hm(r.extra50_minutes)+'</td><td>'+hm(r.extra100_minutes)+'</td><td>'+r.absence_count+'</td><td>'+r.medical_count+'</td><td>'+hm(r.delay_minutes)+'</td><td>'+hm(r.night_minutes)+'</td></tr>').join(""):'<tr><td colspan="8">Nenhum dado importado.</td></tr>';const sum=k=>rows.reduce((a,r)=>a+Number(r[k]||0),0);$("tot50").textContent=hm(sum("extra50_minutes"));$("tot100").textContent=hm(sum("extra100_minutes"));$("totF").textContent=sum("absence_count");$("totA").textContent=sum("medical_count");$("totD").textContent=hm(sum("delay_minutes"));$("totN").textContent=hm(sum("night_minutes"))}
async function loadHistory(){const d=await api("/api/admin/time-imports");$("history").innerHTML=(d.items||[]).length?d.items.map(x=>'<div class="history-row"><b>'+formatComp(x.competence)+'</b><div><b>'+esc(x.file_name)+'</b><br><span class="hint">'+x.matched_count+' vinculados • '+x.unmatched_count+' ignorados</span></div><div>'+esc(x.imported_by)+'<br><span class="hint">'+esc(x.imported_at)+'</span></div><button class="btn danger" data-del="'+x.id+'">Excluir</button></div>').join(""):'<div class="hint" style="padding:12px 0">Nenhuma importação.</div>';document.querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{if(!confirm("Excluir esta competência e seus resumos?"))return;await api("/api/admin/time-imports/"+b.dataset.del,{method:"DELETE"});await loadHistory();await loadCompetences()})}
function receiveFile(f){
  if(!f)return showMsg("Nenhum arquivo foi recebido.");
  $("fileName").innerHTML="<b>Arquivo recebido:</b> "+esc(f.name)+" • "+(f.size/1024).toFixed(0)+" KB";
  requestAnimationFrame(()=>readPdf(f));
}
$("file").addEventListener("change",e=>receiveFile(e.target.files&&e.target.files[0]));
const drop=$("drop");
["dragenter","dragover"].forEach(type=>drop.addEventListener(type,e=>{e.preventDefault();e.stopPropagation();drop.classList.add("drag");e.dataTransfer.dropEffect="copy"}));
["dragleave","dragend"].forEach(type=>drop.addEventListener(type,e=>{e.preventDefault();e.stopPropagation();drop.classList.remove("drag")}));
drop.addEventListener("drop",e=>{e.preventDefault();e.stopPropagation();drop.classList.remove("drag");receiveFile(e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0])});
window.addEventListener("dragover",e=>e.preventDefault(),false);
window.addEventListener("drop",e=>e.preventDefault(),false);
$("clearBtn").onclick=clearImport;
async function getPdfJs(){
  const lib=window.pdfjsLib;
  if(!lib)throw new Error("A biblioteca de leitura do PDF não carregou. Atualize a página e tente novamente.");
  lib.GlobalWorkerOptions.workerSrc="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
  return lib;
}
async function pageText(page){
  const tc=await page.getTextContent();
  const flow=[];
  const groups=[];
  for(const item of tc.items){
    if(!item.str)continue;
    flow.push(item.str);
    if(item.hasEOL)flow.push("\n");
    const y=Math.round(item.transform[5]*2)/2;
    const x=item.transform[4];
    let g=groups.find(a=>Math.abs(a.y-y)<=1.5);
    if(!g){g={y,items:[]};groups.push(g)}
    g.items.push({x,str:item.str});
  }
  groups.sort((a,b)=>b.y-a.y);
  const visual=groups.map(g=>g.items.sort((a,b)=>a.x-b.x).map(i=>i.str).join(" "));
  return flow.join(" ")+"\n"+visual.join("\n");
}
const val=(t,re)=>{const m=t.match(re);return m?m[1]:null},toMin=v=>{if(!v)return 0;const [h,m]=v.split(":").map(Number);return h*60+m},toCount=v=>{if(!v)return 0;const [h,m]=v.split(":").map(Number);return Math.round(h+(m||0)/60)};
function parsePointPage(t){
  const rx=(source)=>new RegExp(source,"i");
  const clean=String(t||"").replace(/\u00a0/g," ").replace(/\s+/g," ").trim();

  const name=val(clean,rx("Funcionario\\s*:\\s*(.*?)\\s+Categoria\\s+de\\s+Ponto"));
  if(!name)return null;

  const registration=val(clean,rx("Matricula\\s*:\\s*([0-9A-Za-z.-]+)"))||"";
  const cm=clean.match(rx("Mes\\s*/\\s*Ano\\s+Competencia\\s*:\\s*([A-Za-zÀ-ÿ]+)\\s*/\\s*(\\d{4})"));
  const competence=cm?(cm[2]+"-"+(months[cm[1].toLowerCase()]||"")):"";

  const getTime=(code,label)=>{
    const mm=clean.match(rx(code+"\\s+"+label+"\\s*=\\s*(\\d{1,3}:\\d{2})"));
    return mm?mm[1]:null;
  };

  return {
    source_name:name.trim(),
    source_registration:registration.trim(),
    competence,
    extra50_minutes:toMin(getTime("00207","HORA\\s+EXTRA\\s+50%")),
    extra100_minutes:toMin(getTime("00208","HORA\\s+EXTRA\\s+100%")),
    absence_count:toCount(getTime("00152","FALTAS")),
    medical_count:toCount(getTime("00239","ATESTADO\\s+MEDICO")),
    delay_minutes:toMin(getTime("00164","ATRASOS\\s+FALTAS")),
    night_minutes:toMin(getTime("00806","ADICIONAL\\s+NOTURNO")),
    bank_minutes:toMin(val(clean,rx("Banco\\s+de\\s+Horas\\s*:\\s*(\\d{1,3}:\\d{2})"))),
    employee_id:null
  };
}
async function readPdf(file){
if(!me||me.role!=="admin"){showMsg("Sua sessão não foi reconhecida como Administrador. Atualize a página.");return}
if(!file||!file.name.toLowerCase().endsWith(".pdf"))return showMsg("Selecione um arquivo PDF.");
selectedFile=file;parsedRows=[];
$("fileName").innerHTML="<b>Arquivo recebido:</b> "+esc(file.name)+" • "+(file.size/1024).toFixed(0)+" KB<br><span style=\"color:#690020;font-weight:700\">Lendo o PDF...</span>";
$("progress").style.display="block";$("bar").style.width="4%";$("previewWrap").style.display="none";$("importMetrics").style.display="none";try{const pdfjs=await getPdfJs(),data=await file.arrayBuffer(),pdf=await pdfjs.getDocument({data}).promise;for(let i=1;i<=pdf.numPages;i++){
    const raw=await pageText(await pdf.getPage(i));
    if(i===1)window.__terralPdfSample=String(raw||"").replace(/\s+/g," ").trim();
    const row=parsePointPage(raw);
    if(row)parsedRows.push(row);
    $("bar").style.width=Math.round(i/pdf.numPages*100)+"%";
  }if(!parsedRows.length){
    const sample=window.__terralPdfSample||"";
    throw new Error("Não encontrei cartões no PDF."+(sample?" Texto lido: "+sample.slice(0,180):""));
  }const comps=[...new Set(parsedRows.map(r=>r.competence).filter(Boolean))];if(comps.length!==1)throw new Error("Não foi possível identificar uma competência única.");parsedRows.forEach(matchRow);$("mComp").textContent=formatComp(comps[0]);$("mPages").textContent=pdf.numPages;renderPreview();$("importMetrics").style.display="grid";$("previewWrap").style.display="block";$("bar").style.width="100%"}catch(e){
  console.error("PDF_READ_ERROR",e);
  showMsg("Não consegui ler o PDF: "+e.message);
  $("progress").style.display="none";
  if(selectedFile)$("fileName").innerHTML="<b>Arquivo selecionado:</b> "+esc(selectedFile.name)+"<br><span style=\"color:#b42318\">A leitura não foi concluída.</span>";
}}
function matchRow(r){let e=employees.find(x=>r.source_registration&&String(x.registration||"")===r.source_registration);if(!e)e=employees.find(x=>normalize(x.name)===normalize(r.source_name));if(e)r.employee_id=Number(e.id)}
function renderPreview(){const matched=parsedRows.filter(r=>r.employee_id).length;$("mMatched").textContent=matched;$("mUnmatched").textContent=parsedRows.length-matched;const opts='<option value="">Ignorar este registro</option>'+employees.map(e=>'<option value="'+e.id+'">'+esc(e.name)+'</option>').join("");$("preview").innerHTML=parsedRows.map((r,i)=>'<tr><td><b>'+esc(r.source_name)+'</b></td><td>'+esc(r.source_registration)+'</td><td>'+hm(r.extra50_minutes)+'</td><td>'+hm(r.extra100_minutes)+'</td><td>'+r.absence_count+'</td><td>'+r.medical_count+'</td><td>'+hm(r.delay_minutes)+'</td><td>'+(r.employee_id?'<span class="ok">✓ Encontrado</span> <span class="pill">'+esc((employees.find(e=>Number(e.id)===Number(r.employee_id))||{}).name||"")+'</span>':'<span class="warn">⚠ Conferir</span><br><select class="map" data-map="'+i+'">'+opts+'</select>')+'</td></tr>').join("");document.querySelectorAll("[data-map]").forEach(s=>s.onchange=()=>{parsedRows[Number(s.dataset.map)].employee_id=s.value?Number(s.value):null;renderPreview()})}
function clearImport(){selectedFile=null;parsedRows=[];$("file").value="";$("fileName").textContent="";$("previewWrap").style.display="none";$("importMetrics").style.display="none";$("progress").style.display="none"}
$("confirmBtn").onclick=async()=>{if(!selectedFile||!parsedRows.length)return;const comp=parsedRows[0].competence,payload={competence:comp,file_name:selectedFile.name,file_size:selectedFile.size,page_count:parsedRows.length,rows:parsedRows.map(r=>({...r,skip:!r.employee_id}))};try{await api("/api/admin/time-import",{method:"POST",body:JSON.stringify(payload)});showMsg("Importação concluída com sucesso.",true);clearImport();await loadCompetences();await loadHistory();$("competence").value=comp;await loadSummary()}catch(e){if(e.status===409&&e.data&&e.data.exists&&confirm("Já existe uma importação para "+formatComp(comp)+". Deseja substituir?")){payload.replace=true;try{await api("/api/admin/time-import",{method:"POST",body:JSON.stringify(payload)});showMsg("Competência substituída com sucesso.",true);clearImport();await loadCompetences();await loadHistory();$("competence").value=comp;await loadSummary()}catch(x){showMsg(x.message)}}else showMsg(e.message)}};
if(!window.pdfjsLib){showMsg("Leitor de PDF não carregado. Atualize a página após o deploy.");}
init().catch(e=>{console.error(e);alert(e.message)});
</script></body></html>`;
}


const TERRAL_PROJECTS = [
  {slug:"ambiente-terral",name:"AMBIENTE TERRAL",image:"/ambiente-terral.jpg",sort_order:1},
  {slug:"serrano",name:"SERRANO",image:"/serrano-terral.jpg",sort_order:2},
  {slug:"aero17",name:"AERO17",image:"/aero17-terral.jpg",sort_order:3},
  {slug:"ita-marista",name:"ITÁ MARISTA",image:"/itamarista-terral.jpg",sort_order:4},
  {slug:"alameda-areiao",name:"ALAMEDA AREIÃO",image:"alameda-terral",sort_order:5},
  {slug:"casa-conceito-praca-do-sol",name:"CASA CONCEITO — PRAÇA DO SOL",image:"",sort_order:6},
  {slug:"origyn-bueno",name:"ORIGYN BUENO",image:"",sort_order:7},
  {slug:"hype-vaca-brava",name:"HYPE VACA BRAVA",image:"",sort_order:8},
  {slug:"emirates-parque-flamboyant",name:"EMIRATES PARQUE FLAMBOYANT",image:"",sort_order:9}
];

async function ensureProjectsSchema(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    image_path TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS user_projects (
    user_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, project_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (project_id) REFERENCES projects(id)
  )`).run();

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS system_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
  )`).run();

  const projectStmts=TERRAL_PROJECTS.map(p=>env.DB.prepare(
    `INSERT INTO projects (slug,name,image_path,active,sort_order)
     VALUES (?,?,?,?,?)
     ON CONFLICT(slug) DO UPDATE SET
       name=excluded.name,image_path=excluded.image_path,active=excluded.active,sort_order=excluded.sort_order`
  ).bind(p.slug,p.name,p.image,1,p.sort_order));
  if(projectStmts.length)await env.DB.batch(projectStmts);

  // One-time bootstrap: preserve the current system for all existing common users
  // by granting Emirates. After this marker is created, permissions are fully manual.
  const boot=await env.DB.prepare("SELECT value FROM system_meta WHERE key='projects_bootstrap_v1'").first();
  if(!boot){
    const emirates=await env.DB.prepare("SELECT id FROM projects WHERE slug='emirates-parque-flamboyant'").first();
    if(emirates){
      await env.DB.prepare(`INSERT OR IGNORE INTO user_projects(user_id,project_id)
        SELECT id,? FROM users WHERE active=1 AND role<>'admin'`).bind(emirates.id).run();
    }
    await env.DB.prepare("INSERT OR REPLACE INTO system_meta(key,value) VALUES('projects_bootstrap_v1','done')").run();
  }
}

async function hasProjectAccess(env,auth,slug){
  if(!auth)return false;
  if(auth.role==="admin")return true;
  await ensureProjectsSchema(env);
  const row=await env.DB.prepare(`SELECT 1 ok
    FROM user_projects up
    JOIN projects p ON p.id=up.project_id
    WHERE up.user_id=? AND p.slug=? AND p.active=1 LIMIT 1`).bind(auth.id,slug).first();
  return !!row;
}

function worksPage(){
return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TERRAL | CONTROLE DE OBRAS</title>
<link rel="icon" type="image/svg+xml" href="/favicon-terral-t.svg">
<style>
:root{--wine:#681522;--wine-2:#7e2433;--wine-3:#54111b;--cream:#f7f1e8;--card:#fffdfa;--text:#311f21;--muted:#766f69;--line:#e9dfd4;--shadow:0 8px 24px rgba(71,35,30,.12)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Arial,Helvetica,sans-serif;background:var(--cream);color:var(--text)}body{min-height:100vh}a,button{font:inherit}button,a,.nav-item,.project-card,.access-btn,.user-menu-btn{cursor:pointer!important}
.app{min-height:100vh;display:grid;grid-template-columns:210px 1fr}
.sidebar{position:fixed;inset:0 auto 0 0;width:210px;height:100vh;background:linear-gradient(180deg,#6c0f21 0%,#59101a 100%);color:#fff;display:flex;flex-direction:column;z-index:20;box-shadow:4px 0 18px rgba(60,18,24,.12)}
.brand{height:145px;display:flex;align-items:center;justify-content:center;padding:24px 20px;background:#6c0f21;border-bottom:1px solid rgba(255,255,255,.08)}
.brand img{width:170px;max-width:100%;height:auto;object-fit:contain;display:block}
.nav{padding:28px 16px;display:flex;flex-direction:column;gap:14px}.nav-item{min-height:76px;border:0;border-radius:11px;background:transparent;color:white;display:flex;align-items:center;gap:18px;padding:0 20px;text-decoration:none;font-size:15px;font-weight:700;transition:.18s}.nav-item:hover{background:rgba(255,255,255,.08)}.nav-item.active{background:#96505b}.nav-icon{width:32px;height:32px;display:grid;place-items:center;flex:0 0 32px}.nav-icon svg{width:29px;height:29px;stroke:currentColor;fill:none;stroke-width:1.8}.nav-spacer{flex:1}.logout{margin:0 18px 24px;padding-top:22px;border-top:1px solid rgba(255,255,255,.28)}.logout .nav-item{width:100%}
.main{grid-column:2;padding:34px 42px 34px;min-width:0}.top{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:30px}.title-wrap{display:flex;align-items:flex-start;gap:18px}.title-icon{width:44px;height:44px;display:grid;place-items:center;color:var(--wine);margin-top:2px}.title-icon svg{width:39px;height:39px;stroke:currentColor;fill:none;stroke-width:1.7}.title h1{margin:0;color:var(--wine);font-size:38px;line-height:1.08;letter-spacing:-.7px}.title p{margin:8px 0 0;color:#625b56;font-size:17px}
.user{position:relative;display:flex;align-items:center;gap:12px;padding-top:4px}.user-ico{width:34px;height:34px;display:grid;place-items:center;color:var(--wine)}.user-ico svg{width:30px;height:30px;stroke:currentColor;fill:none;stroke-width:1.7}.user-text strong{display:block;font-size:15px}.user-text small{display:block;color:#77706b;margin-top:3px;font-size:13px}.user-menu-btn{border:0;background:transparent;color:#2f2926;font-size:18px;padding:8px 10px}.user-menu{display:none;position:absolute;right:0;top:48px;width:215px;background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 14px 38px rgba(57,24,24,.18);overflow:hidden;z-index:30}.user-menu.open{display:block}.user-menu a,.user-menu button{display:block;width:100%;border:0;background:#fff;text-align:left;padding:12px 14px;text-decoration:none;color:#322f2d}.user-menu a:hover,.user-menu button:hover{background:#faf5f0}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:22px 24px}.project-card{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:var(--shadow);transition:transform .18s,box-shadow .18s}.project-card:hover{transform:translateY(-3px);box-shadow:0 14px 30px rgba(71,35,30,.16)}.image-wrap{height:180px;background:linear-gradient(135deg,#eee7df,#e2d9cf);overflow:hidden;position:relative}.image-wrap img{width:100%;height:100%;object-fit:cover;display:block;transition:transform .28s}.image-placeholder{width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#9b9088;font-size:12px;font-weight:700;letter-spacing:.7px;text-transform:uppercase}.project-card:hover .image-wrap img{transform:scale(1.02)}
.card-body{min-height:77px;padding:15px 18px;display:flex;align-items:center;justify-content:space-between;gap:14px}.project-name{color:var(--wine);font-weight:800;font-size:14px;line-height:1.2;letter-spacing:.05px;text-transform:uppercase;max-width:70%}.access-btn{flex:0 0 auto;border:0;border-radius:7px;background:linear-gradient(100deg,#5d111d,#7b1d2c);color:#fff;padding:11px 16px;font-weight:800;text-decoration:none;white-space:nowrap;box-shadow:0 3px 8px rgba(93,17,29,.14)}.access-btn:hover{filter:brightness(1.06)}
.empty{grid-column:1/-1;background:white;border:1px solid var(--line);border-radius:14px;padding:28px;text-align:center;color:var(--muted)}
@media(max-width:1450px){.grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:1050px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:820px){.app{display:block}.sidebar{position:static;width:100%;height:auto;flex-direction:row;align-items:center}.brand{width:170px;height:85px;padding:14px}.nav{flex:1;flex-direction:row;padding:10px;overflow:auto}.nav-item{min-width:95px;min-height:62px;padding:0 12px;justify-content:center;gap:8px}.nav-spacer,.logout{display:none}.main{padding:24px 16px}.top{align-items:flex-start}.title h1{font-size:29px}.title p{font-size:15px}.user-text{display:none}.grid{grid-template-columns:1fr}.image-wrap{height:220px}}
</style></head>
<body>
<div class="app">
<aside class="sidebar">
  <div class="brand"><img src="/terral_logo_transparente.png" onerror="this.onerror=null;this.src='/terral_logo.png'" alt="Terral Incorporadora"></div>
  <nav class="nav">
    <a class="nav-item" href="/"><span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10.5V21h13V10.5"/><path d="M9.5 21v-6h5v6"/></svg></span><span>Início</span></a>
    <a class="nav-item active" href="/"><span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M4 20h16"/><path d="M7 20V8h7"/><path d="M11 8V4h7v4"/><path d="M15 4V2"/><path d="M18 4V2"/><path d="M14 8h6"/><path d="M18 8v12"/><path d="M7 12h11"/><path d="M9 12v8"/></svg></span><span>Obras</span></a>
    <a id="usersNav" class="nav-item" href="/admin" style="display:none"><span class="nav-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4.5 21c.8-4.2 3.4-6.4 7.5-6.4s6.7 2.2 7.5 6.4"/></svg></span><span>Usuários</span></a>
    <div class="nav-spacer"></div>
  </nav>
  <div class="logout"><button id="sideLogout" class="nav-item" type="button"><span class="nav-icon"><svg viewBox="0 0 24 24"><path d="M10 5H5v14h5"/><path d="M13 8l4 4-4 4"/><path d="M8 12h9"/></svg></span><span>Sair</span></button></div>
</aside>

<main class="main">
<header class="top">
  <div class="title-wrap">
    <div class="title-icon"><svg viewBox="0 0 24 24"><path d="M4 20h16"/><path d="M7 20V8h7"/><path d="M11 8V4h7v4"/><path d="M15 4V2"/><path d="M18 4V2"/><path d="M14 8h6"/><path d="M18 8v12"/><path d="M7 12h11"/><path d="M9 12v8"/></svg></div>
    <div class="title"><h1>Selecione a obra</h1><p>Escolha a obra que deseja acessar</p></div>
  </div>
  <div class="user">
    <div class="user-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4.5 21c.8-4.2 3.4-6.4 7.5-6.4s6.7 2.2 7.5 6.4"/></svg></div>
    <div class="user-text"><strong id="userName">Usuário</strong><small id="userRole">Acesso</small></div>
    <button id="userMenuBtn" class="user-menu-btn" type="button">⌄</button>
    <div id="userMenu" class="user-menu"><a id="adminLink" href="/admin" style="display:none">Administração</a><button id="logoutBtn" type="button">Sair</button></div>
  </div>
</header>
<section id="projects" class="grid"></section>
</main>
</div>

<script>
const esc=s=>String(s??"").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
async function api(url,opt={}){const r=await fetch(url,opt);const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||"Erro");return d}
async function init(){
  const me=(await api("/api/me")).user||{};
  const display=(me.name||me.username||"Usuário").toLowerCase().replace(/(^|\s)([^\s])/g,(m,a,b)=>a+b.toUpperCase());
  userName.textContent=display;
  userRole.textContent=me.role==="admin"?"Administrador":"Acesso comum";
  if(me.role==="admin"){adminLink.style.display="block";usersNav.style.display="flex";}
  const d=await api("/api/projects");
  const items=d.items||[];
  if(!items.length){projects.innerHTML='<div class="empty">Nenhuma obra foi liberada para este acesso.</div>';return;}
  projects.innerHTML=items.map(p=>{
    const href="/obra/"+encodeURIComponent(p.slug);
    return '<article class="project-card">'+
      '<div class="image-wrap">'+(p.image_path?'<img src="'+esc(p.image_path)+'" alt="'+esc(p.name)+'">':'<div class="image-placeholder">Imagem será adicionada</div>')+'</div>'+
      '<div class="card-body"><div class="project-name">'+esc(p.name)+'</div>'+
      '<a class="access-btn" href="'+href+'">Acessar&nbsp; →</a></div></article>';
  }).join("");
}
userMenuBtn.onclick=e=>{e.stopPropagation();userMenu.classList.toggle("open")};
document.addEventListener("click",()=>userMenu.classList.remove("open"));
async function logout(){await fetch("/api/logout",{method:"POST"});location.href="/login"}
logoutBtn.onclick=logout;sideLogout.onclick=logout;
init().catch(()=>{projects.innerHTML='<div class="empty">Não foi possível carregar as obras.</div>'});
</script>
</body></html>`;
}


function projectPlaceholderPage(projectName){
return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TERRAL | ${safeText(projectName)}</title>
<style>
body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#f5f1eb;color:#2d2927;min-height:100vh;display:grid;place-items:center;padding:20px}
.card{width:min(650px,100%);background:white;border:1px solid #e5ddd4;border-radius:16px;padding:38px;box-shadow:0 14px 36px #3c211b18;text-align:center}
h1{color:#691522;margin:0 0 10px}p{color:#746e69;line-height:1.6}.btn{display:inline-block;margin-top:18px;background:#681522;color:#fff;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:800}
</style></head><body><div class="card"><h1>${safeText(projectName)}</h1><p>O acesso a esta obra está liberado para o seu perfil.<br>Os módulos específicos desta obra ainda estão sendo configurados no <b>TERRAL | CONTROLE DE OBRAS</b>.</p><a class="btn" href="/">← Voltar às obras</a></div></body></html>`;
}

export default {
  async fetch(request, env) {
    const url=new URL(request.url);
    const path=url.pathname;

    // Static assets (imagens, logo e favicon)
    if(request.method==="GET" && /\.(png|jpg|jpeg|webp|gif|svg|ico)$/i.test(path)){
      return env.ASSETS.fetch(request);
    }

    if(path==="/login" && request.method==="GET"){
      const auth=await getAuth(request,env);
      if(auth)return Response.redirect(url.origin+"/",302);
      return new Response(loginPage(),{headers:{"content-type":"text/html; charset=UTF-8"}});
    }

    if(path==="/api/login" && request.method==="POST"){
      let etapa="início";
      try{
        const b=await request.json().catch(()=>({}));
        const username=String(b.username||"").trim().toUpperCase();
        const password=String(b.password||"");
        if(!username||!password)return json({error:"Informe usuário e senha."},400);

        etapa="localizar usuário";
        const user=await env.DB.prepare(
          "SELECT id,username,password_hash,salt,role,employee_id,active FROM users WHERE UPPER(username)=?"
        ).bind(username).first();

        if(!user||Number(user.active)!==1){
          return json({error:"Usuário ou senha inválidos."},401);
        }

        etapa="validar senha";
        const calculated=await passwordHash(password,String(user.salt||""));
        if(!secureEqual(calculated,String(user.password_hash||""))){
          return json({error:"Usuário ou senha inválidos."},401);
        }

        etapa="gerar token";
        const token=crypto.randomUUID().replaceAll("-","") + crypto.randomUUID().replaceAll("-","");
        const tokenHash=await sha256Hex(token);

        etapa="limpar sessão anterior";
        await env.DB.prepare(
          "DELETE FROM sessions WHERE user_id=?"
        ).bind(Number(user.id)).run();

        etapa="gravar nova sessão";
        const sessionResult=await env.DB.prepare(
          "INSERT INTO sessions (user_id,token_hash,expires_at) VALUES (?, ?, datetime('now', '+12 hours'))"
        ).bind(Number(user.id),tokenHash).run();

        if(sessionResult && sessionResult.success===false){
          throw new Error(sessionResult.error || "O D1 não confirmou a gravação da sessão.");
        }

        return new Response(JSON.stringify({
          ok:true,
          username:user.username,
          role:user.role
        }),{
          status:200,
          headers:{
            "content-type":"application/json; charset=UTF-8",
            "cache-control":"no-store, no-cache, must-revalidate",
            "Set-Cookie":`terral_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_HOURS*3600}`
          }
        });
      }catch(e){
        console.error("LOGIN_ERROR",etapa,e);
        const detalhe=(e && e.message) ? e.message : String(e||"erro desconhecido");
        return json({
          error:`Erro no login (${etapa}): ${detalhe}`
        },500);
      }
    }

    if(request.method==="OPTIONS") return new Response(null,{status:204,headers:{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"Content-Type","Access-Control-Allow-Methods":"GET, POST, PUT, DELETE, OPTIONS"}});

    if(path==="/recuperar-senha" && request.method==="GET"){
      const token=String(url.searchParams.get("token")||"");
      const page=token?`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TERRAL | NOVA SENHA</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f4f6;font-family:Arial;color:#202631;padding:20px}.box{width:min(430px,100%);background:#fff;border-radius:16px;padding:28px;box-shadow:0 15px 45px #0001}h1{font-size:23px;color:#690020}p{color:#68717e;line-height:1.5;font-size:13px}label{display:block;font-size:12px;font-weight:800;margin:12px 0 6px}input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #ccd2d9;border-radius:8px}button{width:100%;border:0;background:#780329;color:white;padding:12px;border-radius:8px;margin-top:16px;font-weight:800;cursor:pointer}.msg{margin-top:12px;font-size:13px}</style></head><body><div class="box"><h1>Definir nova senha</h1><p>Escolha uma nova senha para seu acesso ao TERRAL | Controle de Obras.</p><form id="f"><label>Nova senha</label><input id="p1" type="password" minlength="4" required><label>Confirmar nova senha</label><input id="p2" type="password" minlength="4" required><button>Salvar nova senha</button><div id="msg" class="msg"></div></form></div><script>f.onsubmit=async e=>{e.preventDefault();msg.textContent='';if(p1.value!==p2.value){msg.textContent='As senhas não conferem.';return}const r=await fetch('/api/reset-password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:${JSON.stringify(token)},password:p1.value})});const d=await r.json().catch(()=>({}));if(r.ok){msg.innerHTML='Senha alterada com sucesso. <a href="/login">Entrar no sistema</a>';f.querySelector('button').disabled=true}else msg.textContent=d.error||'Não foi possível alterar a senha.'};</script></body></html>`:`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TERRAL | RECUPERAR SENHA</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f4f6;font-family:Arial;color:#202631;padding:20px}.box{width:min(430px,100%);background:white;border-radius:16px;padding:28px;box-shadow:0 15px 45px #0001}h1{font-size:23px;color:#690020}p{color:#68717e;line-height:1.5;font-size:13px}label{display:block;font-size:12px;font-weight:800;margin:12px 0 6px}input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #ccd2d9;border-radius:8px}button{width:100%;border:0;background:#780329;color:white;padding:12px;border-radius:8px;margin-top:16px;font-weight:800;cursor:pointer}.back{display:block;text-align:center;margin-top:16px;color:#690020;text-decoration:none;font-size:13px}.msg{margin-top:12px;font-size:13px}</style></head><body><div class="box"><h1>Recuperar senha</h1><p>Informe seu usuário ou e-mail cadastrado. Se encontrarmos seu acesso, você receberá um link válido por 30 minutos.</p><form id="f"><label>Usuário ou e-mail</label><input id="identity" required><button>Enviar link de recuperação</button><div id="msg" class="msg"></div></form><a class="back" href="/login">Voltar ao login</a></div><script>f.onsubmit=async e=>{e.preventDefault();msg.textContent='Enviando...';const r=await fetch('/api/request-password-reset',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({identity:identity.value})});const d=await r.json().catch(()=>({}));msg.textContent=r.ok?(d.message||'Confira seu e-mail.'):(d.error||'Não foi possível enviar o e-mail.');};</script></body></html>`;
      return new Response(page,{headers:{"content-type":"text/html; charset=UTF-8"}});
    }

    if(path==="/api/request-password-reset" && request.method==="POST"){
      await ensureAdminSchema(env);
      const b=await request.json().catch(()=>({}));
      const identity=String(b.identity||"").trim();
      if(!identity)return json({error:"Informe seu usuário ou e-mail."},400);
      const user=await env.DB.prepare(`SELECT u.id,u.username,u.email,e.name AS employee_name FROM users u LEFT JOIN employees e ON e.id=u.employee_id WHERE u.active=1 AND (UPPER(u.username)=UPPER(?) OR LOWER(u.email)=LOWER(?)) LIMIT 1`).bind(identity,identity).first();
      if(!user||!String(user.email||"").trim())return json({message:"Se o acesso possuir um e-mail válido, o link de recuperação será enviado."});
      try{
        const token=await createPasswordReset(env,user.id);
        const link=url.origin+"/recuperar-senha?token="+encodeURIComponent(token);
        await sendPasswordResetEmail(env,String(user.email).trim(),user.employee_name||user.username,link);
        return json({message:"Se o acesso possuir um e-mail válido, o link de recuperação será enviado."});
      }catch(e){return json({error:String(e&&e.message||e)},503);}
    }

    if(path==="/api/reset-password" && request.method==="POST"){
      await ensureAdminSchema(env);
      const b=await request.json().catch(()=>({})),token=String(b.token||""),password=String(b.password||"");
      if(!token||password.length<4)return json({error:"Link ou nova senha inválidos."},400);
      const tokenHash=await sha256Hex(token);
      const reset=await env.DB.prepare(`SELECT pr.id,pr.user_id FROM password_resets pr JOIN users u ON u.id=pr.user_id WHERE pr.token_hash=? AND pr.used=0 AND u.active=1 AND datetime(pr.expires_at)>datetime('now') LIMIT 1`).bind(tokenHash).first();
      if(!reset)return json({error:"Este link expirou ou já foi utilizado."},400);
      const salt=randomHex(16),hash=await passwordHash(password,salt);
      await env.DB.prepare("UPDATE users SET password_hash=?,salt=? WHERE id=?").bind(hash,salt,reset.user_id).run();
      await env.DB.prepare("UPDATE password_resets SET used=1 WHERE id=?").bind(reset.id).run();
      await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(reset.user_id).run();
      return json({ok:true});
    }

    if(path==="/api/health" && request.method==="GET"){
      try{await env.DB.prepare("SELECT 1").first();return json({ok:true,sistema:"Emirates Parque Flamboyant",banco:"D1 conectado"});}
      catch(e){return json({ok:false,error:"Banco D1 indisponível"},500);}
    }


    const auth=await getAuth(request,env);
    if(!auth){
      if(path.startsWith("/api/"))return json({error:"Sessão expirada. Entre novamente."},401);
      return Response.redirect(url.origin+"/login",302);
    }


    if(path==="/cartao-ponto" && request.method==="GET"){await ensureTimeImportSchema(env);return new Response(pointPage(auth),{headers:{"content-type":"text/html; charset=UTF-8"}});}
    if(path==="/api/time/competences" && request.method==="GET"){await ensureTimeImportSchema(env);const r=await env.DB.prepare("SELECT competence,file_name,imported_at FROM time_imports ORDER BY competence DESC").all();return json({items:r.results||[]});}
    if(path==="/api/time/summary" && request.method==="GET"){await ensureTimeImportSchema(env);const competence=String(url.searchParams.get("competence")||"");if(!/^\d{4}-\d{2}$/.test(competence))return json({error:"Competência inválida."},400);const visibility=auth.role==="admin"?"":" AND e.admin_only=0";const r=await env.DB.prepare(`SELECT e.id,e.name,e.role,e.sex,e.salary,s.extra50_minutes,s.extra100_minutes,s.absence_count,s.medical_count,s.delay_minutes,s.night_minutes,s.bank_minutes FROM employees e JOIN monthly_time_summary s ON s.employee_id=e.id AND s.competence=? WHERE e.status='ATIVO'${visibility} ORDER BY e.role COLLATE NOCASE,e.name COLLATE NOCASE`).bind(competence).all();return json({items:r.results||[]});}
    if(path==="/api/admin/time-imports" && request.method==="GET"){if(!isAdmin(auth))return json({error:"Acesso restrito ao Administrador."},403);await ensureTimeImportSchema(env);const r=await env.DB.prepare(`SELECT i.*,u.username AS imported_by FROM time_imports i JOIN users u ON u.id=i.imported_by_user_id ORDER BY i.competence DESC,i.imported_at DESC`).all();return json({items:r.results||[]});}
    if(path==="/api/admin/time-import" && request.method==="POST"){
      if(!isAdmin(auth))return json({error:"Somente o Administrador pode importar cartão de ponto."},403);await ensureTimeImportSchema(env);const b=await request.json().catch(()=>({})),competence=String(b.competence||""),rows=Array.isArray(b.rows)?b.rows:[];if(!/^\d{4}-\d{2}$/.test(competence)||!rows.length)return json({error:"Competência ou dados inválidos."},400);if(rows.length>200)return json({error:"Quantidade de registros acima do permitido."},400);
      const existing=await env.DB.prepare("SELECT id FROM time_imports WHERE competence=?").bind(competence).first();if(existing&&!b.replace)return json({error:"Já existe uma importação para esta competência.",exists:true},409);
      const allEmployees=(await env.DB.prepare("SELECT id,name,registration FROM employees WHERE status='ATIVO'").all()).results||[],resolved=[];let ignored=0;
      for(const raw of rows){if(raw.skip){ignored++;continue}let employee=null,id=Number(raw.employee_id||0),reg=String(raw.source_registration||"").trim();if(id)employee=allEmployees.find(e=>Number(e.id)===id);if(!employee&&reg)employee=allEmployees.find(e=>String(e.registration||"").trim()===reg);if(!employee){const nn=normalizePersonName(raw.source_name);employee=allEmployees.find(e=>normalizePersonName(e.name)===nn)}if(!employee){ignored++;continue}resolved.push({employee,raw});}
      if(!resolved.length)return json({error:"Nenhum funcionário pôde ser vinculado."},400);if(existing&&b.replace){await env.DB.prepare("DELETE FROM monthly_time_summary WHERE competence=?").bind(competence).run();await env.DB.prepare("DELETE FROM time_imports WHERE id=?").bind(existing.id).run()}
      const ir=await env.DB.prepare(`INSERT INTO time_imports (competence,file_name,file_size,page_count,employee_count,matched_count,unmatched_count,imported_by_user_id) VALUES (?,?,?,?,?,?,?,?)`).bind(competence,String(b.file_name||""),Number(b.file_size||0),Number(b.page_count||rows.length),rows.length,resolved.length,ignored,auth.id).run();const importId=Number(ir.meta?.last_row_id||0);if(!importId)return json({error:"Não foi possível registrar a importação."},500);
      const stmts=[];for(const x of resolved){const r=x.raw,e=x.employee;stmts.push(env.DB.prepare(`INSERT INTO monthly_time_summary (import_id,employee_id,competence,source_name,source_registration,extra50_minutes,extra100_minutes,absence_count,medical_count,delay_minutes,night_minutes,bank_minutes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).bind(importId,e.id,competence,String(r.source_name||""),String(r.source_registration||""),Math.max(0,Number(r.extra50_minutes||0)),Math.max(0,Number(r.extra100_minutes||0)),Math.max(0,Math.round(Number(r.absence_count||0))),Math.max(0,Math.round(Number(r.medical_count||0))),Math.max(0,Number(r.delay_minutes||0)),Math.max(0,Number(r.night_minutes||0)),Math.max(0,Number(r.bank_minutes||0))));if(!String(e.registration||"").trim()&&String(r.source_registration||"").trim())stmts.push(env.DB.prepare("UPDATE employees SET registration=? WHERE id=? AND (registration='' OR registration IS NULL)").bind(String(r.source_registration).trim(),e.id));}if(stmts.length)await env.DB.batch(stmts);return json({ok:true,import_id:importId,matched:resolved.length,ignored},201);
    }
    const timeImportDelete=path.match(/^\/api\/admin\/time-imports\/(\d+)$/);if(timeImportDelete&&request.method==="DELETE"){if(!isAdmin(auth))return json({error:"Acesso restrito ao Administrador."},403);await ensureTimeImportSchema(env);const id=Number(timeImportDelete[1]),row=await env.DB.prepare("SELECT id FROM time_imports WHERE id=?").bind(id).first();if(!row)return json({error:"Importação não encontrada."},404);await env.DB.prepare("DELETE FROM monthly_time_summary WHERE import_id=?").bind(id).run();await env.DB.prepare("DELETE FROM time_imports WHERE id=?").bind(id).run();return json({ok:true});}


    if(path==="/" && request.method==="GET"){
      await ensureProjectsSchema(env);
      return new Response(worksPage(),{headers:{"content-type":"text/html; charset=UTF-8"}});
    }

    if(path==="/api/projects" && request.method==="GET"){
      await ensureProjectsSchema(env);
      if(auth.role==="admin"){
        const rows=(await env.DB.prepare(`SELECT id,slug,name,image_path,active,sort_order FROM projects WHERE active=1 ORDER BY sort_order,name`).all()).results||[];
        return json({items:rows.map(p=>({...p,allowed:true}))});
      }
      const rows=(await env.DB.prepare(`SELECT p.id,p.slug,p.name,p.image_path,p.active,p.sort_order FROM projects p INNER JOIN user_projects up ON up.project_id=p.id WHERE p.active=1 AND up.user_id=? ORDER BY p.sort_order,p.name`).bind(auth.id).all()).results||[];
      return json({items:rows.map(p=>({...p,allowed:true}))});
    }

    const projectMatch=path.match(/^\/obra\/([a-z0-9-]+)$/);
    if(projectMatch && request.method==="GET"){
      await ensureProjectsSchema(env);
      const slug=projectMatch[1];
      const project=await env.DB.prepare("SELECT * FROM projects WHERE slug=? AND active=1").bind(slug).first();
      if(!project)return new Response("Obra não encontrada.",{status:404,headers:{"content-type":"text/plain; charset=UTF-8"}});
      if(!(await hasProjectAccess(env,auth,slug)))return new Response(worksPage(),{status:403,headers:{"content-type":"text/html; charset=UTF-8"}});
      if(slug!=="emirates-parque-flamboyant")return new Response(projectPlaceholderPage(project.name),{headers:{"content-type":"text/html; charset=UTF-8"}});
      // Emirates continues below in the existing dashboard route.
    }

    if(path==="/api/me" && request.method==="GET") return json({ok:true,user:auth});
    if(path==="/api/change-password" && request.method==="POST"){
      const b=await request.json().catch(()=>({})),password=String(b.password||'');
      if(password.length<4)return json({error:"A senha deve ter pelo menos 4 caracteres."},400);
      const salt=randomHex(16),hash=await passwordHash(password,salt);
      await env.DB.prepare("UPDATE users SET password_hash=?,salt=? WHERE id=?").bind(hash,salt,auth.id).run();
      await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(auth.id).run();
      return new Response(JSON.stringify({ok:true}),{headers:{"content-type":"application/json; charset=UTF-8","Set-Cookie":"terral_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"}});
    }

    if(path==="/api/logout" && request.method==="POST"){
      const token=getCookie(request,"terral_session");
      if(token){const tokenHash=await sha256Hex(token);await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(tokenHash).run();}
      return new Response(JSON.stringify({ok:true}),{headers:{"content-type":"application/json; charset=UTF-8","Set-Cookie":"terral_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"}});
    }

    if(path==="/admin" && request.method==="GET"){
      if(!isAdmin(auth)) return new Response("Acesso negado.",{status:403,headers:{"content-type":"text/plain; charset=UTF-8"}});
      await ensureAdminSchema(env);
      return new Response(adminPage(),{headers:{"content-type":"text/html; charset=UTF-8"}});
    }

    if(path==="/api/admin/users" && request.method==="GET"){
      if(!isAdmin(auth)) return json({error:"Acesso restrito ao Administrador."},403);
      await ensureAdminSchema(env);
      const r=await env.DB.prepare(`SELECT u.id,u.username,u.email,u.role,u.employee_id,u.active,e.name AS employee_name,e.role AS employee_role FROM users u LEFT JOIN employees e ON e.id=u.employee_id ORDER BY e.name COLLATE NOCASE,u.username COLLATE NOCASE`).all();
      return json({users:r.results||[]});
    }

    if(path==="/api/admin/projects" && request.method==="GET"){
      if(!isAdmin(auth))return json({error:"Acesso restrito ao Administrador."},403);
      await ensureProjectsSchema(env);
      const r=await env.DB.prepare("SELECT id,slug,name,image_path,sort_order FROM projects WHERE active=1 ORDER BY sort_order,name").all();
      return json({items:r.results||[]});
    }

    const adminUserProjects=path.match(/^\/api\/admin\/users\/(\d+)\/projects$/);
    if(adminUserProjects && request.method==="GET"){
      if(!isAdmin(auth))return json({error:"Acesso restrito ao Administrador."},403);
      await ensureProjectsSchema(env);
      const id=Number(adminUserProjects[1]);
      const u=await env.DB.prepare("SELECT id,role FROM users WHERE id=?").bind(id).first();
      if(!u)return json({error:"Usuário não encontrado."},404);
      const r=await env.DB.prepare("SELECT project_id FROM user_projects WHERE user_id=? ORDER BY project_id").bind(id).all();
      return json({project_ids:(r.results||[]).map(x=>Number(x.project_id)),role:u.role});
    }
    if(adminUserProjects && request.method==="PUT"){
      if(!isAdmin(auth))return json({error:"Acesso restrito ao Administrador."},403);
      await ensureProjectsSchema(env);
      const id=Number(adminUserProjects[1]),b=await request.json().catch(()=>({}));
      const ids=[...new Set((Array.isArray(b.project_ids)?b.project_ids:[]).map(Number).filter(Number.isInteger))];
      const u=await env.DB.prepare("SELECT id,role FROM users WHERE id=?").bind(id).first();
      if(!u)return json({error:"Usuário não encontrado."},404);
      if(u.role==='admin')return json({ok:true,project_ids:[]});
      if(ids.length){
        const marks=ids.map(()=>'?').join(',');
        const valid=(await env.DB.prepare(`SELECT id FROM projects WHERE active=1 AND id IN (${marks})`).bind(...ids).all()).results||[];
        if(valid.length!==ids.length)return json({error:"Uma ou mais obras selecionadas são inválidas."},400);
      }
      await env.DB.prepare("DELETE FROM user_projects WHERE user_id=?").bind(id).run();
      if(ids.length)await env.DB.batch(ids.map(pid=>env.DB.prepare("INSERT INTO user_projects(user_id,project_id) VALUES (?,?)").bind(id,pid)));
      return json({ok:true,project_ids:ids});
    }

    const adminSendReset=path.match(/^\/api\/admin\/users\/(\d+)\/send-reset$/);
    if(adminSendReset && request.method==="POST"){
      if(!isAdmin(auth))return json({error:"Acesso restrito ao Administrador."},403);
      await ensureAdminSchema(env);
      const id=Number(adminSendReset[1]);
      const u=await env.DB.prepare(`SELECT u.id,u.username,u.email,u.active,e.name AS employee_name FROM users u LEFT JOIN employees e ON e.id=u.employee_id WHERE u.id=?`).bind(id).first();
      if(!u)return json({error:"Usuário não encontrado."},404);
      if(Number(u.active)!==1)return json({error:"Ative o usuário antes de enviar uma recuperação."},400);
      if(!String(u.email||'').trim())return json({error:"Este usuário não possui e-mail cadastrado."},400);
      try{
        const token=await createPasswordReset(env,id);
        const link=url.origin+"/recuperar-senha?token="+encodeURIComponent(token);
        await sendPasswordResetEmail(env,String(u.email).trim(),u.employee_name||u.username,link);
        return json({ok:true});
      }catch(e){return json({error:String(e&&e.message||e)},503);}
    }
    if(path==="/api/admin/users" && request.method==="POST"){
      if(!isAdmin(auth)) return json({error:"Acesso restrito ao Administrador."},403);
      await ensureAdminSchema(env);
      const b=await request.json().catch(()=>({}));
      const username=String(b.username||"").trim().toUpperCase();
      const password=String(b.password||"");
      const email=String(b.email||"").trim().toLowerCase();
      const role=b.role==='admin'?'admin':'common';
      const employeeId=Number(b.employee_id||0);
      if(!employeeId||!username||password.length<4)return json({error:"Funcionário, usuário e senha (mínimo 4 caracteres) são obrigatórios."},400);
      if(!/^[A-Z0-9._-]+$/.test(username))return json({error:"Use no usuário apenas letras, números, ponto, hífen ou underline."},400);
      const exists=await env.DB.prepare("SELECT id FROM users WHERE UPPER(username)=?").bind(username).first();
      if(exists)return json({error:"Este nome de usuário já existe."},409);
      const employee=await env.DB.prepare("SELECT id FROM employees WHERE id=?").bind(employeeId).first();
      if(!employee)return json({error:"Funcionário não encontrado."},400);
      const salt=randomHex(16),hash=await passwordHash(password,salt);
      const r=await env.DB.prepare("INSERT INTO users (username,password_hash,salt,role,employee_id,active,email) VALUES (?,?,?,?,?,1,?)").bind(username,hash,salt,role,employeeId,email).run();
      return json({ok:true,id:r.meta?.last_row_id},201);
    }
    const adminUserMatch=path.match(/^\/api\/admin\/users\/(\d+)$/);
    if(adminUserMatch && request.method==="PATCH"){
      if(!isAdmin(auth)) return json({error:"Acesso restrito ao Administrador."},403);
      await ensureAdminSchema(env);
      const id=Number(adminUserMatch[1]),b=await request.json().catch(()=>({}));
      const current=await env.DB.prepare("SELECT id,role,active FROM users WHERE id=?").bind(id).first();
      if(!current)return json({error:"Usuário não encontrado."},404);
      if(id===Number(auth.id) && b.active===0)return json({error:"Você não pode desativar seu próprio acesso."},400);
      const email=b.email===undefined?null:String(b.email||'').trim().toLowerCase();
      const active=b.active===undefined?null:(Number(b.active)===1?1:0);
      const role=b.role===undefined?null:(b.role==='admin'?'admin':'common');
      if(email!==null)await env.DB.prepare("UPDATE users SET email=? WHERE id=?").bind(email,id).run();
      if(active!==null)await env.DB.prepare("UPDATE users SET active=? WHERE id=?").bind(active,id).run();
      if(role!==null){if(id===Number(auth.id)&&role!=='admin')return json({error:"Você não pode retirar seu próprio perfil de Administrador."},400);await env.DB.prepare("UPDATE users SET role=? WHERE id=?").bind(role,id).run();}
      return json({ok:true});
    }
    const passMatch=path.match(/^\/api\/admin\/users\/(\d+)\/password$/);
    if(passMatch && request.method==="POST"){
      if(!isAdmin(auth)) return json({error:"Acesso restrito ao Administrador."},403);
      await ensureAdminSchema(env);
      const id=Number(passMatch[1]),b=await request.json().catch(()=>({})),password=String(b.password||'');
      if(password.length<4)return json({error:"A nova senha deve ter pelo menos 4 caracteres."},400);
      const u=await env.DB.prepare("SELECT id FROM users WHERE id=?").bind(id).first();if(!u)return json({error:"Usuário não encontrado."},404);
      const salt=randomHex(16),hash=await passwordHash(password,salt);
      await env.DB.prepare("UPDATE users SET password_hash=?,salt=? WHERE id=?").bind(hash,salt,id).run();
      await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id).run();
      return json({ok:true});
    }
    if(adminUserMatch && request.method==="DELETE"){
      if(!isAdmin(auth)) return json({error:"Acesso restrito ao Administrador."},403);
      const id=Number(adminUserMatch[1]);if(id===Number(auth.id))return json({error:"Você não pode excluir seu próprio acesso."},400);
      await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id).run();
      await env.DB.prepare("DELETE FROM password_resets WHERE user_id=?").bind(id).run().catch(()=>null);
      await env.DB.prepare("DELETE FROM user_projects WHERE user_id=?").bind(id).run().catch(()=>null);
      await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();
      return json({ok:true});
    }

    if(path==="/api/employees" && request.method==="GET"){
      await ensureTimeImportSchema(env);const visibility=auth.role==="admin"?"":" AND e.admin_only=0";
      const r=await env.DB.prepare(`SELECT e.*,COALESCE(s.extra50_minutes,0) extra50_minutes,COALESCE(s.extra100_minutes,0) extra100_minutes,COALESCE(s.absence_count,0) absence_count,COALESCE(s.medical_count,0) medical_count,COALESCE(s.delay_minutes,0) delay_minutes,s.competence point_competence FROM employees e LEFT JOIN monthly_time_summary s ON s.employee_id=e.id AND s.competence=(SELECT MAX(competence) FROM time_imports) WHERE e.status='ATIVO'${visibility} ORDER BY e.role COLLATE NOCASE,e.name COLLATE NOCASE`).all();return json(r.results||[]);
    }
    if(path==="/api/employees" && request.method==="POST"){
      if(auth.role!=="admin")return json({error:"Apenas o Administrador pode cadastrar funcionários."},403);
      const b=await request.json();if(!b.name||!b.name.trim()||!b.role||!b.role.trim())return json({error:"Nome e função são obrigatórios."},400);
      const restricted=/ASSISTENTE|ENCARREGADO|ANALISTA|MESTRE/i.test(b.role)?1:0;
      const r=await env.DB.prepare("INSERT INTO employees (name,role,registration,team,company,status,sex,salary,admission_date,cbo,admin_only) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
      .bind(b.name.trim(),b.role.trim(),b.registration||"",b.team||"",b.company||"TERRAL INCORPORADORA",b.status||"ATIVO",b.sex||"",Number(b.salary||0),b.admission_date||"",b.cbo||"",restricted).run();
      return json({ok:true,id:r.meta.last_row_id},201);
    }

    if(path==="/api/tasks" && request.method==="GET"){const r=await env.DB.prepare("SELECT * FROM tasks WHERE active=1 ORDER BY description COLLATE NOCASE").all();return json(r.results||[]);}
    if(path==="/api/tasks" && request.method==="POST"){const b=await request.json();if(!b.description||!b.unit)return json({error:"Descrição e unidade são obrigatórias."},400);const r=await env.DB.prepare("INSERT INTO tasks (description, unit, unit_value, active) VALUES (?, ?, ?, ?)").bind(b.description.trim(),b.unit.trim(),Number(b.unit_value||0),b.active===false?0:1).run();return json({ok:true,id:r.meta.last_row_id},201);}

    if(path==="/api/time-entries" && request.method==="GET"){const r=await env.DB.prepare("SELECT t.*, e.name AS employee_name FROM time_entries t JOIN employees e ON e.id=t.employee_id ORDER BY t.work_date DESC, e.name COLLATE NOCASE").all();return json(r.results||[]);}
    if(path==="/api/time-entries" && request.method==="POST"){const b=await request.json();if(!b.employee_id||!b.work_date)return json({error:"Funcionário e data são obrigatórios."},400);const r=await env.DB.prepare("INSERT INTO time_entries (employee_id,work_date,entry_time,break_start,break_end,exit_time,normal_hours,overtime_hours,occurrence,notes,launched_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(Number(b.employee_id),b.work_date,b.entry_time||"",b.break_start||"",b.break_end||"",b.exit_time||"",Number(b.normal_hours||0),Number(b.overtime_hours||0),b.occurrence||"",b.notes||"",b.launched_by||"").run();return json({ok:true,id:r.meta.last_row_id},201);}

    if(path==="/api/production" && request.method==="GET"){const r=await env.DB.prepare("SELECT p.*, e.name AS employee_name, t.description AS task_description, t.unit AS task_unit FROM production_entries p JOIN employees e ON e.id=p.employee_id JOIN tasks t ON t.id=p.task_id ORDER BY p.work_date DESC, e.name COLLATE NOCASE").all();return json(r.results||[]);}
    if(path==="/api/production" && request.method==="POST"){const b=await request.json();if(!b.employee_id||!b.task_id||!b.work_date)return json({error:"Funcionário, tarefa e data são obrigatórios."},400);const q=Number(b.quantity||0),u=Number(b.unit_value||0),t=q*u;const r=await env.DB.prepare("INSERT INTO production_entries (employee_id,task_id,work_date,tower,floor,location,details,quantity,unit_value,total_value,launched_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(Number(b.employee_id),Number(b.task_id),b.work_date,b.tower||"",b.floor||"",b.location||"",b.details||"",q,u,t,b.launched_by||"").run();return json({ok:true,id:r.meta.last_row_id,total_value:t},201);}

    if(path==="/funcionarios" && request.method==="GET") return new Response('<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TERRAL | FUNCIONÁRIOS</title><style>\n:root{--wine:#690020;--wine2:#8a1237;--wine3:#5b001a;--bg:#f3f4f6;--text:#202631;--muted:#6d7480;--line:#e6e8ec}*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:var(--bg);color:var(--text)}header{background:linear-gradient(90deg,var(--wine3),var(--wine2));color:#fff;padding:17px 30px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 10px #0002}header h1{margin:0;font-size:21px}header small{opacity:.9}header a{color:#fff;text-decoration:none;font-weight:700}.wrap{max-width:1180px;margin:28px auto;padding:0 20px}.toolbar{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px;display:flex;gap:12px;flex-wrap:wrap;box-shadow:0 10px 28px #0f172a10}.toolbar input,.toolbar select{padding:11px 12px;border:1px solid #ccd2d9;border-radius:9px;font-size:14px;background:#fff}.toolbar input{flex:1;min-width:230px}.pill{padding:9px 12px;border-radius:999px;background:#f5e9ee;color:var(--wine);font-size:12px;font-weight:800}.note{margin:12px 2px 20px;color:var(--muted);font-size:12px}.group{margin:22px 0}.gt{display:flex;justify-content:space-between;align-items:center;margin-bottom:9px}.gt h2{font-size:17px;color:var(--wine);margin:0}.gt span{font-size:12px;color:var(--muted)}.box{background:#fff;border:1px solid var(--line);border-radius:13px;overflow:auto;box-shadow:0 8px 24px #0f172a0b}table{width:100%;min-width:1030px;border-collapse:collapse;table-layout:auto}th,td{padding:13px 12px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap;vertical-align:middle}th{font-size:10px;text-transform:uppercase;letter-spacing:.3px;color:#6b7280;background:#fafafb;font-weight:800}td{font-size:13px}tbody tr{transition:background .15s ease}tbody tr:hover{background:#fcfafb}td.name{min-width:245px;white-space:normal}td.role-cell{min-width:155px;white-space:normal}.salary{font-weight:800;color:var(--wine)}.point-value{font-weight:700;color:var(--text);text-align:center}.point-head{text-align:center}.adm{font-size:9px;background:#f5e9ee;color:var(--wine);padding:4px 7px;border-radius:999px;margin-left:6px;vertical-align:middle}.empty{text-align:center;padding:35px;color:var(--muted)}@media(max-width:760px){.wrap{padding:0 12px}.toolbar{padding:13px}.box{overflow-x:auto}table{min-width:1000px}th,td{padding:11px 10px}}\nbutton,a,select,label,.module,.user-btn,.menu-link,.menu-action,.btn,.upload,.emp-card{cursor:pointer!important}button *,a *,label *,.module *,.user-btn *,.menu-link *,.menu-action *,.btn *,.upload *,.emp-card *{cursor:pointer!important}button,button *,a,a *,select,select *,label,label *,.module,.module *,.user-btn,.user-btn *,.menu-link,.menu-link *,.menu-action,.menu-action *,.btn,.btn *,.upload,.upload *,.emp-card,.emp-card *{cursor:pointer!important}</style></head><body><header><div><h1>Funcionários Ativos</h1><small>EMIRATES PARQUE FLAMBOYANT</small></div><a href="/">← Voltar</a></header><main class="wrap"><div class="toolbar"><input id="q" placeholder="Buscar funcionário..."><select id="role"><option value="">Todas as funções</option></select><span class="pill" id="access">...</span><span class="pill" id="total">...</span></div><div class="note">A visualização desta página respeita automaticamente o nível de acesso do usuário conectado.</div><div id="list"></div></main><script>\nconst money=v=>Number(v||0).toLocaleString(\'pt-BR\',{style:\'currency\',currency:\'BRL\'});const hm=m=>{m=Number(m||0);return Math.floor(m/60)+\'h\'+String(m%60).padStart(2,\'0\')};let all=[];async function load(){const r=await fetch(\'/api/employees?scope=admin\');all=await r.json();const rs=[...new Set(all.map(e=>e.role))].sort((a,b)=>a.localeCompare(b,\'pt-BR\'));role.innerHTML=\'<option value="">Todas as funções</option>\'+rs.map(x=>`<option>${x}</option>`).join(\'\');render()}function render(){const text=q.value.toLowerCase().trim(),rf=role.value;const a=all.filter(e=>(!rf||e.role===rf)&&(!text||e.name.toLowerCase().includes(text)));total.textContent=a.length+\' ativos\';const groups={};a.forEach(e=>(groups[e.role]??=[]).push(e));list.innerHTML=Object.keys(groups).sort((a,b)=>a.localeCompare(b,\'pt-BR\')).map(k=>`<section class="group"><div class="gt"><h2>${k}</h2><span>${groups[k].length} funcionário(s)</span></div><div class="box"><table><thead><tr><th>Nome</th><th>Sexo</th><th>Função</th><th>Salário</th><th class="point-head">HE 50%</th><th class="point-head">HE 100%</th><th class="point-head">Faltas</th><th class="point-head">Atestados</th><th class="point-head">Atrasos</th></tr></thead><tbody>${groups[k].map(e=>`<tr><td class="name"><b>${e.name}</b>${Number(e.admin_only)===1?\'<span class="adm">ADM</span>\':\'\'}</td><td>${e.sex===\'F\'?\'Feminino\':e.sex===\'M\'?\'Masculino\':\'—\'}</td><td class="role-cell">${e.role}</td><td class="salary">${money(e.salary)}</td><td class="point-value">${hm(Number(e.extra50_minutes||0))}</td><td class="point-value">${hm(Number(e.extra100_minutes||0))}</td><td class="point-value">${Number(e.absence_count||0)}</td><td class="point-value">${Number(e.medical_count||0)}</td><td class="point-value">${hm(Number(e.delay_minutes||0))}</td></tr>`).join(\'\')}</tbody></table></div></section>`).join(\'\')||\'<div class="empty">Nenhum funcionário encontrado.</div>\'}q.oninput=render;role.onchange=render;load().catch(()=>list.innerHTML=\'<div class="empty">Erro ao carregar funcionários do D1.</div>\');\n</script></body></html>',{headers:{"content-type":"text/html; charset=UTF-8"}});

    if(path==="/obra/emirates-parque-flamboyant" && request.method==="GET") return new Response('<!DOCTYPE html>\n<html lang="pt-BR">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>TERRAL | EMIRATES PARQUE FLAMBOYANT</title>\n<link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAACc0lEQVR4nO3cPU7DYBAGYYOoQEpJyw24Freg4IgcgzIStFCgSEYkIXbifRfPPBfA3+5g50fK1dPw8DkI6zp9AcoyADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAMwA4A4AzADgDgDMAOAOAu0lfwCH3t5v0JVzc28c2fQm/tApgjUsfG5+vSwwtAlj74vfZnTkdQvw1AHH5Y+nzRwNIH76L5BxiAbj8n1LziATg8vdLzKU8AJd/XPV8SgNw+aepnFNZAC5/mqp5xd8GKqskAP/756mYW4tPAo95eX9NX8LZnu8e05dwUOtHwBqWPwy9z7F4AHNvY52HNsfc8yz9GGh9B9DyDADOAOAMAM4A4AwAzgDgDADOAODaBtD58/M5up6nbQDD0HdoU3U+R/tvAy8xvHO+V+i8vEtofQfQ8gwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDABu8QDePrZL/4k/zf2xxw4/Ern0/DB3gKnL7LD8Cu1/KvaSKEudouQO0OEx8B9VzA3zCNB+ZQF4F5imal6ldwAjOE3lnMofAUZwXPV8Iq8BjGC/xFxiLwKN4KfUPKLvAozgW3IO8beB9AjS52/xSeBuCPe3m/CV1EkvfqdFADvjoawxhi5LH2sVwFjHYa1R/DWAsgwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADOAOAMAM4A4AwAzgDgDADuC1o5ZrPxplRWAAAAAElFTkSuQmCC">\n<style>\n:root{\n  --wine:#690020;\n  --wine2:#8a1237;\n  --wine3:#5b001a;\n  --bg:#f3f4f6;\n  --text:#202631;\n  --muted:#6d7480;\n  --green:#199447;\n  --line:#e6e8ec;\n}\n*{box-sizing:border-box}\nhtml,body{margin:0;min-height:100%;font-family:Arial,Helvetica,sans-serif;background:var(--bg);color:var(--text)}\nbody{min-height:100vh;display:flex;flex-direction:column}\n\nsvg{width:100%;height:100%;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}\n\n.topbar{\n  background:linear-gradient(90deg,var(--wine3),var(--wine2));\n  color:#fff;\n  min-height:88px;\n  padding:16px 34px;\n  display:flex;\n  align-items:center;\n  gap:26px;\n  box-shadow:0 2px 10px rgba(0,0,0,.16);\n}\n.logo{width:150px;max-height:58px;object-fit:contain}\n.vline{width:1px;height:54px;background:rgba(255,255,255,.55)}\n.project{flex:1;min-width:0}\n.project h1{margin:0;font-size:22px;line-height:1.1;letter-spacing:.2px}\n.project p{margin:6px 0 0;font-size:14px;opacity:.92}\n.topmeta{display:flex;align-items:center;gap:28px;font-size:14px;white-space:nowrap}\n.meta-item{display:flex;align-items:center;gap:9px}\n.meta-ico{width:20px;height:20px;color:#fff}\n.user-wrap{position:relative}.user-btn{display:flex;align-items:center;gap:8px;border:0;background:transparent;color:#fff;font:inherit;cursor:pointer;padding:8px 5px}.user-btn svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8}.caret{font-size:11px;opacity:.8}.user-dropdown{display:none;position:absolute;right:0;top:calc(100% + 12px);width:245px;background:#fff;color:#202631;border:1px solid #e4e7eb;border-radius:11px;box-shadow:0 18px 45px #0003;z-index:50;overflow:hidden}.user-dropdown.open{display:block}.user-head{padding:14px 15px 11px;background:#fafafb;border-bottom:1px solid #eceef1}.user-head strong{display:block;font-size:14px}.user-head small{display:block;color:#707782;margin-top:3px}.menu-link,.menu-action{width:100%;display:flex;align-items:center;gap:10px;border:0;background:#fff;color:#252a33;text-decoration:none;padding:12px 15px;font-size:13px;text-align:left;cursor:pointer}.menu-link:hover,.menu-action:hover{background:#f6f7f8}.menu-sep{height:1px;background:#eceef1}.admin-only{display:none}\n\nmain{flex:1;width:100%;max-width:1060px;margin:0 auto;padding:34px 24px 28px}\n.panel{\n  background:#fff;\n  border-radius:16px;\n  border:1px solid #eceff2;\n  box-shadow:0 12px 34px rgba(15,23,42,.09);\n  overflow:hidden;\n}\n.hero{text-align:center;padding:30px 32px 10px}\n.hero .eyebrow{color:var(--wine);font-size:18px;font-weight:800;margin-bottom:10px}\n.hero h2{font-size:37px;line-height:1.08;margin:0;font-weight:800;letter-spacing:.2px}\n.hero p{font-size:19px;color:var(--muted);margin:12px 0 0}\n\n.status{\n  margin:18px 30px 24px;\n  padding:17px 20px;\n  border:1px solid #b7ddc2;\n  background:#eff9f2;\n  border-radius:10px;\n  display:flex;\n  justify-content:center;\n  align-items:center;\n  gap:12px;\n  font-size:17px;\n}\n.check{\n  width:34px;height:34px;border-radius:50%;\n  background:#27a74d;color:#fff;\n  display:grid;place-items:center;\n  font-size:21px;font-weight:800;\n}\n#statusText{color:var(--green);font-weight:800}\n\n.modules{\n  display:grid;\n  grid-template-columns:1fr 1fr;\n  gap:14px;\n  padding:0 30px 26px;\n}\n.module{\n  border:0;\n  background:linear-gradient(135deg,var(--wine3),var(--wine2));\n  color:#fff;\n  border-radius:10px;\n  min-height:128px;\n  padding:20px 22px;\n  display:grid;\n  grid-template-columns:64px 1fr 24px;\n  gap:18px;\n  align-items:center;\n  text-align:left;\n  box-shadow:inset 0 0 0 1px rgba(255,255,255,.06);\n  cursor:pointer!important;\n  transition:transform .15s ease,box-shadow .15s ease,filter .15s ease;\n}\n.module:hover{transform:translateY(-2px);filter:brightness(1.035);box-shadow:inset 0 0 0 1px rgba(255,255,255,.08),0 8px 18px rgba(73,0,23,.15)}\n.module-icon{\n  width:62px;height:62px;\n  border-radius:50%;\n  background:rgba(255,255,255,.13);\n  display:grid;place-items:center;\n  color:#fff;\n}\n.module-icon svg{width:34px;height:34px}\n.module strong{display:block;font-size:19px;margin-bottom:7px}\n.module small{display:block;font-size:14px;line-height:1.45;color:rgba(255,255,255,.94)}\n.arrow{font-size:31px;font-weight:300;text-align:right}\n\n.panel-foot{\n  border-top:1px solid var(--line);\n  min-height:72px;\n  padding:18px 30px;\n  display:flex;\n  align-items:center;\n  justify-content:space-between;\n  gap:20px;\n  font-size:14px;\n  color:#454c56;\n}\n.foot-item{display:flex;align-items:center;gap:9px}\n.foot-ico{width:20px;height:20px;color:#374151}\n.foot-divider{height:26px;width:1px;background:#cfd4da}\n\nfooter{\n  background:linear-gradient(90deg,var(--wine3),#720522);\n  color:#fff;\n  padding:18px 20px;\n  text-align:center;\n  font-size:13px;\n}\n\n@media(max-width:900px){\n  .topbar{flex-wrap:wrap;gap:16px;padding:14px 22px}\n  .topmeta{width:100%;justify-content:flex-end}\n  .modules{grid-template-columns:1fr}\n  .hero h2{font-size:31px}\n}\n@media(max-width:620px){\n  .topbar{padding:13px 16px}\n  .logo{width:125px}\n  .vline{display:none}\n  .project{flex-basis:100%}\n  .topmeta{justify-content:space-between;gap:12px;font-size:12px}\n  main{padding:20px 12px}\n  .hero{padding:24px 16px 8px}\n  .hero h2{font-size:25px}\n  .hero p{font-size:16px}\n  .status{margin:15px 14px 18px;font-size:15px}\n  .modules{padding:0 14px 18px}\n  .module{grid-template-columns:54px 1fr 18px;padding:16px}\n  .module-icon{width:52px;height:52px}\n  .module-icon svg{width:29px;height:29px}\n  .panel-foot{flex-direction:column;align-items:flex-start;padding:15px 18px}\n  .foot-divider{display:none}\n}\nbutton,a,select,label,.module,.user-btn,.menu-link,.menu-action,.btn,.upload,.emp-card{cursor:pointer!important}button *,a *,label *,.module *,.user-btn *,.menu-link *,.menu-action *,.btn *,.upload *,.emp-card *{cursor:pointer!important}button,button *,a,a *,select,select *,label,label *,.module,.module *,.user-btn,.user-btn *,.menu-link,.menu-link *,.menu-action,.menu-action *,.btn,.btn *,.upload,.upload *,.emp-card,.emp-card *{cursor:pointer!important}</style>\n</head>\n<body>\n\n<header class="topbar">\n  <img class="logo" src="data:image/png;base64,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" alt="Terral Incorporadora">\n  <div class="vline"></div>\n  <div class="project">\n    <h1>EMIRATES PARQUE FLAMBOYANT</h1>\n    <p>Controle da Obra</p>\n  </div>\n  <div class="topmeta">\n    <div class="meta-item"><span class="meta-ico"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3.5" y="5.5" width="17" height="15" rx="2"/><path d="M7 3.5v4M17 3.5v4M3.5 9.5h17M8 13h3M13 13h3M8 16h3"/></svg></span><b id="today"></b></div>\n    <div class="vline" style="height:34px"></div>\n    <div class="meta-item user-wrap"><button id="userMenuBtn" class="user-btn" type="button" aria-expanded="false"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.5"/><path d="M5 20c.5-4.1 3-6.2 7-6.2s6.5 2.1 7 6.2"/></svg><span id="userLabel">Usuário</span><span class="caret">▼</span></button><div id="userDropdown" class="user-dropdown"><div class="user-head"><strong id="menuName">Usuário</strong><small id="menuRole">Acesso</small></div><a class="menu-link" href="/">▥ Todas as obras</a><a class="menu-link admin-only" id="adminMenu" href="/admin">⚙ Administração</a><button class="menu-action" id="changePassBtn" type="button">🔐 Alterar minha senha</button><div class="menu-sep"></div><button class="menu-action" id="logoutBtn" type="button">↪ Sair</button></div></div>\n  </div>\n</header>\n\n<main>\n<section class="panel">\n  <div class="hero">\n    <div class="eyebrow">BEM-VINDO</div>\n    <h2>EMIRATES PARQUE FLAMBOYANT</h2>\n    <p>Controle da Obra</p>\n  </div>\n\n  <div class="status">\n    <div class="check">✓</div>\n    <span>Status do sistema: <span id="statusText">VERIFICANDO...</span></span>\n  </div>\n\n  <div class="modules">\n    <button class="module" type="button" onclick="location.href=\'/funcionarios\'">\n      <div class="module-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 11a4 4 0 1 0-3.6-5.7A4 4 0 0 0 16 11ZM8 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm8 2c-3.2 0-6 1.6-6 4.5V20h12v-2.5C22 14.6 19.2 13 16 13ZM8 13c-3.3 0-6 1.5-6 4.3V20h6.5v-2.5c0-1.6.6-2.9 1.7-3.9A7.8 7.8 0 0 0 8 13Z"/></svg></div>\n      <div><strong>Funcionários</strong><small>Cadastre e gerencie os funcionários da obra.</small></div>\n      <div class="arrow">›</div>\n    </button>\n\n    <button class="module" type="button" onclick="location.href=\'/cartao-ponto\'">\n      <div class="module-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 7v5l3.5 2"/></svg></div>\n      <div><strong>Cartão de Ponto</strong><small>Importação e consulta mensal do cartão de ponto.</small></div>\n      <div class="arrow">›</div>\n    </button>\n\n    <button class="module" type="button">\n      <div class="module-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3.5" y="7.5" width="17" height="11" rx="2"/><path d="M9 7.5V5.8c0-.7.6-1.3 1.3-1.3h3.4c.7 0 1.3.6 1.3 1.3v1.7M3.5 11.5h17M10 11.5v2h4v-2"/></svg></div>\n      <div><strong>Produção</strong><small>Lançamento de produção diária da equipe.</small></div>\n      <div class="arrow">›</div>\n    </button>\n\n    <button class="module" type="button">\n      <div class="module-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="4" width="14" height="16" rx="1.5"/><path d="M8 8h8M8 12h8M8 16h8"/></svg></div>\n      <div><strong>Tarefas</strong><small>Cadastre e gerencie as tarefas da obra.</small></div>\n      <div class="arrow">›</div>\n    </button>\n  </div>\n\n  <div class="panel-foot">\n    <div class="foot-item"><span class="foot-ico"><svg viewBox="0 0 24 24" aria-hidden="true"><ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v5c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 10v5c0 1.7 3.1 3 7 3s7-1.3 7-3v-5M5 15v4c0 1.7 3.1 3 7 3s7-1.3 7-3v-4"/></svg></span><span>Banco de dados: <b>emirates-ponto-db (D1)</b></span></div>\n    <div class="foot-divider"></div>\n    <div class="foot-item"><span class="foot-ico"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.5 8A7 7 0 0 1 19 10M17.5 16A7 7 0 0 1 5 14"/></svg></span><span>Última atualização: agora há pouco</span></div>\n  </div>\n</section>\n</main>\n\n<footer>© 2026 Terral Incorporadora. Todos os direitos reservados.</footer>\n\n<script>\ndocument.getElementById("today").textContent = new Date().toLocaleDateString("pt-BR");\n\nasync function initUser(){\n  try{\n    const r=await fetch("/api/me");const d=await r.json();if(!r.ok)return;\n    const u=d.user||{};const display=(u.name||u.username||"Usuário").toLowerCase().replace(/(^|\\s)([^\\s])/g,(m,a,b)=>a+b.toUpperCase());\n    document.getElementById("userLabel").textContent=display.split(" ").slice(0,2).join(" ");\n    document.getElementById("menuName").textContent=display;\n    document.getElementById("menuRole").textContent=u.role==="admin"?"Administrador":"Acesso comum";\n    if(u.role==="admin")document.getElementById("adminMenu").style.display="flex";\n  }catch(e){}\n}\nconst umb=document.getElementById("userMenuBtn"),udd=document.getElementById("userDropdown");\numb.onclick=(e)=>{e.stopPropagation();udd.classList.toggle("open");umb.setAttribute("aria-expanded",udd.classList.contains("open")?"true":"false")};\ndocument.addEventListener("click",()=>udd.classList.remove("open"));udd.onclick=e=>e.stopPropagation();\ndocument.getElementById("logoutBtn").onclick=async()=>{await fetch("/api/logout",{method:"POST"});location.href="/login"};\ndocument.getElementById("changePassBtn").onclick=async()=>{const p=prompt("Digite sua nova senha (mínimo 4 caracteres):");if(p===null)return;if(p.length<4){alert("A senha deve ter pelo menos 4 caracteres.");return;}const r=await fetch("/api/change-password",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:p})});const d=await r.json().catch(()=>({}));if(r.ok){alert("Senha alterada. Entre novamente com a nova senha.");location.href="/login";}else alert(d.error||"Não foi possível alterar a senha.");};\ninitUser();\n\nasync function health(){\n  const el=document.getElementById("statusText");\n  try{\n    const r=await fetch("/api/health");\n    const d=await r.json();\n    if(!r.ok || !d.ok) throw new Error();\n    el.textContent="ONLINE ✓";\n    el.style.color="#199447";\n  }catch(e){\n    el.textContent="ERRO";\n    el.style.color="#b42318";\n  }\n}\nhealth();\n</script>\n</body>\n</html>',{headers:{"content-type":"text/html; charset=UTF-8"}});

    return json({error:"Rota não encontrada."},404);
  }
};

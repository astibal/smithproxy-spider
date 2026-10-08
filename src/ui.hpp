#pragma once

#include <string_view>

namespace spider {
inline constexpr std::string_view kIndexHtml = R"SPIDER(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Smithproxy Spider</title>
  <style>
    :root{color-scheme:dark;--bg:#0b1017;--panel:#121a24;--line:#263445;--text:#dce7f3;--muted:#8291a5;--green:#58d68d}
    *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:14px ui-monospace,SFMono-Regular,Consolas,monospace}
    header{display:flex;align-items:center;gap:16px;padding:18px 24px;border-bottom:1px solid var(--line)}
    h1{font-size:18px;margin:0} .status{color:var(--green)} main{padding:24px} table{width:100%;border-collapse:collapse;background:var(--panel)}
    th,td{text-align:left;padding:11px 13px;border-bottom:1px solid var(--line)} th{color:var(--muted)}
    .empty{padding:40px;text-align:center;color:var(--muted)} input{margin-left:auto;background:#0d141d;color:var(--text);border:1px solid var(--line);padding:8px;width:260px}
  </style>
</head>
<body>
  <header><h1>Smithproxy Spider</h1><span id="status" class="status">connecting</span><input id="token" type="password" placeholder="X-Spider-Token"></header>
  <main><table><thead><tr><th>Session</th><th>State</th><th>Revision</th><th>ID</th></tr></thead><tbody id="sessions"></tbody></table><div id="empty" class="empty">No active sessions</div></main>
  <script>
    const token=document.querySelector('#token'), rows=document.querySelector('#sessions'), empty=document.querySelector('#empty'), status=document.querySelector('#status');
    token.value=sessionStorage.getItem('spider-token')||''; token.onchange=()=>sessionStorage.setItem('spider-token',token.value);
    async function refresh(){try{const r=await fetch('/api/sessions',{headers:{'X-Spider-Token':token.value}});if(!r.ok)throw new Error(r.status);const d=await r.json();rows.replaceChildren(...d.sessions.map(s=>{const tr=document.createElement('tr');[s.label||'—',s.state,s.revision,s.id].forEach(v=>{const td=document.createElement('td');td.textContent=v;tr.append(td)});return tr}));empty.hidden=d.sessions.length>0;status.textContent='live · r'+d.revision}catch(e){status.textContent='offline / unauthorized'}}
    refresh();setInterval(refresh,1000);
  </script>
</body>
</html>)SPIDER";
} // namespace spider


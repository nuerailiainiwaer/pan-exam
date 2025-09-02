function $(sel){ return document.querySelector(sel); }
function $all(sel){ return Array.prototype.slice.call(document.querySelectorAll(sel)); }
function getJSON(url){
  return fetch(url, { credentials: 'same-origin' }).then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); });
}
function postJSON(url, data){
  return fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify(data||{}) })
    .then(function(r){ return r.json().then(function(j){ if(!r.ok||j.error){ throw new Error(j.error||('HTTP '+r.status)); } return j; }); });
}
function del(url){
  return fetch(url, { method:'DELETE', credentials:'same-origin' }).then(function(r){ return r.json().then(function(j){ if(!r.ok||j.error){ throw new Error(j.error||('HTTP '+r.status)); } return j; }); });
}
function backBtn(){
  var bar=document.createElement('div'); bar.className='backbar';
  var b=document.createElement('button'); b.className='btn'; b.textContent='← Back';
  b.onclick=function(){ history.back(); }; bar.appendChild(b); return bar;
}
function injectUsername(){
  getJSON('/api/me').then(function(m){
    if(!m || !m.ok) return;
    var header = document.querySelector('.header');
    if(!header) return;
    var who = document.getElementById('whoami');
    if(!who){
      who = document.createElement('span');
      who.id = 'whoami';
      who.className = 'badge';
      who.style.marginLeft = 'auto';
      header.appendChild(who);
    }
    who.textContent = '👤 ' + m.username;
  }).catch(function(){});
}

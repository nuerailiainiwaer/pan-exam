document.getElementById('back').appendChild(backBtn());
function qs(name){ var m=location.search.match(new RegExp('[?&]'+name+'=([^&]+)')); return m?decodeURIComponent(m[1]):''; }
var caseId=qs('id');
function loadCase(){
  getJSON('/api/admin/cases/'+caseId).then(function(c){
    var card=$('#caseCard'); card.innerHTML='';
    var p=document.createElement('p'); p.textContent=c.text; card.appendChild(p);
    if(c.imageUrl){ var img=document.createElement('img'); img.src=c.imageUrl; img.className='responsive'; card.appendChild(img); }
  });
}
function loadComments(){
  getJSON('/api/admin/comments?caseId='+encodeURIComponent(caseId)).then(function(res){
    var wrap=$('#comments'); wrap.innerHTML='';
    res.items.forEach(function(cm){
      var div=document.createElement('div'); div.className='item line';
      var btn=document.createElement('button'); btn.className='btn bad'; btn.textContent='Delete';
      var span=document.createElement('span'); span.innerHTML='<b>'+cm.username+':</b> '+cm.text;
      btn.onclick=function(){ if(!confirm('Delete comment?')) return; del('/api/admin/comments/'+cm.id).then(loadComments); };
      div.appendChild(btn); div.appendChild(span); wrap.appendChild(div);
    });
  });
}
loadCase(); loadComments();


// ---- Delete Case ----
(function(){
  const btn = document.getElementById('deleteCaseBtn');
  if (!btn) return;
  const params = new URLSearchParams(location.search);
  const caseId = params.get('id');
  btn.addEventListener('click', async () => {
    if (!caseId) { alert('Missing case id'); return; }
    if (!confirm('Delete this case and all its comments? This cannot be undone.')) return;
    try {
      const r = await fetch(`/api/admin/cases/${caseId}`, { method: 'DELETE' });
      const j = await r.json().catch(()=>({}));
      if (!r.ok || j.error) throw new Error(j.error || 'Delete failed');
      alert('Case deleted.');
      location.href = '/admin/cases.html';
    } catch(e) {
      alert(e.message || 'Delete failed');
    }
  });
})();

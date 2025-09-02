(function(){
  function getParam(name){
    const params = new URLSearchParams(location.search);
    return params.get(name) || params.get('caseId') || params.get('id');
  }
  const caseId = getParam('id');
  const btn = document.getElementById('btnDeleteCase');
  const msg = document.getElementById('delMsg');
  if (!btn || !caseId) return;

  btn.addEventListener('click', async () => {
    if (!confirm('Delete this case and all its comments? This cannot be undone.')) return;
    btn.disabled = true;
    msg.textContent = 'Deleting...';
    try{
      const res = await fetch(`/api/admin/cases/${caseId}`, { method: 'DELETE', headers: { 'Content-Type':'application/json' } });
      if(!res.ok){
        const j = await res.json().catch(()=>({}));
        throw new Error(j.error || ('HTTP ' + res.status));
      }
      msg.textContent = 'Deleted. Redirecting...';
      setTimeout(()=>{ location.href = '/admin/cases.html'; }, 800);
    }catch(e){
      console.error(e);
      msg.textContent = 'Failed: ' + e.message;
      btn.disabled = false;
    }
  });
})();
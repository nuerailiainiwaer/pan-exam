injectUsername();
document.getElementById('back').appendChild(backBtn());
function qs(name){ var m=location.search.match(new RegExp('[?&]'+name+'=([^&]+)')); return m?decodeURIComponent(m[1]):''; }
var caseId=qs('id');
function loadCase(){
  getJSON('/api/user/cases/'+caseId).then(function(c){
    var card=document.getElementById('caseCard'); card.innerHTML='';
    var p=document.createElement('p'); p.textContent=c.text; card.appendChild(p);
    if(c.imageUrl){ var img=document.createElement('img'); img.src=c.imageUrl; img.className='responsive'; card.appendChild(img); }
  });
}
function loadComments(){
  getJSON('/api/user/cases/'+caseId+'/comments').then(function(res){
    var wrap=document.getElementById('comments'); wrap.innerHTML='';
    res.items.forEach(function(cm){
      var div=document.createElement('div'); div.className='item line';
      if(cm.isOwner){
        var btn=document.createElement('button'); btn.className='btn bad'; btn.textContent='Delete';
        btn.onclick=function(){ del('/api/user/comments/'+cm.id).then(loadComments); };
        div.appendChild(btn);
      }
      var span=document.createElement('span'); span.innerHTML='<b>'+cm.username+':</b> '+cm.text;
      div.appendChild(span); 
      wrap.appendChild(div);
    });
  });
}
document.getElementById('add').onclick=function(){
  var t=document.getElementById('commentInput').value.trim(); if(!t) return;
  postJSON('/api/user/cases/'+caseId+'/comments', { text:t }).then(function(){ document.getElementById('commentInput').value=''; loadComments(); });
};
loadCase(); loadComments();

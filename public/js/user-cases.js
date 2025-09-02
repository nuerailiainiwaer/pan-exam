injectUsername();
document.getElementById('back').appendChild(backBtn());
var list=document.getElementById('list');
function load(){
  var q=document.getElementById('search').value.trim();
  var url='/api/user/cases'+(q?('?search='+encodeURIComponent(q)):''); 
  getJSON(url).then(function(res){
    document.getElementById('ucCount').textContent='Cases: '+res.items.length;
    list.innerHTML='';
    res.items.forEach(function(it){
      var div=document.createElement('div'); div.className='item';
      if(it.commented){ div.classList.add('tag-green'); }
      var a=document.createElement('a'); a.href='./case-view.html?id='+it.id; a.textContent=it.snippet||'(no text)';
      div.appendChild(a); list.appendChild(div);
    });
  });
}
document.getElementById('search').addEventListener('input', load);
load();

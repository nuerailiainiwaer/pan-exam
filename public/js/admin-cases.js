document.getElementById('back').appendChild(backBtn());
var list=$('#list');
function load(){
  var q=$('#search').value.trim();
  var url='/api/admin/cases'+(q?('?search='+encodeURIComponent(q)):''); 
  getJSON(url).then(function(res){
    $('#cCount').textContent='Cases: '+res.items.length;
    list.innerHTML='';
    res.items.forEach(function(it){
      var div=document.createElement('div'); div.className='item line';
      var delBtn=document.createElement('button'); delBtn.className='btn bad'; delBtn.textContent='Delete Case';
      var a=document.createElement('a'); a.href='./case-view.html?id='+it.id; a.textContent=it.snippet||'(no text)';
      delBtn.onclick=function(){ if(!confirm('Delete this case and its comments?')) return; del('/api/admin/cases/'+it.id).then(load); };
      div.appendChild(delBtn); div.appendChild(a); list.appendChild(div);
    });
  });
}
$('#search').addEventListener('input', load);
load();

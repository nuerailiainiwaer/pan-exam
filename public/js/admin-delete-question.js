document.getElementById('back').appendChild(backBtn());
var list=$('#list');
function load(){
  var q=$('#search').value.trim();
  var url='/api/admin/questions'+(q?('?search='+encodeURIComponent(q)):''); 
  getJSON(url).then(function(res){
    $('#qCount').textContent='Questions: '+res.items.length;
    list.innerHTML='';
    res.items.forEach(function(it){
      var div=document.createElement('div'); div.className='item line';
      var btn=document.createElement('button'); btn.className='btn bad'; btn.textContent='Delete';
      var span=document.createElement('span'); span.textContent=it.topic;
      btn.onclick=function(){ if(!confirm('Are you sure?')) return; del('/api/admin/questions/'+it.id).then(load).catch(function(e){ alert('Error: '+e.message); }); };
      div.appendChild(btn); div.appendChild(span); list.appendChild(div);
    });
  });
}
$('#search').addEventListener('input', load);
load();

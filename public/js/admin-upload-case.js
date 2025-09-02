document.getElementById('back').appendChild(backBtn());
function refreshCount(){ getJSON('/api/admin/cases').then(function(res){ document.getElementById('cCount').textContent='Cases: '+res.items.length; }); }
document.getElementById('upload').onclick=function(){
  var t=$('#text').value.trim(); var img=$('#imageUrl').value.trim();
  if(!t){ $('#msg').textContent='Text is required.'; return; }
  postJSON('/api/admin/cases', { text:t, imageUrl:img }).then(function(){ $('#msg').textContent='Uploaded!'; $('#text').value=''; $('#imageUrl').value=''; refreshCount(); });
};
refreshCount();

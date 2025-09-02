document.getElementById('back').appendChild(backBtn());
document.getElementById('addBtn').onclick=function(){
  var topic=$('#topic').value.trim();
  var optA=$('#optA').value.trim();
  var optB=$('#optB').value.trim();
  var optC=$('#optC').value.trim();
  var optD=$('#optD').value.trim();
  var imageUrl=$('#imageUrl').value.trim();
  var correct=(document.querySelector('input[name="correct"]:checked')||{}).value;
  if(!topic||!optA||!optB||!optC||!optD||!correct){ $('#msg').textContent='Please fill all required fields and select the correct answer.'; return; }
  if(!confirm('Add this question?')) return;
  postJSON('/api/admin/questions',{ topic:topic, options:{A:optA,B:optB,C:optC,D:optD}, correct:correct, imageUrl:imageUrl })
  .then(function(){ $('#msg').textContent='Added!'; $('#topic').value=$('#optA').value=$('#optB').value=$('#optC').value=$('#optD').value=$('#imageUrl').value=''; var c=document.querySelector('input[name="correct"]:checked'); if(c) c.checked=false; })
  .catch(function(e){ $('#msg').textContent='Error: '+e.message; });
};

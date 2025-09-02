document.getElementById('back').appendChild(backBtn());
document.getElementById('add').onclick=function(){
  var u=$('#username').value.trim();
  var p=$('#password').value;
  if(!u||!p){ $('#msg').textContent='Both fields required.'; return; }
  postJSON('/api/admin/users', { username:u, password:p }).then(function(){ $('#msg').textContent='Added!'; $('#username').value=''; $('#password').value=''; })
  .catch(function(e){ $('#msg').textContent='Error: '+e.message; });
};

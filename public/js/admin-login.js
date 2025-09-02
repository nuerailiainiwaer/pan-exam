document.getElementById('loginBtn').onclick=function(){
  var u=document.getElementById('username').value.trim();
  var p=document.getElementById('password').value;
  postJSON('/api/admin/login', { username:u, password:p }).then(function(){
    location.href='/admin/admin-dashboard.html';
  }).catch(function(e){ document.getElementById('msg').textContent='Login failed: '+e.message; });
};

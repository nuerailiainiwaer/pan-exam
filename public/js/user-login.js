document.getElementById('loginBtn').onclick=function(){
  var u=$('#username').value.trim();
  var p=$('#password').value;
  postJSON('/api/user/login', { username:u, password:p }).then(function(){
    location.href='/user/home.html';
  }).catch(function(e){ document.getElementById('msg').textContent='Login failed: '+e.message; });
};

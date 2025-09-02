injectUsername();
document.getElementById('back').appendChild(backBtn());
function logout(){ postJSON('/api/logout',{}).then(function(){ location.href='/index.html'; }); }

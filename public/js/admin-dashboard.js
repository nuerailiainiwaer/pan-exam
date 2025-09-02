function refreshStats(){
  getJSON('/api/admin/stats').then(function(s){
    document.getElementById('usersCount').textContent = 'Users: ' + s.userCount;
    document.getElementById('questionsCount').textContent = 'Questions: ' + s.questionCount;
    document.getElementById('casesCount').textContent = 'Cases: ' + s.caseCount;
    document.getElementById('commentsCount').textContent = 'Comments: ' + s.commentCount;
  }).catch(function(e){ console.error(e); });
}
function logout(){ postJSON('/api/logout',{}).then(function(){ location.href='/index.html'; }); }
refreshStats();

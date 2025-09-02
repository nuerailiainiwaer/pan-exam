injectUsername();
document.getElementById('back').appendChild(backBtn());
var list=document.getElementById('list');
var bar=document.getElementById('bar');
var progressText=document.getElementById('progressText');

function loadProgress(){
  getJSON('/api/user/progress').then(function(p){
    var pct=(p.totalQuestions>0)?Math.round(100*p.knownCount/p.totalQuestions):0;
    bar.style.width=pct+'%'; progressText.textContent=p.knownCount+' / '+p.totalQuestions;
  });
}
function loadList(){
  var q=document.getElementById('search').value.trim();
  var url='/api/user/questions'+(q?('?search='+encodeURIComponent(q)):''); 
  getJSON(url).then(function(res){
    list.innerHTML='';
    res.items.forEach(function(it){
      var wrap=document.createElement('div'); wrap.className='item';
      var header=document.createElement('div'); header.className='item-header'; header.textContent=it.topic;
      var area=document.createElement('div'); area.style.marginTop='10px'; area.style.display='none';
      setHeaderColor(header, it.known, it.marked);
      header.onclick=function(){
        if(area.style.display==='none'){ area.style.display='block'; wrap.classList.add('expanded'); loadQuestion(it.id, header, area); } else { area.style.display='none'; wrap.classList.remove('expanded'); }
      };
      wrap.appendChild(header); wrap.appendChild(area); list.appendChild(wrap);
    });
  });
}
function setHeaderColor(header, known, marked){
  header.classList.remove('tag-green'); header.classList.remove('tag-red');
  if(known){ header.classList.add('tag-green'); }
  else if(marked){ header.classList.add('tag-red'); }
}
function loadQuestion(id, header, area){
  getJSON('/api/user/questions/'+id).then(function(qn){
    area.innerHTML='';
    setHeaderColor(header, qn.known, qn.marked);
    if(qn.imageUrl){ var img=document.createElement('img'); img.src=qn.imageUrl; img.className='responsive'; area.appendChild(img); }
    var keys=['A','B','C','D'];
    for(var i=0;i<keys.length;i++){
      var k=keys[i]; var line=document.createElement('div'); line.style.margin='4px 0';
      var span=document.createElement('span'); span.textContent=k+'. '+qn.options[k]; span.setAttribute('data-key',k);
      line.appendChild(span); area.appendChild(line);
    }
    var row=document.createElement('div'); row.className='row'; row.style.marginTop='8px';
    var show=document.createElement('button'); show.className='btn'; show.textContent='Show Answer';
    var knownBtn=document.createElement('button'); knownBtn.className='btn good'; knownBtn.textContent='Already Known';
    var markBtn=document.createElement('button'); markBtn.className='btn bad'; markBtn.textContent='Mark It';
    show.onclick=function(){
      var spans=area.querySelectorAll('span[data-key]');
      for(var i=0;i<spans.length;i++){ if(spans[i].getAttribute('data-key')===qn.correct){ spans[i].className='answer'; } }
    };
    knownBtn.onclick=function(){
      var next=!qn.known;
      postJSON('/api/user/known', { questionId:id, known:next }).then(function(){
        qn.known=next; if(next){ qn.marked=false; }
        setHeaderColor(header, qn.known, qn.marked); loadProgress();
      });
    };
    markBtn.onclick=function(){
      var next=!qn.marked;
      postJSON('/api/user/mark', { questionId:id, marked:next }).then(function(){
        qn.marked=next; if(qn.marked){ qn.known=false; }
        setHeaderColor(header, qn.known, qn.marked);
      });
    };
    row.appendChild(show); row.appendChild(knownBtn); row.appendChild(markBtn); area.appendChild(row);

    var notesWrap=document.createElement('div'); notesWrap.style.marginTop='10px';
    var lab=document.createElement('div'); lab.className='label'; lab.textContent='Your Notes';
    var notes=document.createElement('textarea'); notes.className='input'; notes.rows=4; notes.placeholder='Write a note about this question...';
    var save=document.createElement('button'); save.className='btn'; save.textContent='Save Note';
    var msg=document.createElement('div'); msg.className='small';
    save.onclick=function(){
      postJSON('/api/user/notes/'+id, { text: notes.value }).then(function(){ msg.textContent='Saved'; setTimeout(function(){ msg.textContent=''; }, 1500); });
    };
    notesWrap.appendChild(lab); notesWrap.appendChild(notes); notesWrap.appendChild(document.createElement('br')); notesWrap.appendChild(save); notesWrap.appendChild(msg);
    area.appendChild(notesWrap);
    getJSON('/api/user/notes/'+id).then(function(res){ notes.value=res.text||''; });
  });
}
document.getElementById('search').addEventListener('input', loadList);
loadProgress(); loadList();

// Auto-dismiss alerts after a short delay
document.addEventListener('DOMContentLoaded', function () {
  const alerts = document.querySelectorAll('.alert');
  alerts.forEach((a) => {
    setTimeout(() => {
      try { 
        // Bootstrap's alert dispose
        const bsAlert = bootstrap.Alert.getOrCreateInstance(a);
        bsAlert.close();
      } catch (e) {
        a.classList.remove('show');
      }
    }, 4500);
  });

  // clean up any stale Bootstrap modal state
  document.body.classList.remove('modal-open');
  document.body.style.removeProperty('paddingRight');
  document.querySelectorAll('.modal-backdrop').forEach((backdrop) => backdrop.remove());

  // ensure modals release backdrop on submit actions that trigger reload
  document.querySelectorAll('.modal form').forEach((form)=>{
    form.addEventListener('submit', ()=>{
      const modalEl = form.closest('.modal');
      if(modalEl && window.bootstrap){
        const modalInstance = bootstrap.Modal.getInstance(modalEl) || bootstrap.Modal.getOrCreateInstance(modalEl);
        modalInstance.hide();
      }
      setTimeout(()=>{
        document.body.classList.remove('modal-open');
        document.body.style.removeProperty('paddingRight');
        document.querySelectorAll('.modal-backdrop').forEach((backdrop) => backdrop.remove());
      }, 150);
    })
  });
  
  // initialize bootstrap tooltips
  try{
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    tooltipTriggerList.map(function (el) {
      return new bootstrap.Tooltip(el)
    })
  }catch(e){/* ignore */}

  // theme toggle (simple localStorage)
  const themeBtn = document.getElementById('theme-toggle-btn');
  if(themeBtn){
    const root = document.documentElement;
  // default to dark (tech-style). Stored values: 'dark' or 'light'
  const current = localStorage.getItem('site-theme') || 'dark';
    if(current === 'light') root.classList.add('light-theme');
    // set initial icon
    themeBtn.innerText = (current === 'light') ? '☀️' : '🌙';
    themeBtn.addEventListener('click', ()=>{
      if(root.classList.contains('light-theme')){
        root.classList.remove('light-theme');
        localStorage.setItem('site-theme','dark');
        themeBtn.innerText = '🌙';
      } else {
        root.classList.add('light-theme');
        localStorage.setItem('site-theme','light');
        themeBtn.innerText = '☀️';
      }
    })
  }
});

/* Additional UI behaviors inspired by 111.html */
(function(){
  // Smooth scroll for same-page anchors
  document.querySelectorAll('a[href^="#"]').forEach(a=>{
    a.addEventListener('click', function(e){
      const href = this.getAttribute('href');
      if(href === '#' || href === '') return;
      const target = document.querySelector(href);
      if(target){
        e.preventDefault();
        target.scrollIntoView({behavior:'smooth',block:'start'});
        // close mobile nav if open
        if(document.body.classList.contains('nav-open')){
          document.body.classList.remove('nav-open');
        }
      }
    })
  })

  // Mobile nav toggle (expect a button with id 'mobile-nav-toggle')
  const mobileToggle = document.getElementById('mobile-nav-toggle');
  if(mobileToggle){
    mobileToggle.addEventListener('click', ()=>{
      document.body.classList.toggle('nav-open');
    })
  }
  document.querySelectorAll('[data-close-nav]').forEach((el)=>{
    el.addEventListener('click', ()=>document.body.classList.remove('nav-open'))
  })
  document.querySelectorAll('.mobile-nav a').forEach((link)=>{
    link.addEventListener('click', ()=>document.body.classList.remove('nav-open'))
  })
  window.addEventListener('keydown',(evt)=>{
    if(evt.key === 'Escape') document.body.classList.remove('nav-open')
  })

  // Back-to-top button
  let backBtn = document.querySelector('.back-to-top');
  if(!backBtn){
    backBtn = document.createElement('button');
    backBtn.className = 'back-to-top';
    backBtn.setAttribute('aria-label','回到顶部');
    backBtn.innerHTML = '↑';
    document.body.appendChild(backBtn);
  }
  const toggleBackBtn = ()=>{
    if(window.scrollY > 300) backBtn.classList.add('show'); else backBtn.classList.remove('show');
  }
  window.addEventListener('scroll', toggleBackBtn);
  backBtn.addEventListener('click', ()=>{ window.scrollTo({top:0,behavior:'smooth'}) });

  // Chart.js safe init: only run if Chart exists and a canvas with id 'statsChart' present
  try{
    if(window.Chart){
      const ctx = document.getElementById('statsChart');
      if(ctx){
        // create a lightweight example chart if no dataset present
        const data = ctx.dataset && ctx.dataset.values ? JSON.parse(ctx.dataset.values) : [12,19,6,8,10,5];
        new Chart(ctx.getContext('2d'),{
          type:'line',
          data:{labels:data.map((_,i)=>i+1),datasets:[{label:'示例',data:data,backgroundColor:'rgba(11,95,255,0.12)',borderColor:'rgba(11,95,255,0.9)',tension:0.3}]},
          options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}}}
        });
      }
    }
  }catch(e){console.warn('Chart init skipped',e)}

})();

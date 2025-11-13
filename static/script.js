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

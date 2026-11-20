(function () {
  // get set theme, if any
  var stored = null;
  stored = window.localStorage.getItem('theme');

  var choice = stored === 'light' || stored === 'dark' ? stored : null; // missing key is null

  // get OS theme, if any
  var systemMode = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';

  // update
  document.documentElement.setAttribute('data-theme', choice || systemMode);
})();

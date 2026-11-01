/*
 * QRShare - global loading modal.
 *
 * Loaded in <head> on every page. It automatically shows a blocking
 * "please wait" modal for:
 *   - form submits (login, register, logout, folder / trash / admin actions)
 *   - same-site link clicks (page navigations, downloads)
 *   - every fetch() call
 * and exposes window.QRLoading for manual control (uploads, etc.).
 *
 * Opt out per element with data-no-loader, or per fetch with { loader: false }
 * (used for the background polling).
 */
(function () {
  'use strict';

  var SHOW_DELAY_MS = 120;   // skip the modal for instant actions (no flicker)
  var HIDE_DELAY_MS = 150;   // bridge the gap between back-to-back requests
  var DEFAULT_MAX_MS = 60000; // failsafe so a stuck request never traps the user
  var DOWNLOAD_HIDE_MS = 3500; // downloads don't leave the page, so auto-close

  var holds = 0;
  var message = null;
  var overlay, titleEl, subEl, barEl, fillEl;
  var showTimer = null, hideTimer = null, failsafeTimer = null, slowTimers = [];
  var visible = false;

  function build() {
    if (overlay || !document.body) return;
    overlay = document.createElement('div');
    overlay.className = 'qrl-overlay';
    overlay.setAttribute('role', 'alertdialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-live', 'polite');
    overlay.setAttribute('aria-busy', 'true');
    overlay.innerHTML =
      '<div class="qrl-card">' +
        '<div class="qrl-spinner" aria-hidden="true"></div>' +
        '<p class="qrl-title"></p>' +
        '<p class="qrl-sub"></p>' +
        '<div class="qrl-bar" aria-hidden="true"><div class="qrl-bar-fill"></div></div>' +
      '</div>';
    document.body.appendChild(overlay);
    titleEl = overlay.querySelector('.qrl-title');
    subEl = overlay.querySelector('.qrl-sub');
    barEl = overlay.querySelector('.qrl-bar');
    fillEl = overlay.querySelector('.qrl-bar-fill');
  }

  function clearSlow() {
    slowTimers.forEach(clearTimeout);
    slowTimers = [];
  }

  function reveal() {
    build();
    if (!overlay) { showTimer = setTimeout(reveal, 50); return; }
    titleEl.textContent = message || 'Please wait\u2026';
    subEl.textContent = 'Please don\u2019t close or refresh this page.';
    overlay.classList.add('qrl-visible');
    visible = true;
    clearSlow();
    slowTimers.push(setTimeout(function () {
      if (visible) subEl.textContent = 'Still working\u2026 the server may be waking up.';
    }, 6000));
    slowTimers.push(setTimeout(function () {
      if (visible) subEl.textContent = 'This is taking longer than usual. Hang tight!';
    }, 15000));
  }

  function hideNow() {
    clearTimeout(showTimer); clearTimeout(hideTimer); clearTimeout(failsafeTimer);
    clearSlow();
    holds = 0;
    message = null;
    if (overlay) {
      overlay.classList.remove('qrl-visible');
      if (barEl) barEl.classList.remove('qrl-has-progress');
      if (fillEl) fillEl.style.width = '0%';
    }
    visible = false;
  }

  function setText(msg) {
    message = msg;
    if (visible && titleEl) titleEl.textContent = msg;
  }

  /** Begin (or join) a loading period. Pair every start() with a stop(). */
  function start(msg, opts) {
    opts = opts || {};
    clearTimeout(hideTimer);
    holds += 1;
    if (msg) setText(msg);
    if (holds === 1) {
      clearTimeout(showTimer);
      showTimer = setTimeout(reveal, SHOW_DELAY_MS);
    }
    var maxMs = opts.maxMs === undefined ? DEFAULT_MAX_MS : opts.maxMs;
    clearTimeout(failsafeTimer);
    if (maxMs > 0) failsafeTimer = setTimeout(hideNow, maxMs);
  }

  /** End one loading period; the modal closes once every period has ended. */
  function stop() {
    holds = Math.max(0, holds - 1);
    if (holds > 0) return;
    clearTimeout(showTimer);
    clearTimeout(hideTimer);
    hideTimer = setTimeout(hideNow, visible ? HIDE_DELAY_MS : 0);
  }

  /** Update the determinate progress bar (0-100). */
  function progress(pct) {
    build();
    if (!barEl) return;
    barEl.classList.add('qrl-has-progress');
    fillEl.style.width = Math.max(0, Math.min(100, pct)) + '%';
  }

  /** Navigate with the modal up. Auto-closes shortly after for file downloads. */
  function go(url, msg) {
    start(msg || 'Loading\u2026');
    setTimeout(stop, DOWNLOAD_HIDE_MS);
    window.location.href = url;
  }

  function labelFor(url) {
    var path = '';
    try { path = new URL(url, location.href).pathname; } catch (e) { path = String(url || ''); }
    var map = [
      [/^\/login/, 'Signing you in\u2026'],
      [/^\/register/, 'Creating your account\u2026'],
      [/^\/logout/, 'Signing you out\u2026'],
      [/^\/item\/create_folder/, 'Creating folder\u2026'],
      [/^\/item\/trash\//, 'Moving to trash\u2026'],
      [/^\/item\/restore\//, 'Restoring item\u2026'],
      [/^\/item\/delete_forever\//, 'Deleting permanently\u2026'],
      [/^\/item\/star\//, 'Updating favorites\u2026'],
      [/^\/admin\/delete_user\//, 'Removing user\u2026'],
      [/^\/admin\/delete_file\//, 'Purging file\u2026'],
      [/^\/admin/, 'Opening admin panel\u2026'],
      [/^\/folder\//, 'Opening folder\u2026'],
      [/^\/virtual\//, 'Loading files\u2026'],
      [/^\/download\//, 'Preparing your download\u2026'],
      [/^\/share\/.+\/download/, 'Authenticating secure link\u2026'],
      [/^\/share\//, 'Opening shared file\u2026'],
      [/^\/api\/upload\/sign/, 'Preparing secure upload\u2026'],
      [/^\/api\/upload\/finalize/, 'Verifying file safety\u2026'],
      [/^\/api\/item\/share\//, 'Generating QR code\u2026']
    ];
    for (var i = 0; i < map.length; i++) if (map[i][0].test(path)) return map[i][1];
    return 'Please wait\u2026';
  }

  /* ---- fetch(): every request shows the modal unless { loader: false } ---- */
  if (window.fetch) {
    var nativeFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      if (init && init.loader === false) return nativeFetch(input, init);
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      start(labelFor(url));
      return nativeFetch(input, init).then(
        function (res) { stop(); return res; },
        function (err) { stop(); throw err; }
      );
    };
  }

  /* ---- form submits ---- */
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (e.defaultPrevented || !form || form.hasAttribute('data-no-loader')) return;
    start(labelFor(form.getAttribute('action') || location.pathname));
  });

  /* ---- same-site link navigation ---- */
  document.addEventListener('click', function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var a = e.target.closest && e.target.closest('a[href]');
    if (!a || a.hasAttribute('data-no-loader') || a.hasAttribute('download')) return;
    if (a.target && a.target !== '_self') return;
    var href = a.getAttribute('href') || '';
    if (!href || href.charAt(0) === '#' || /^(javascript|mailto|tel):/i.test(href)) return;
    var url;
    try { url = new URL(a.href, location.href); } catch (err) { return; }
    if (url.origin !== location.origin) return;
    if (url.pathname === location.pathname && url.search === location.search) return;
    start(labelFor(url.pathname));
    if (/^\/download\//.test(url.pathname)) setTimeout(stop, DOWNLOAD_HIDE_MS);
  });

  /* Back/forward cache restores the old page with the modal still up. */
  window.addEventListener('pageshow', function (e) { if (e.persisted) hideNow(); });

  window.QRLoading = { start: start, stop: stop, text: setText, progress: progress, go: go,
                       labelFor: labelFor, reset: hideNow };
})();

(function () {
  'use strict';

  var CSRF = document.querySelector('meta[name=csrf]').content;
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return MAP[c]; }); };
  var ico = function (n) { return '<svg class="ic"><use href="#i-' + n + '"/></svg>'; };

  var state = { tab: 'overview', keys: {}, connectUrl: '', snip: 'python', host: null };
  var TITLES = { overview: 'Overview', keys: 'Keys', logs: 'Activity', connect: 'Connect' };

  /* ---------- helpers ---------- */
  function api(path, opts) {
    opts = opts || {};
    var o = { method: opts.method || 'GET', headers: {}, credentials: 'same-origin' };
    if (opts.body !== undefined) { o.body = JSON.stringify(opts.body); o.headers['Content-Type'] = 'application/json'; }
    if (o.method !== 'GET') o.headers['X-CSRF'] = CSRF;
    return fetch(path, o).then(function (r) {
      if (r.status === 401) { location.href = '/login'; throw new Error('Signed out'); }
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.message || d.error || 'Request failed');
        return d;
      });
    });
  }

  function toast(msg, kind) {
    var el = document.createElement('div');
    el.className = 'toast ' + (kind || 'ok');
    el.innerHTML = ico(kind === 'err' ? 'x' : 'check') + '<span>' + esc(msg) + '</span>';
    $('#toasts').appendChild(el);
    setTimeout(function () { el.classList.add('out'); setTimeout(function () { el.remove(); }, 250); }, 3200);
  }

  function copy(text) {
    var done = function () { toast('Copied to clipboard'); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else { fallback(); }
    function fallback() {
      var t = document.createElement('textarea');
      t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
      document.body.appendChild(t); t.select();
      try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed', 'err'); }
      t.remove();
    }
  }

  function fmt(iso) {
    if (!iso) return '-';
    var d = new Date(iso);
    return d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  }
  function ago(iso) {
    if (!iso) return 'Never';
    var s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'Just now';
    if (s < 3600) return Math.floor(s / 60) + ' min ago';
    if (s < 86400) return Math.floor(s / 3600) + ' h ago';
    return Math.floor(s / 86400) + ' d ago';
  }
  function uptime(sec) {
    var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    return (d ? d + 'd ' : '') + (h ? h + 'h ' : '') + m + 'm';
  }
  function busy(btn, on) { if (btn) { btn.disabled = on; btn.classList.toggle('loading', on); } }
  function debounce(fn, ms) { var t; return function () { var a = arguments; clearTimeout(t); t = setTimeout(function () { fn.apply(null, a); }, ms); }; }

  /* ---------- modals ---------- */
  function openModal(id) { var m = $(id); m.hidden = false; var f = $('input,select,button.btn-primary', m); if (f) setTimeout(function () { f.focus(); }, 30); }
  function closeModals() { $$('.modal').forEach(function (m) { m.hidden = true; }); }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeModals(); });
  $$('.modal').forEach(function (m) {
    m.addEventListener('mousedown', function (e) { if (e.target === m) closeModals(); });
    $$('[data-close]', m).forEach(function (b) { b.addEventListener('click', closeModals); });
  });

  var confirmResolve = null;
  function confirmBox(title, text, label) {
    $('#cTitle').textContent = title; $('#cText').textContent = text; $('#cGo').textContent = label || 'Confirm';
    openModal('#confirmModal');
    return new Promise(function (res) { confirmResolve = res; });
  }
  $('#cGo').addEventListener('click', function () { closeModals(); if (confirmResolve) confirmResolve(true); confirmResolve = null; });
  $('#confirmModal').addEventListener('click', function (e) {
    if (e.target.closest('[data-close]') || e.target === this) { if (confirmResolve) confirmResolve(false); confirmResolve = null; }
  });

  /* ---------- tabs ---------- */
  function showTab(t) {
    state.tab = t;
    $$('#nav button').forEach(function (b) { b.classList.toggle('on', b.dataset.tab === t); });
    $$('.tab').forEach(function (s) { s.classList.toggle('on', s.id === 'tab-' + t); });
    $('#pageTitle').textContent = TITLES[t];
    load();
  }
  $$('#nav button').forEach(function (b) { b.addEventListener('click', function () { showTab(b.dataset.tab); }); });

  function load() {
    var p = state.tab === 'overview' ? loadOverview() : state.tab === 'keys' ? loadKeys() :
      state.tab === 'logs' ? loadLogs() : loadOverview();
    return p.catch(function (e) { toast(e.message, 'err'); });
  }

  /* ---------- overview + connect ---------- */
  function kv(rows) {
    return rows.filter(function (r) { return r[1]; }).map(function (r) {
      return '<div><dt>' + esc(r[0]) + '</dt><dd>' + esc(r[1]) + '</dd></div>';
    }).join('');
  }

  function loadOverview() {
    return api('/api/admin/overview').then(function (d) {
      var s = d.stats;
      var cards = [
        ['key', 'Total keys', s.total], ['shield', 'Active', s.active], ['clock', 'Expired', s.expired],
        ['ban', 'Revoked', s.revoked], ['monitor', 'Bound devices', s.devices], ['activity', 'Checks today', s.checks_today]
      ];
      $('#stats').innerHTML = cards.map(function (c) {
        return '<div class="glass stat">' + ico(c[0]) + '<div><b>' + c[2] + '</b><span>' + c[1] + '</span></div></div>';
      }).join('');

      var max = Math.max.apply(null, d.series.map(function (x) { return x.ok + x.fail; }).concat([1]));
      $('#bars').innerHTML = d.series.map(function (x) {
        var day = new Date(x.day + 'T00:00:00').toLocaleDateString([], { weekday: 'short' });
        return '<div class="bar" title="' + x.ok + ' accepted, ' + x.fail + ' rejected"><div class="bar-col">' +
          '<i class="seg fail" style="height:' + (x.fail / max * 100) + '%"></i>' +
          '<i class="seg ok" style="height:' + (x.ok / max * 100) + '%"></i></div><span>' + esc(day) + '</span></div>';
      }).join('');

      state.connectUrl = d.connect_url; state.host = d.host;
      $('#hostLine').textContent = d.host.name + (d.host.service ? ' - ' + d.host.service : '');
      $('#sysInfo').innerHTML = kv([
        ['Hosting', d.host.name], ['Database', d.system.database], ['Python', d.system.python],
        ['Uptime', uptime(d.system.uptime_seconds)], ['Server time', fmt(d.system.server_time)]
      ]);
      $('#connectUrl').textContent = d.connect_url;
      $('#hostInfo').innerHTML = kv([
        ['Hosting provider', d.host.name], ['Service name', d.host.service], ['Public address', d.host.external_url],
        ['Region', d.host.region], ['Instance', d.host.instance]
      ]);
      renderSnippet();
    });
  }

  function snippets(url) {
    return {
      python: 'import requests, uuid\n\nres = requests.post(\n    "' + url + '",\n    json={"key": "MAFIA-XXXX-XXXX-XXXX-XXXX",\n          "device_id": hex(uuid.getnode())},\n    timeout=15,\n)\ndata = res.json()\nif data.get("ok"):\n    print("Licensed:", data["plan"], data["days_left"])\nelse:\n    print("Rejected:", data["error"])',
      js: 'const res = await fetch("' + url + '", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify({\n    key: "MAFIA-XXXX-XXXX-XXXX-XXXX",\n    device_id: "unique-device-id",\n  }),\n});\nconst data = await res.json();\nconsole.log(data.ok ? data.plan : data.error);',
      curl: 'curl -X POST "' + url + '" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"key":"MAFIA-XXXX-XXXX-XXXX-XXXX","device_id":"unique-device-id"}\''
    };
  }
  function renderSnippet() {
    if (!state.connectUrl) return;
    $('#snippet').textContent = snippets(state.connectUrl)[state.snip];
  }
  $$('#snipTabs button').forEach(function (b) {
    b.addEventListener('click', function () {
      state.snip = b.dataset.s;
      $$('#snipTabs button').forEach(function (x) { x.classList.toggle('on', x === b); });
      renderSnippet();
    });
  });
  $('#copyUrl').addEventListener('click', function () { copy(state.connectUrl); });
  $('#copySnip').addEventListener('click', function () { copy($('#snippet').textContent); });

  /* ---------- keys ---------- */
  function badge(st) { return '<span class="badge ' + st + '">' + st.charAt(0).toUpperCase() + st.slice(1) + '</span>'; }

  function loadKeys() {
    var q = encodeURIComponent($('#q').value.trim());
    return api('/api/admin/keys?q=' + q + '&status=' + $('#statusFilter').value).then(function (d) {
      state.keys = {};
      d.keys.forEach(function (k) { state.keys[k.id] = k; });
      $('#keysEmpty').hidden = d.keys.length > 0;
      $('#keyRows').innerHTML = d.keys.map(function (k) {
        var exp = k.lifetime ? 'Lifetime' : fmt(k.expires_at) + (k.status === 'active' ? ' (' + k.days_left + ' d left)' : '');
        return '<tr>' +
          '<td><code class="keycode">' + esc(k.key) + '</code></td>' +
          '<td>' + (esc(k.label) || '<span class="muted">-</span>') + '</td>' +
          '<td>' + esc(k.plan) + '</td><td>' + badge(k.status) + '</td>' +
          '<td>' + k.devices + ' / ' + k.max_devices + '</td>' +
          '<td>' + esc(exp) + '</td><td>' + esc(ago(k.last_used_at)) + '</td>' +
          '<td class="r"><div class="row-actions">' +
          '<button class="icon-btn" data-act="copy" data-id="' + k.id + '" aria-label="Copy key" title="Copy key">' + ico('copy') + '</button>' +
          '<button class="icon-btn" data-act="manage" data-id="' + k.id + '" aria-label="Manage key" title="Manage">' + ico('sliders') + '</button>' +
          '<button class="icon-btn" data-act="toggle" data-id="' + k.id + '" aria-label="' + (k.status === 'revoked' ? 'Activate' : 'Revoke') + ' key" title="' + (k.status === 'revoked' ? 'Activate' : 'Revoke') + '">' + ico(k.status === 'revoked' ? 'check' : 'ban') + '</button>' +
          '<button class="icon-btn danger" data-act="delete" data-id="' + k.id + '" aria-label="Delete key" title="Delete">' + ico('trash') + '</button>' +
          '</div></td></tr>';
      }).join('');
    });
  }

  $('#keyRows').addEventListener('click', function (e) {
    var b = e.target.closest('button[data-act]'); if (!b) return;
    var k = state.keys[b.dataset.id]; if (!k) return;
    var act = b.dataset.act;
    if (act === 'copy') return copy(k.key);
    if (act === 'manage') return openManage(k.id);
    if (act === 'toggle') {
      var revoke = k.status !== 'revoked';
      return api('/api/admin/keys/' + k.id, { method: 'PATCH', body: { revoked: revoke } })
        .then(function () { toast(revoke ? 'Key revoked' : 'Key activated'); return loadKeys(); })
        .catch(function (er) { toast(er.message, 'err'); });
    }
    if (act === 'delete') {
      confirmBox('Delete this key', k.key + ' and its device list will be removed permanently.', 'Delete key').then(function (ok) {
        if (!ok) return;
        api('/api/admin/keys/' + k.id, { method: 'DELETE' })
          .then(function () { toast('Key deleted'); return loadKeys(); })
          .catch(function (er) { toast(er.message, 'err'); });
      });
    }
  });
  $('#q').addEventListener('input', debounce(function () { loadKeys().catch(function (e) { toast(e.message, 'err'); }); }, 250));
  $('#statusFilter').addEventListener('change', function () { loadKeys().catch(function (e) { toast(e.message, 'err'); }); });

  /* ---------- generate ---------- */
  $('#newKeyBtn').addEventListener('click', function () { $('#genResult').hidden = true; openModal('#genModal'); });
  $('#genGo').addEventListener('click', function () {
    var btn = this; busy(btn, true);
    api('/api/admin/keys', { method: 'POST', body: {
      count: $('#gCount').value, plan: $('#gPlan').value, days: $('#gDays').value,
      max_devices: $('#gDev').value, prefix: $('#gPrefix').value, label: $('#gLabel').value
    } }).then(function (d) {
      $('#genOut').value = d.keys.join('\n');
      $('#genCount').textContent = d.keys.length + (d.keys.length === 1 ? ' key created' : ' keys created');
      $('#genResult').hidden = false;
      toast('Keys generated');
      if (state.tab === 'keys') loadKeys(); else if (state.tab === 'overview') loadOverview();
    }).catch(function (e) { toast(e.message, 'err'); }).then(function () { busy(btn, false); });
  });
  $('#copyGen').addEventListener('click', function () { copy($('#genOut').value); });

  /* ---------- manage ---------- */
  var managing = null;
  function openManage(id) {
    api('/api/admin/keys/' + id).then(function (d) {
      managing = d.key;
      $('#mKey').textContent = d.key.key;
      $('#mLabel').value = d.key.label; $('#mPlan').value = d.key.plan;
      if (![].some.call($('#mPlan').options, function (o) { return o.value === d.key.plan; })) {
        var o = document.createElement('option'); o.textContent = d.key.plan; $('#mPlan').appendChild(o); $('#mPlan').value = d.key.plan;
      }
      $('#mDev').value = d.key.max_devices; $('#mDays').value = 0; $('#mLife').checked = false;
      $('#mExpiry').textContent = d.key.lifetime ? 'This key never expires.' : 'Expires ' + fmt(d.key.expires_at) + '.';
      renderDevices(d.devices);
      openModal('#manageModal');
    }).catch(function (e) { toast(e.message, 'err'); });
  }
  function renderDevices(list) {
    $('#mDevices').innerHTML = list.length ? list.map(function (v) {
      return '<div class="dev">' + ico('monitor') + '<div><b>' + esc(v.device_id) + '</b><span>' + esc(v.ip) + ' - last seen ' + esc(ago(v.last_seen)) +
        '</span></div><button class="icon-btn danger" data-dev="' + v.id + '" aria-label="Remove device" title="Remove device">' + ico('x') + '</button></div>';
    }).join('') : '<p class="muted">No device has used this key yet.</p>';
  }
  $('#mDevices').addEventListener('click', function (e) {
    var b = e.target.closest('button[data-dev]'); if (!b) return;
    api('/api/admin/devices/' + b.dataset.dev, { method: 'DELETE' }).then(function () {
      toast('Device removed'); openManage(managing.id); if (state.tab === 'keys') loadKeys();
    }).catch(function (er) { toast(er.message, 'err'); });
  });
  $('#mReset').addEventListener('click', function () {
    confirmBox('Reset devices', 'All devices bound to this key will be released so it can be used on new ones.', 'Reset devices').then(function (ok) {
      if (!ok) return;
      api('/api/admin/keys/' + managing.id + '/reset-devices', { method: 'POST' }).then(function () {
        toast('Devices reset'); if (state.tab === 'keys') loadKeys();
      }).catch(function (er) { toast(er.message, 'err'); });
    });
  });
  $('#mSave').addEventListener('click', function () {
    var btn = this; busy(btn, true);
    api('/api/admin/keys/' + managing.id, { method: 'PATCH', body: {
      label: $('#mLabel').value, plan: $('#mPlan').value, max_devices: $('#mDev').value,
      add_days: $('#mDays').value, lifetime: $('#mLife').checked
    } }).then(function () { toast('Key updated'); closeModals(); loadKeys(); })
      .catch(function (e) { toast(e.message, 'err'); }).then(function () { busy(btn, false); });
  });

  /* ---------- logs ---------- */
  var LOGNAME = { verify_ok: 'Key accepted', verify_fail: 'Key rejected', login: 'Admin sign in', login_fail: 'Failed sign in',
    keys_created: 'Keys created', key_updated: 'Key updated', key_deleted: 'Key deleted', devices_reset: 'Devices reset', device_removed: 'Device removed' };
  function loadLogs() {
    return api('/api/admin/logs?kind=' + $('#logKind').value).then(function (d) {
      $('#logsEmpty').hidden = d.logs.length > 0;
      $('#logRows').innerHTML = d.logs.map(function (l) {
        var bad = l.action === 'verify_fail' || l.action === 'login_fail';
        return '<tr><td>' + esc(fmt(l.ts)) + '</td><td><span class="badge ' + (bad ? 'revoked' : l.action === 'verify_ok' ? 'active' : 'info') + '">' +
          esc(LOGNAME[l.action] || l.action) + '</span></td><td><code class="keycode">' + esc(l.detail) + '</code></td><td>' + esc(l.ip) + '</td></tr>';
      }).join('');
    });
  }
  $('#logKind').addEventListener('change', function () { loadLogs().catch(function (e) { toast(e.message, 'err'); }); });

  /* ---------- global ---------- */
  $('#refreshBtn').addEventListener('click', function () { load().then(function () { toast('Refreshed'); }); });
  $('#logoutBtn').addEventListener('click', function () {
    api('/logout', { method: 'POST' }).then(function () { location.href = '/login'; });
  });

  load();
  loadOverview().catch(function () {});
  setInterval(function () { if (!document.hidden && state.tab === 'overview') loadOverview().catch(function () {}); }, 30000);
})();

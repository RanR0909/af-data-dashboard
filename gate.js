(function () {
  'use strict';
  var gate = document.getElementById('gate'), workspace = document.getElementById('workspace'), form = document.getElementById('unlock-form');
  var input = document.getElementById('password'), message = document.getElementById('message'), submit = document.getElementById('submit');
  var refresh = document.getElementById('new-version'), frame = null, objectURL = null, password = null, version = null, pending = null;
  function bytes(text) { return Uint8Array.from(atob(text), function (char) { return char.charCodeAt(0); }); }
  function hex(data) { return Array.from(new Uint8Array(data)).map(function (byte) { return byte.toString(16).padStart(2, '0'); }).join(''); }
  function validHash(hash) { return /^#\/[a-z]+(?:\?[^\r\n]*)?$/.test(hash) && hash.length <= 12000 ? hash : '#/today'; }
  async function manifest() {
    var response = await fetch('manifest.json?fresh=' + Date.now(), { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!response.ok) throw new Error('network');
    var item = await response.json();
    if (item.format !== 1 || item.cipher !== 'AES-256-GCM' || item.kdf !== 'PBKDF2-SHA256' || item.iterations !== 600000 ||
        item.file !== 'snapshot.bin' || !/^[a-f0-9]{64}$/.test(item.sha256) || bytes(item.salt).length !== 16 || bytes(item.iv).length !== 12) throw new Error('format');
    return item;
  }
  async function decrypt(item, secret) {
    var response = await fetch(item.file + '?v=' + item.sha256, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!response.ok) throw new Error('network');
    var encrypted = await response.arrayBuffer();
    if (hex(await crypto.subtle.digest('SHA-256', encrypted)) !== item.sha256) throw new Error('integrity');
    var material = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveKey']);
    var key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: bytes(item.salt), iterations: item.iterations }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    var compressed;
    try { compressed = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(item.iv), tagLength: 128, additionalData: new TextEncoder().encode('AF-DASHBOARD-V1') }, key, encrypted); }
    catch (error) { throw new Error('password'); }
    var html = await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    if (!html.startsWith('<!doctype html>') || !html.includes('af-encrypted-snapshot-v1')) throw new Error('format');
    return html;
  }
  function show(html, item) {
    var hash = frame ? validHash(frame.contentWindow.location.hash) : validHash(location.hash);
    var previous = objectURL;
    objectURL = URL.createObjectURL(new Blob([html], { type: 'text/html;charset=utf-8' }));
    var next = document.createElement('iframe'); next.title = 'AF 数据看板';
    next.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-downloads allow-popups');
    next.src = objectURL + hash;
    workspace.replaceChildren(next); frame = next; version = item.sha256; pending = null;
    workspace.hidden = false; gate.hidden = true; refresh.hidden = true;
    if (previous) URL.revokeObjectURL(previous);
  }
  function lock() {
    workspace.replaceChildren(); frame = null; password = null; version = null; pending = null;
    if (objectURL) URL.revokeObjectURL(objectURL); objectURL = null;
    workspace.hidden = true; gate.hidden = false; refresh.hidden = true; input.value = ''; message.textContent = ''; input.focus();
  }
  function friendly(error) {
    return { password: '访问密码不正确，或维护人已更换密码。', network: '暂时无法读取发布文件，请稍后重试。', integrity: '发布文件未完整读取，请稍后重试。', format: '发布文件格式不支持，请联系维护人。' }[error.message] || '暂时无法解锁，请重试或联系维护人。';
  }
  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (!window.crypto || !crypto.subtle || !window.DecompressionStream) { message.textContent = '请通过 HTTPS，使用最新版 Chrome、Edge 或 Safari 打开。'; return; }
    var secret = input.value.trim(); if (!secret) return;
    submit.disabled = true; submit.textContent = '正在解锁…'; message.textContent = '';
    try { var item = await manifest(), html = await decrypt(item, secret); password = secret; input.value = ''; show(html, item); }
    catch (error) { message.textContent = friendly(error); }
    finally { submit.disabled = false; submit.textContent = '解锁面板'; }
  });
  document.getElementById('show-password').addEventListener('click', function (event) {
    var visible = input.type === 'password'; input.type = visible ? 'text' : 'password';
    event.currentTarget.textContent = visible ? '隐藏' : '显示'; event.currentTarget.setAttribute('aria-pressed', String(visible)); input.focus();
  });
  window.addEventListener('message', function (event) {
    if (!frame || event.source !== frame.contentWindow || event.origin !== location.origin || !event.data) return;
    if (event.data.type === 'af-host-lock') lock();
    if (event.data.type === 'af-host-route') history.replaceState(null, '', location.pathname + location.search + validHash(event.data.hash || ''));
  });
  refresh.addEventListener('click', async function () {
    refresh.disabled = true;
    try { var item = pending || await manifest(), html = await decrypt(item, password); show(html, item); }
    catch (error) { var notice = document.getElementById('notice'); notice.hidden = false; notice.textContent = friendly(error); setTimeout(function () { notice.hidden = true; }, 7000); }
    finally { refresh.disabled = false; }
  });
  setInterval(async function () {
    if (!frame || !password || document.hidden) return;
    try { var item = await manifest(); if (item.sha256 !== version) { pending = item; refresh.hidden = false; } } catch (error) { /* 不影响已解锁的上一版。 */ }
  }, 300000);
})();

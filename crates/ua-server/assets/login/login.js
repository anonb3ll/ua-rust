// Passkey sign-in (/login) and registration (/login/passkeys).
// Served by the hub at /login/assets/login.js; the pages run no inline
// script and pass their values in data- attributes:
//   #go  data-next  where to go after signing in
//   #add data-csrf  the browser session's CSRF token
(() => {
  'use strict';
  const b64u = {
    dec: (s) => Uint8Array.from(
      atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)),
      (c) => c.charCodeAt(0),
    ),
    enc: (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  };
  const say = (m) => {
    const el = document.getElementById('msg');
    if (el) el.textContent = m;
  };
  const post = (url, headers, body) => fetch(url, { method: 'POST', headers, body });

  const go = document.getElementById('go');
  if (go) {
    go.addEventListener('click', async () => {
      try {
        const label = document.getElementById('label').value.trim();
        const json = { 'content-type': 'application/json' };
        let r = await post('/login/passkey/start', json, JSON.stringify({ label }));
        let j = await r.json();
        if (!r.ok) return say(j.message || 'Sign-in failed');
        const pk = j.options.publicKey;
        pk.challenge = b64u.dec(pk.challenge);
        (pk.allowCredentials || []).forEach((c) => { c.id = b64u.dec(c.id); });
        const c = await navigator.credentials.get({ publicKey: pk });
        const credential = {
          id: c.id, rawId: b64u.enc(c.rawId), type: c.type, extensions: {},
          response: {
            authenticatorData: b64u.enc(c.response.authenticatorData),
            clientDataJSON: b64u.enc(c.response.clientDataJSON),
            signature: b64u.enc(c.response.signature),
            userHandle: c.response.userHandle ? b64u.enc(c.response.userHandle) : null,
          },
        };
        r = await post('/login/passkey/finish', json,
          JSON.stringify({ state_id: j.state_id, credential, next: go.dataset.next || '/ui' }));
        j = await r.json();
        if (!r.ok) return say(j.message || 'Sign-in failed');
        location.href = j.next;
      } catch (e) {
        say('Sign-in was cancelled or failed.');
      }
    });
  }

  const add = document.getElementById('add');
  if (add) {
    add.addEventListener('click', async () => {
      try {
        const h = { 'content-type': 'application/json', 'X-CSRF-Token': add.dataset.csrf || '' };
        let r = await post('/login/passkeys/register/start', h);
        let j = await r.json();
        if (!r.ok) return say(j.message || 'Could not start');
        const pk = j.options.publicKey;
        pk.challenge = b64u.dec(pk.challenge);
        pk.user.id = b64u.dec(pk.user.id);
        (pk.excludeCredentials || []).forEach((c) => { c.id = b64u.dec(c.id); });
        const c = await navigator.credentials.create({ publicKey: pk });
        const credential = {
          id: c.id, rawId: b64u.enc(c.rawId), type: c.type, extensions: {},
          response: {
            attestationObject: b64u.enc(c.response.attestationObject),
            clientDataJSON: b64u.enc(c.response.clientDataJSON),
          },
        };
        r = await post('/login/passkeys/register/finish', h, JSON.stringify({
          state_id: j.state_id, credential, name: document.getElementById('name').value,
        }));
        j = await r.json();
        if (!r.ok) return say(j.message || 'Registration failed');
        location.reload();
      } catch (e) {
        say('Registration was cancelled or failed.');
      }
    });
  }
})();

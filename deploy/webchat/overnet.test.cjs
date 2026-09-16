const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
const tick = () => new Promise((resolve) => setImmediate(resolve));

function setup() {
  const handlers = {}, raw = [], requests = [], notes = [], messages = new Set(), closes = [];
  const network = { serverBuffer: () => ({}), ircClient: {
    raw: (...args) => {
      const event = { network, message: { command: args[0], params: args.slice(1) }, handled: false };
      handlers.ircout?.(event);
      if (!event.handled) raw.push(args);
    },
    quit: (message) => raw.push(['QUIT', message]),
    once: (event, handler) => closes.push(handler),
  } };
  const window = {
    addEventListener: (type, handler) => messages.add(handler),
    removeEventListener: (type, handler) => messages.delete(handler),
    postMessage: (message) => {
      requests.push(message);
      if (message.method === 'provider.info') queueMicrotask(() => reply(message.id, { version: 1 }));
    },
  };
  const reply = (id, result, error) => {
    for (const handler of [...messages]) handler({ source: window, origin: 'http://chat.example',
      data: { type: 'overnet:response', id, result, error } });
  };
  const kiwi = { plugin: (name, callback) => callback(kiwi), on: (name, callback) => { handlers[name] = callback; },
    state: { addMessage: (buffer, message) => notes.push(message.message) } };
  vm.runInNewContext(fs.readFileSync(`${__dirname}/overnet.js`, 'utf8'), { kiwi, window,
    location: { origin: 'http://chat.example' }, crypto, AbortController, TextDecoder, TextEncoder, atob, btoa,
    clearTimeout, setTimeout: (fn, delay) => setTimeout(fn, delay).unref() });
  const incoming = (command, params) => handlers['irc.raw'](command, { params }, network);
  const start = () => {
    handlers['network.connecting']({ network });
    incoming('CAP', ['*', 'LS', 'sasl=NOSTR']);
    incoming('CAP', ['*', 'ACK', 'sasl']);
  };
  const challenge = (payload) => {
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
    for (let i = 0; i < encoded.length; i += 400) incoming('AUTHENTICATE', [encoded.slice(i, i + 400)]);
    if (encoded.length % 400 === 0) incoming('AUTHENTICATE', ['+']);
  };
  const close = () => { for (const callback of closes.splice(0)) callback(); };
  return { network, raw, requests, notes, reply, incoming, start, challenge, close };
}

test('Kiwi waits for approval and transmits the combined exchange in SASL chunks', async () => {
  const s = setup();
  try {
    s.start();
    assert.deepEqual(s.raw, [['CAP', 'REQ', 'sasl'], ['AUTHENTICATE', 'NOSTR']]);
    s.network.ircClient.raw('CAP', 'END');
    assert.equal(s.raw.length, 2, 'CAP END is held until authentication succeeds');
    const challenge = { challenge: 'x'.repeat(500), scope: 'scope', delegate_pubkey: 'a'.repeat(64) };
    s.challenge(challenge); await tick();
    const request = s.requests.find((message) => message.method === 'authenticate');
    assert.deepEqual(JSON.parse(JSON.stringify(request.challenge)), challenge);
    const response = { auth_event: { content: 'ü'.repeat(600) }, delegate_event: { kind: 14142 } };
    s.reply(request.id, response); await tick();
    const chunks = s.raw.slice(2).map((command) => command[1]);
    assert.ok(chunks.every((chunk) => chunk.length <= 400));
    assert.deepEqual(JSON.parse(Buffer.from(chunks.filter((chunk) => chunk !== '+').join(''), 'base64').toString()), response);
    assert.equal(s.raw.some((command) => command[0] === 'CAP' && command[1] === 'END'), false);
    s.incoming('903', ['nick', 'SASL authentication successful']);
    assert.deepEqual(s.raw.at(-1), ['CAP', 'END']);
  } finally { s.close(); }
});

test('denial never registers a guest and preserves a useful connection error', async () => {
  const s = setup();
  try {
    s.start(); s.challenge({ scope: 'scope', challenge: 'nonce', delegate_pubkey: 'a'.repeat(64) }); await tick();
    s.reply(s.requests.find((message) => message.method === 'authenticate').id, undefined, 'Sign-in declined'); await tick();
    assert.equal(s.raw.some((command) => command[0] === 'CAP' && command[1] === 'END'), false);
    assert.equal(s.raw.at(-1)[0], 'QUIT');
    assert.match(s.network.last_error, /Sign-in declined/);
  } finally { s.close(); }
});

test('reconnect cancels the old approval and cannot use its late response', async () => {
  const s = setup();
  try {
    s.start(); s.challenge({ scope: 'scope', challenge: 'nonce', delegate_pubkey: 'a'.repeat(64) }); await tick();
    const request = s.requests.find((message) => message.method === 'authenticate');
    s.start(); const count = s.raw.length;
    assert.ok(s.requests.some((message) => message.id === request.id && message.method === 'cancel'));
    s.reply(request.id, { auth_event: {}, delegate_event: {} }); await tick();
    assert.equal(s.raw.length, count);
  } finally { s.close(); }
});

test('missing delegation and missing SASL fail closed', async () => {
  for (const withSasl of [false, true]) {
    const s = setup();
    try {
      if (withSasl) { s.start(); s.challenge({ scope: 'scope', challenge: 'nonce' }); }
      else { s.start(); s.incoming('CAP', ['*', 'NAK', 'sasl']); }
      await tick();
      assert.equal(s.requests.some((message) => message.method === 'authenticate'), false);
      assert.equal(s.raw.at(-1)[0], 'QUIT');
    } finally { s.close(); }
  }
});

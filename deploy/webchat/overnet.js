/* global kiwi */
// Kiwi owns the IRC connection. Overnet supplies only the shared signed exchange.
kiwi.plugin('overnet', (kiwi) => {
  const connections = new WeakMap();
  const responseType = 'overnet:response';

  function browserRequest(method, challenge, signal, timeout) {
    const id = [...crypto.getRandomValues(new Uint32Array(4))].join('-');
    const post = (method) => window.postMessage({ type: 'overnet:request', id, method, challenge }, location.origin);
    return new Promise((resolve, reject) => {
      const finish = (result, error) => {
        clearTimeout(timer);
        window.removeEventListener('message', receive);
        signal.removeEventListener('abort', abort);
        if (error) reject(new Error(error)); else resolve(result);
      };
      const receive = (event) => {
        if (event.source !== window || event.origin !== location.origin ||
            event.data?.type !== responseType || event.data.id !== id) return;
        finish(event.data.result, event.data.error);
      };
      const abort = () => { post('cancel'); finish(undefined, 'Sign-in cancelled'); };
      const timer = setTimeout(() => {
        post('cancel');
        finish(undefined, method === 'provider.info'
          ? 'Enable the Overnet extension and allow it on this website, then reload the page.'
          : 'Overnet sign-in timed out. Connect again to retry.');
      }, timeout);
      window.addEventListener('message', receive);
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort(); else post(method);
    });
  }

  function note(network, message) {
    kiwi.state.addMessage(network.serverBuffer(), { time: Date.now(), nick: '', message, type: 'notice' });
  }

  function fail(network, state, message) {
    if (state.phase === 'failed') return;
    state.phase = 'failed';
    clearTimeout(state.timer);
    state.controller.abort();
    network.last_error = `Overnet: ${message}`;
    note(network, network.last_error);
    network.ircClient.raw('AUTHENTICATE', '*');
    network.ircClient.quit('Overnet authentication failed');
  }

  kiwi.on('network.connecting', ({ network }) => {
    const previous = connections.get(network);
    if (previous) { clearTimeout(previous.timer); previous.controller.abort(); }
    const state = { phase: 'cap', capabilities: '', chunks: '', controller: new AbortController() };
    connections.set(network, state);
    network.ircClient.once('socket close', () => {
      clearTimeout(state.timer);
      state.controller.abort();
      if (connections.get(network) === state) connections.delete(network);
    });
    state.timer = setTimeout(() => fail(network, state, 'Sign-in timed out. Connect again.'), 150000);
  });

  kiwi.on('ircout', (event) => {
    const state = connections.get(event.network);
    if (state && event.message.command === 'CAP' && event.message.params.includes('END') && state.phase !== 'done') {
      event.handled = true;
    }
  });

  kiwi.on('irc.raw', (command, event, network) => {
    const state = connections.get(network);
    if (!state || state.phase === 'done' || state.phase === 'failed') return;
    const client = network.ircClient;
    if (command === 'CAP') {
      // Own SASL negotiation, so Kiwi never falls back to a password mechanism
      // or ends capability negotiation before the approval arrives.
      event.handled = true;
      const subcommand = event.params[1];
      const capabilities = event.params.at(-1).split(' ');
      if (subcommand === 'LS') {
        state.capabilities += ` ${capabilities.join(' ')}`;
        if (event.params[2] === '*') return;
        if (!state.capabilities.split(' ').some((cap) => cap === 'sasl' || cap.startsWith('sasl='))) {
          fail(network, state, 'The IRC server does not offer SASL authentication.'); return;
        }
        client.raw('CAP', 'REQ', 'sasl');
      } else if (subcommand === 'ACK' && capabilities.some((cap) => cap === 'sasl' || cap.startsWith('sasl='))) {
        state.phase = 'challenge';
        client.raw('AUTHENTICATE', 'NOSTR');
      } else if (subcommand === 'NAK') fail(network, state, 'The IRC server refused SASL authentication.');
    } else if (command === 'AUTHENTICATE') {
      event.handled = true;
      if (state.phase !== 'challenge') { fail(network, state, 'Unexpected authentication challenge.'); return; }
      const chunk = event.params[0];
      if (chunk !== '+') state.chunks += chunk;
      if (state.chunks.length > 65536 || typeof chunk !== 'string' || chunk.length > 400) {
        fail(network, state, 'Invalid authentication challenge.'); return;
      }
      if (chunk !== '+' && chunk.length === 400) return;
      state.phase = 'approval';
      authenticate(network, state).catch((error) => {
        if (connections.get(network) === state && !state.controller.signal.aborted) fail(network, state, error.message);
      });
    } else if (command === '903') {
      event.handled = true;
      if (state.phase !== 'response') { fail(network, state, 'Unexpected authentication result.'); return; }
      state.phase = 'done';
      clearTimeout(state.timer);
      note(network, 'Overnet sign-in and session delegation approved.');
      client.raw('CAP', 'END');
    } else if (/^90[4-7]$/.test(command)) {
      event.handled = true;
      fail(network, state, event.params.at(-1) || 'The IRC server rejected authentication.');
    }
  });

  async function authenticate(network, state) {
    const challenge = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(
      Uint8Array.from(atob(state.chunks), (char) => char.charCodeAt(0)),
    ));
    // This deployment requires a delegated session, not a guest registration.
    if (!challenge.delegate_pubkey) throw new Error('The IRC server did not offer session delegation.');
    await browserRequest('provider.info', undefined, state.controller.signal, 2000);
    note(network, 'Approve this sign-in in the Overnet extension window.');
    const response = await browserRequest('authenticate', challenge, state.controller.signal, 125000);
    if (!response?.auth_event || !response.delegate_event) throw new Error('Incomplete Overnet authentication response.');
    if (connections.get(network) !== state || state.controller.signal.aborted) return;
    const bytes = new TextEncoder().encode(JSON.stringify(response));
    const encoded = btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(''));
    state.phase = 'response';
    for (let offset = 0; offset < encoded.length; offset += 400) {
      network.ircClient.raw('AUTHENTICATE', encoded.slice(offset, offset + 400));
    }
    if (encoded.length % 400 === 0) network.ircClient.raw('AUTHENTICATE', '+');
  }
});

// With pairing disallowed (a collector in a fleet that shares one key), the
// plugin must never start a J-PAKE exchange: a rejected or missing key ends
// the session instead of silently re-pairing the sensor's slot, which would
// invalidate the key every other collector holds.

const { expect } = require('chai');
const Plugin = require('../lib/keks_plugin/plugin');
const { Transmitter } = require('./helpers/g7-transmitter');

const KEY = '00112233445566778899aabbccddeeff';

describe('KEKS plugin allowPairing', () => {
  afterEach(() => { Plugin.instance = null; });

  it('starts J-PAKE without a key by default', () => {
    const plugin = Plugin.getInstance('1234');
    plugin.amConnected();
    plugin.aNext();
    expect(plugin.state).to.equal(Plugin.Round1);
  });

  it('refuses to start J-PAKE without a key when pairing is disallowed', () => {
    const plugin = Plugin.getInstance('1234');
    plugin.setAllowPairing(false);
    plugin.amConnected();
    expect(() => plugin.aNext()).to.throw(/pairing not allowed/i);
    expect(plugin.state).to.equal(Plugin.RoundStart);
  });

  it('still authenticates with a saved key when pairing is disallowed', () => {
    const plugin = Plugin.getInstance('1234');
    plugin.setAllowPairing(false);
    plugin.setPersistence(2, KEY);
    plugin.amConnected();
    plugin.aNext();
    expect(plugin.state).to.equal(Plugin.RequestAuth);
  });

  it('does not re-pair after the sensor rejects the saved key', () => {
    const plugin = Plugin.getInstance('1234');
    plugin.setAllowPairing(false);
    plugin.setPersistence(2, KEY);
    plugin.amConnected();
    plugin.aNext(); // -> RequestAuth with the saved key
    // the sensor's challenge reply does not match our key
    plugin.context.challenge = Buffer.alloc(8, 0xAA);
    plugin.changeState(Plugin.RequestAuth);
    const reply = Buffer.concat([Buffer.from([0x03]), Buffer.alloc(16, 0x55)]);
    try { plugin.receivedResponse(reply); } catch (e) { /* mismatch may throw */ }
    // whatever the plugin does next, it must not start a new J-PAKE
    plugin.changeState(Plugin.RoundStart);
    expect(() => plugin.aNext()).to.throw(/pairing not allowed/i);
  });
});

describe('Transmitter allowPairing option', () => {
  afterEach(() => { Plugin.instance = null; });

  it('passes allowPairing: false to the plugin', () => {
    const tx = new Transmitter('1234', () => [], false, KEY, 'AA:BB:CC:DD:EE:01', { allowPairing: false });
    expect(tx.plugin.allowPairing).to.equal(false);
  });

  it('allows pairing by default', () => {
    const tx = new Transmitter('1234', () => [], false, null, null, {});
    expect(tx.plugin.allowPairing).to.equal(true);
  });
});

describe('Transmitter pairingBlocked event', () => {
  afterEach(() => { Plugin.instance = null; });

  it('emits pairingBlocked when the plugin refuses to pair', async () => {
    const tx = new Transmitter('1234', () => [], false, KEY, 'AA:BB:CC:DD:EE:01', { allowPairing: false });
    tx.authenticateAndPairG7 = async () => { throw new Error('Pairing not allowed: no valid key for this sensor'); };
    tx.disconnect = async () => {};
    const seen = [];
    tx.on('pairingBlocked', (d) => seen.push(d));
    await tx.isReady('AA:BB:CC:DD:EE:01');
    expect(seen).to.deep.equal([{ id: '1234', address: 'AA:BB:CC:DD:EE:01' }]);
  });

  it('does not emit pairingBlocked for other errors', async () => {
    const tx = new Transmitter('1234', () => [], false, KEY, 'AA:BB:CC:DD:EE:01', { allowPairing: false });
    tx.authenticateAndPairG7 = async () => { throw new Error('timeout'); };
    tx.disconnect = async () => {};
    const seen = [];
    tx.on('pairingBlocked', (d) => seen.push(d));
    await tx.isReady('AA:BB:CC:DD:EE:01');
    expect(seen).to.deep.equal([]);
  });
});

// Seen on a real G7 (fleet collector, 2026-11-11): the AuthStatus after our
// challenge reply never arrived, the plugin started a new round, and re-sent
// the PREVIOUS round's challenge reply (stale context.challenge) without
// waiting for the sensor's new challenge. The sensor answered "not
// authenticated", the plugin wiped the saved key, and fleet mode reported
// the (valid) key as rejected.
describe('KEKS plugin: re-authenticating within one connection', () => {
  afterEach(() => { Plugin.instance = null; });

  it('waits for the new challenge instead of re-sending the old reply', () => {
    const plugin = Plugin.getInstance('1234');
    plugin.setAllowPairing(false);
    plugin.setPersistence(2, KEY);
    plugin.amConnected();
    plugin.context.challenge = Buffer.alloc(8, 0x11);     // left over from the last round
    const sent = plugin.aNext();                           // RoundStart -> RequestAuth: 02 ...
    expect(Buffer.from(sent[0])[0]).to.equal(0x02);
    expect(plugin.context.challenge).to.equal(null);
    const next = plugin.aNext();                           // no new challenge yet
    expect(!next || !next[0] || Buffer.from(next[0])[0] !== 0x04).to.equal(true);
  });

  it('keeps the configured key after a plain "not authenticated" (pairing disallowed)', () => {
    const plugin = Plugin.getInstance('1234');
    plugin.setAllowPairing(false);
    plugin.setPersistence(2, KEY);
    plugin.amConnected();
    plugin.changeState(Plugin.ChallengeReply);
    plugin.receivedResponse(Buffer.from([0x05, 0x00, 0x00]));    // not authenticated
    plugin.changeState(Plugin.RoundStart);
    const sent = plugin.aNext();                                  // retries auth, no J-PAKE
    expect(Buffer.from(sent[0])[0]).to.equal(0x02);
    expect(plugin.state).to.equal(Plugin.RequestAuth);
  });

  it('stops retrying after a few "not authenticated" answers', () => {
    const plugin = Plugin.getInstance('1234');
    plugin.setAllowPairing(false);
    plugin.setPersistence(2, KEY);
    plugin.amConnected();
    for (let i = 0; i < 3; i += 1) {
      plugin.changeState(Plugin.ChallengeReply);
      plugin.receivedResponse(Buffer.from([0x05, 0x00, 0x00]));
      plugin.changeState(Plugin.RoundStart);
      if (i < 2) plugin.aNext();
    }
    expect(() => plugin.aNext()).to.throw(/pairing not allowed/i);
  });
});

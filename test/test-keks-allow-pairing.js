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

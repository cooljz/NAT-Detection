#!/usr/bin/env node
'use strict';
/**
 * NAT behavior discovery per RFC 4787 / RFC 5780 (UDP, IPv4, Node.js built-ins only).
 *
 * Usage: node nat_detect.js [host[:port]]      (needs Node.js 16 or newer)
 *
 * The STUN server must support RFC 5780 (OTHER-ADDRESS and CHANGE-REQUEST).
 */
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const dns = require('node:dns').promises;

const MAGIC = 0x2112a442;
const BINDING_REQUEST = 0x0001;
const BINDING_SUCCESS = 0x0101;
const ATTR_MAPPED = 0x0001;
const ATTR_CHANGE_REQUEST = 0x0003;
const ATTR_CHANGED_ADDRESS = 0x0005; // RFC 3489 name for OTHER-ADDRESS
const ATTR_XOR_MAPPED = 0x0020;
const ATTR_OTHER_ADDRESS = 0x802c;
const FLAG_CHANGE_IP = 0x04;
const FLAG_CHANGE_PORT = 0x02;

const EI = 'Endpoint-Independent';
const AD = 'Address-Dependent';
const APD = 'Address and Port-Dependent';

const DEFAULT_SERVER = 'stunserver2025.stunprotocol.org:3478';

/** Decode an IPv4 (XOR-)MAPPED-ADDRESS style value into { ip, port }. */
function parseAddr(v, xor) {
  if (v.length < 8 || v[1] !== 1) return null;
  let port = v.readUInt16BE(2);
  let ip = v.readUInt32BE(4);
  if (xor) {
    port ^= MAGIC >>> 16;
    ip = (ip ^ MAGIC) >>> 0;
  }
  return { ip: [ip >>> 24, (ip >>> 16) & 255, (ip >>> 8) & 255, ip & 255].join('.'), port };
}

/** Return { mapped, other } from a Binding Success Response, or null. */
function parseReply(data, txid) {
  if (
    data.length < 20 ||
    data.readUInt16BE(0) !== BINDING_SUCCESS ||
    data.readUInt32BE(4) !== MAGIC ||
    !data.subarray(8, 20).equals(txid)
  ) {
    return null;
  }
  const end = Math.min(20 + data.readUInt16BE(2), data.length);
  let xorMapped = null;
  let plainMapped = null;
  let other = null;
  for (let pos = 20; pos + 4 <= end; ) {
    const type = data.readUInt16BE(pos);
    const len = data.readUInt16BE(pos + 2);
    if (pos + 4 + len > end) break;
    const val = data.subarray(pos + 4, pos + 4 + len);
    if (type === ATTR_XOR_MAPPED) xorMapped = parseAddr(val, true);
    else if (type === ATTR_MAPPED) plainMapped = parseAddr(val, false);
    else if (type === ATTR_OTHER_ADDRESS || type === ATTR_CHANGED_ADDRESS) other = parseAddr(val, false);
    pos += 4 + ((len + 3) & ~3); // attributes are padded to 4 bytes
  }
  const mapped = xorMapped || plainMapped;
  return mapped ? { mapped, other } : null;
}

/** Send a Binding Request and wait for a matching reply (1 s per try). Resolves null on failure. */
function transact(sock, host, port, flags = 0, tries = 3) {
  const txid = crypto.randomBytes(12);
  const attrs = Buffer.alloc(flags ? 8 : 0);
  if (flags) {
    attrs.writeUInt16BE(ATTR_CHANGE_REQUEST, 0);
    attrs.writeUInt16BE(4, 2);
    attrs.writeUInt32BE(flags, 4);
  }
  const header = Buffer.alloc(20);
  header.writeUInt16BE(BINDING_REQUEST, 0);
  header.writeUInt16BE(attrs.length, 2);
  header.writeUInt32BE(MAGIC, 4);
  txid.copy(header, 8);
  const req = Buffer.concat([header, attrs]);

  return new Promise((resolve) => {
    let attempts = 0;
    let finished = false;
    let timer = null;
    const finish = (result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      sock.off('message', onMessage);
      resolve(result);
    };
    // The socket is unconnected, so replies from another IP/port are accepted.
    const onMessage = (msg) => {
      const reply = parseReply(msg, txid);
      if (reply) finish(reply);
    };
    const attempt = () => {
      if (attempts++ >= tries) return finish(null);
      sock.send(req, port, host, (err) => {
        if (err) finish(null);
      });
      timer = setTimeout(attempt, 1000);
    };
    sock.on('message', onMessage);
    attempt();
  });
}

function openSocket() {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.once('error', reject);
    sock.bind(0, () => {
      sock.off('error', reject);
      sock.on('error', () => {}); // later errors surface as missing replies
      resolve(sock);
    });
  });
}

/** Local IPv4 address the OS would use to reach the server. */
function localIp(host, port) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    sock.once('error', () => {
      try { sock.close(); } catch {}
      resolve(null);
    });
    sock.connect(port, host, () => {
      const ip = sock.address().address;
      sock.close();
      resolve(ip);
    });
  });
}

const same = (a, b) => a.ip === b.ip && a.port === b.port;

/** RFC 5780 section 4.3. Uses one socket for every probe. */
async function detectMapping(sock, server, mapped1, other) {
  const r2 = await transact(sock, other.ip, server.port); // other IP, primary port
  if (!r2) return null;
  if (same(r2.mapped, mapped1)) return EI;
  const r3 = await transact(sock, other.ip, other.port); // other IP, other port
  if (!r3) return null;
  return same(r3.mapped, r2.mapped) ? AD : APD;
}

/**
 * RFC 5780 section 4.4. Uses a fresh socket so earlier probes cannot have
 * opened the filter toward the server's alternate address.
 */
async function detectFiltering(server) {
  const sock = await openSocket();
  try {
    if (!(await transact(sock, server.ip, server.port))) return null;
    if (await transact(sock, server.ip, server.port, FLAG_CHANGE_IP | FLAG_CHANGE_PORT, 2)) return EI;
    if (await transact(sock, server.ip, server.port, FLAG_CHANGE_PORT, 2)) return AD;
    return APD;
  } finally {
    sock.close();
  }
}

function legacyName(mapping, filtering) {
  if (!mapping || !filtering) return 'unknown';
  if (mapping !== EI) return 'symmetric';
  return { [EI]: 'full cone', [AD]: 'restricted cone', [APD]: 'port-restricted cone' }[filtering];
}

function die(message) {
  console.error(message);
  process.exit(1);
}

async function main() {
  const arg = process.argv[2] || DEFAULT_SERVER;
  const colon = arg.lastIndexOf(':');
  const host = colon === -1 ? arg : arg.slice(0, colon);
  const port = colon === -1 ? 3478 : Number(arg.slice(colon + 1));
  let server;
  try {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid port');
    server = { ip: (await dns.lookup(host, { family: 4 })).address, port };
  } catch (e) {
    die(`cannot resolve ${arg}: ${e.message}`);
  }

  const sock = await openSocket();
  const first = await transact(sock, server.ip, server.port);
  if (!first) die(`no STUN reply from ${server.ip}:${server.port}`);
  const { mapped, other } = first;
  console.log(`Server:  ${server.ip}:${server.port}`);
  console.log(`Mapped:  ${mapped.ip}:${mapped.port}`);
  if (mapped.ip === (await localIp(server.ip, server.port)) && mapped.port === sock.address().port) {
    console.log('Note:    mapped address equals local address, so no NAT was detected.');
  }
  if (!other) {
    die(
      'The server did not send OTHER-ADDRESS, so it does not support RFC 5780. ' +
        'Use a server that does (for example coturn or stunserver2025.stunprotocol.org).'
    );
  }

  const mapping = await detectMapping(sock, server, mapped, other);
  sock.close();
  const filtering = await detectFiltering(server);
  console.log(`Mapping behavior:   ${mapping || 'unknown (no reply from alternate address)'}`);
  console.log(`Filtering behavior: ${filtering || 'unknown (no reply)'}`);
  console.log(`Legacy name (approximate): ${legacyName(mapping, filtering)}`);
}

main().catch((e) => die(`error: ${e.message}`));

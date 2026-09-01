'use strict';

/**
 * CA loading + per-host leaf certificate minting for TLS interception.
 *
 * Leaf certs are signed by the local CA and cached in-memory per hostname so
 * repeated CONNECTs to the same host reuse the same context.
 */

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const forge = require('node-forge');
const config = require('../config');

let caCert = null; // forge cert
let caKey = null; // forge private key
const contextCache = new Map(); // hostname -> tls.SecureContext

function loadCA() {
  if (caCert && caKey) return;
  const certPath = path.join(config.caDir, config.caCertFile);
  const keyPath = path.join(config.caDir, config.caKeyFile);
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    throw new Error(
      `CA not found in ${config.caDir}. Run: node src/tools/gen-ca.js`
    );
  }
  caCert = forge.pki.certificateFromPem(fs.readFileSync(certPath, 'utf8'));
  caKey = forge.pki.privateKeyFromPem(fs.readFileSync(keyPath, 'utf8'));
}

/**
 * Mint (or reuse) a leaf certificate for `hostname` and return a
 * tls.SecureContext usable as an SNICallback result or server context.
 */
function getSecureContext(hostname) {
  loadCA();
  const key = normalizeHost(hostname);
  let ctx = contextCache.get(key);
  if (ctx) return ctx;

  const { certPem, keyPem } = mintLeaf(key);
  ctx = tls.createSecureContext({ key: keyPem, cert: certPem });
  contextCache.set(key, ctx);
  return ctx;
}

function mintLeaf(hostname) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerial();
  cert.validity.notBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 397 * 24 * 60 * 60 * 1000);

  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const subject = [{ name: 'commonName', value: hostname }];
  cert.setSubject(subject);
  cert.setIssuer(caCert.subject.attributes);

  const altNames = isIp
    ? [{ type: 7, ip: hostname }]
    : [{ type: 2, value: hostname }];

  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    {
      name: 'keyUsage',
      critical: true,
      digitalSignature: true,
      keyEncipherment: true,
    },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
    { name: 'subjectAltName', altNames },
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

/**
 * Default TLS credentials (PEM) for the MITM server handshake, used when a
 * client does not send SNI. Minted once for a placeholder host.
 */
let defaultCreds = null;
function getDefaultCredentials() {
  loadCA();
  if (!defaultCreds) {
    const { certPem, keyPem } = mintLeaf('localhost');
    defaultCreds = { cert: certPem, key: keyPem };
  }
  return defaultCreds;
}

function normalizeHost(h) {
  return String(h || '').trim().toLowerCase();
}

function randomSerial() {
  const bytes = forge.random.getBytesSync(16);
  let hex = forge.util.bytesToHex(bytes);
  hex = '0' + hex.slice(1);
  return hex;
}

module.exports = { loadCA, getSecureContext, getDefaultCredentials };

'use strict';

/**
 * Generate a local root CA (self-signed) used to mint per-host leaf certs for
 * TLS interception. Writes:
 *   <caDir>/ca.pem       -> CA certificate (PEM)  [import into trust store]
 *   <caDir>/ca.key.pem   -> CA private key (PEM)  [keep secret, gitignored]
 *
 * Usage:
 *   node src/tools/gen-ca.js [--out <caDir>] [--force]
 */

const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const config = require('../config');

function parseArgs(argv) {
  const args = { out: config.caDir, force: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') args.out = argv[++i];
    else if (a === '--force') args.force = true;
    else if (a === '--help' || a === '-h') args.help = true;
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write(
      'Usage: node src/tools/gen-ca.js [--out <caDir>] [--force]\n'
    );
    return;
  }

  const caDir = path.resolve(args.out);
  const certPath = path.join(caDir, config.caCertFile);
  const keyPath = path.join(caDir, config.caKeyFile);

  fs.mkdirSync(caDir, { recursive: true });

  if (!args.force && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    process.stdout.write(
      `CA already exists at ${certPath}\nUse --force to regenerate.\n`
    );
    return;
  }

  process.stdout.write('Generating 2048-bit RSA CA key pair...\n');
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerial();
  cert.validity.notBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000);

  const attrs = [
    { name: 'commonName', value: 'Secret Redaction Proxy Local CA' },
    { name: 'organizationName', value: 'Secret Redaction Proxy' },
    { shortName: 'OU', value: 'Local Development CA' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs); // self-signed

  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    {
      name: 'keyUsage',
      critical: true,
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: true,
    },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  fs.writeFileSync(certPath, certPem, { mode: 0o644 });
  fs.writeFileSync(keyPath, keyPem, { mode: 0o600 });

  process.stdout.write(`\nCA certificate: ${certPath}\n`);
  process.stdout.write(`CA private key: ${keyPath}\n\n`);
  process.stdout.write('Next steps:\n');
  process.stdout.write(
    `  1. Trust the CA:  Import-Certificate -FilePath "${certPath}" -CertStoreLocation Cert:\\CurrentUser\\Root\n`
  );
  process.stdout.write(
    `  2. Point harness: $env:NODE_EXTRA_CA_CERTS = "${certPath}"\n`
  );
}

function randomSerial() {
  // Positive hex serial (avoid leading bit set which some parsers dislike).
  const bytes = forge.random.getBytesSync(16);
  let hex = forge.util.bytesToHex(bytes);
  // Force the high nibble low so the serial is unambiguously positive.
  hex = '0' + hex.slice(1);
  return hex;
}

if (require.main === module) {
  main();
}

module.exports = { main };

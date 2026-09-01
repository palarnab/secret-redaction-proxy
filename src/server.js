'use strict';

/**
 * Secret-Redaction Proxy — entry point.
 *
 * A forward proxy (HTTP CONNECT) that TLS-intercepts allowlisted LLM hosts,
 * redacts secrets in outbound request bodies, forwards to the real upstream
 * over a genuinely validated TLS connection, then restores the real values in
 * the response. Non-allowlisted hosts are blind-tunnelled (never decrypted).
 */

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const { StringDecoder } = require('string_decoder');

const config = require('./config');
const { getSecureContext, getDefaultCredentials, loadCA } = require('./intercept/ca');
const { shouldIntercept } = require('./intercept/allowlist');
const { redactJson, redactString } = require('./redact');
const { restoreString } = require('./restore');
const { Vault } = require('./vault');
const { Stats } = require('./stats');
const { AuditLog } = require('./audit-log');
const { createOpenAiRestore } = require('./intercept/stream/sse-openai');
const { createAnthropicRestore } = require('./intercept/stream/sse-anthropic');

function parseArgs(argv) {
  const opts = {
    port: config.port,
    host: config.host,
    allowlist: config.allowlist.slice(),
    audit: true,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--port') opts.port = parseInt(argv[++i], 10);
    else if (a === '--host') opts.host = argv[++i];
    else if (a === '--allowlist') opts.allowlist = argv[++i].split(',').map((s) => s.trim());
    else if (a === '--no-audit') opts.audit = false;
    else if (a === '--verbose') config.verbose = true;
    else if (a === '--help' || a === '-h') opts.help = true;
  }
  return opts;
}

function log(...args) {
  if (config.verbose) process.stderr.write(args.join(' ') + '\n');
}

function pickStreamRestore(host, vault, ctx) {
  const h = host.toLowerCase();
  if (h.includes('anthropic')) return createAnthropicRestore(vault, ctx);
  if (h.includes('openai') || h.includes('githubcopilot') || h.includes('githubusercontent'))
    return createOpenAiRestore(vault, ctx);
  return new GenericStreamRestore(vault, ctx);
}

/** Fallback streaming restorer for unknown formats (raw rolling-buffer). */
class GenericStreamRestore {
  constructor(vault, ctx) {
    const { StreamRestorer } = require('./restore');
    this.inner = new StreamRestorer(vault, ctx);
    this.decoder = new StringDecoder('utf8');
  }
  push(buf) {
    return this.inner.push(typeof buf === 'string' ? buf : this.decoder.write(buf));
  }
  end() {
    return this.inner.end();
  }
}

function createServer(runtime) {
  const { stats, audit } = runtime;

  // 1) Handler for decrypted (intercepted) requests.
  const mitm = http.createServer((req, res) => handleIntercepted(req, res, runtime));
  mitm.on('clientError', (err, socket) => {
    log('mitm clientError:', err.message);
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  // 2) TLS server that terminates client TLS using per-host minted certs.
  const def = getDefaultCredentials();
  const tlsServer = tls.createServer(
    {
      key: def.key,
      cert: def.cert,
      SNICallback: (servername, cb) => {
        try {
          cb(null, getSecureContext(servername));
        } catch (e) {
          cb(e);
        }
      },
    },
    (tlsSocket) => {
      mitm.emit('connection', tlsSocket);
    }
  );
  tlsServer.on('tlsClientError', (err) => log('tlsClientError:', err.message));

  // 3) The forward proxy: handles CONNECT (and passes intercept vs tunnel).
  const proxy = http.createServer((req, res) => {
    // Plain HTTP proxying is out of scope; respond politely.
    res.writeHead(405, { 'content-type': 'text/plain' });
    res.end('This proxy only supports HTTPS via CONNECT.\n');
  });

  proxy.on('connect', (req, clientSocket, head) => {
    const [host, portStr] = req.url.split(':');
    const port = parseInt(portStr, 10) || 443;

    if (shouldIntercept(host)) {
      log('INTERCEPT', host + ':' + port);
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) clientSocket.unshift(head);
      tlsServer.emit('connection', clientSocket);
    } else {
      log('TUNNEL   ', host + ':' + port);
      blindTunnel(clientSocket, head, host, port);
    }
  });

  proxy.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  runtime.mitm = mitm;
  runtime.tlsServer = tlsServer;
  return proxy;
}

function blindTunnel(clientSocket, head, host, port) {
  const upstream = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  const onErr = (e) => {
    log('tunnel error:', e.message);
    clientSocket.destroy();
    upstream.destroy();
  };
  upstream.on('error', onErr);
  clientSocket.on('error', onErr);
}

function handleIntercepted(req, res, runtime) {
  const { stats, audit } = runtime;
  stats.recordRequest();

  const host = (req.headers.host || '').split(':')[0];
  const chunks = [];
  let size = 0;

  req.on('data', (c) => {
    chunks.push(c);
    size += c.length;
  });

  req.on('end', () => {
    const body = Buffer.concat(chunks, size);
    const vault = new Vault();
    const ctx = { stats };

    let outBody = body;
    let blocked = null;
    const contentType = (req.headers['content-type'] || '').toLowerCase();
    const isJson = contentType.includes('application/json') && body.length > 0;

    if (isJson && body.length <= config.limits.maxRedactBytes) {
      try {
        const parsed = JSON.parse(body.toString('utf8'));
        const result = redactJson(parsed, vault, ctx);
        if (result.blocked) {
          blocked = result.blocked;
        } else {
          for (const hit of result.hits) {
            audit.redaction({
              type: hit.type,
              detector: hit.detector,
              fingerprint: stats.fingerprint(hit.match),
              host,
            });
          }
          outBody = Buffer.from(JSON.stringify(result.value), 'utf8');
        }
      } catch (e) {
        log('JSON parse/redact skipped:', e.message);
      }
    } else if (body.length && body.length <= config.limits.maxRedactBytes) {
      // Non-JSON textual body: best-effort string redaction.
      const asText = body.toString('utf8');
      const result = redactString(asText, vault, ctx);
      if (result.blocked) blocked = result.blocked;
      else if (result.hits.length) {
        for (const hit of result.hits) {
          audit.redaction({
            type: hit.type,
            detector: hit.detector,
            fingerprint: stats.fingerprint(hit.match),
            host,
          });
        }
        outBody = Buffer.from(result.value, 'utf8');
      }
    }

    if (blocked) {
      stats.recordBlock();
      audit.block({ type: blocked.type, reason: blocked.reason, host });
      vault.zeroize();
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          error: {
            type: 'secret_redaction_proxy_block',
            message:
              'Request blocked: a high-confidence secret was detected but could not be safely tokenized (fail-closed).',
            secret_type: blocked.type,
          },
        })
      );
      return;
    }

    forwardUpstream(req, res, host, outBody, vault, runtime);
  });

  req.on('error', (e) => {
    log('request error:', e.message);
    res.destroy();
  });
}

function forwardUpstream(req, res, host, outBody, vault, runtime) {
  const { stats, audit } = runtime;

  const headers = { ...req.headers };
  delete headers['proxy-connection'];
  headers['host'] = host;
  // Force identity so we can read/restore plaintext (no gzip on the way back).
  headers['accept-encoding'] = 'identity';
  if (outBody && outBody.length) headers['content-length'] = String(outBody.length);

  const options = {
    host,
    servername: host,
    port: 443,
    method: req.method,
    path: req.url,
    headers,
  };

  const upReq = https.request(options, (upRes) => {
    const ct = (upRes.headers['content-type'] || '').toLowerCase();
    const isSse = ct.includes('text/event-stream');

    const outHeaders = { ...upRes.headers };
    delete outHeaders['content-encoding'];
    delete outHeaders['transfer-encoding'];

    if (isSse) {
      delete outHeaders['content-length'];
      res.writeHead(upRes.statusCode, outHeaders);
      const restorer = pickStreamRestore(host, vault, { stats, audit, host });
      upRes.on('data', (chunk) => {
        const out = restorer.push(chunk);
        if (out) res.write(out);
      });
      upRes.on('end', () => {
        const tail = restorer.end();
        if (tail) res.write(tail);
        res.end();
        vault.zeroize();
      });
      upRes.on('error', (e) => {
        log('upstream stream error:', e.message);
        res.destroy();
        vault.zeroize();
      });
    } else {
      const parts = [];
      upRes.on('data', (c) => parts.push(c));
      upRes.on('end', () => {
        const text = Buffer.concat(parts).toString('utf8');
        const { value } = restoreString(text, vault, { stats, audit, host });
        const outBuf = Buffer.from(value, 'utf8');
        outHeaders['content-length'] = String(outBuf.length);
        res.writeHead(upRes.statusCode, outHeaders);
        res.end(outBuf);
        vault.zeroize();
      });
      upRes.on('error', (e) => {
        log('upstream error:', e.message);
        res.destroy();
        vault.zeroize();
      });
    }
  });

  upReq.on('error', (e) => {
    log('upstream request error:', e.message);
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('Upstream connection failed: ' + e.message + '\n');
    vault.zeroize();
  });

  if (outBody && outBody.length) upReq.write(outBody);
  upReq.end();
}

function main() {
  const opts = parseArgs(process.argv);
  if (opts.help) {
    process.stdout.write(
      'Usage: node src/server.js [--port N] [--host H] [--allowlist a,b,c] [--no-audit] [--verbose]\n'
    );
    return;
  }

  config.allowlist = opts.allowlist;

  try {
    loadCA();
  } catch (e) {
    process.stderr.write('\nERROR: ' + e.message + '\n');
    process.exit(1);
  }

  const runtime = {
    stats: new Stats(),
    audit: new AuditLog({ enabled: opts.audit }),
  };

  const proxy = createServer(runtime);
  proxy.listen(opts.port, opts.host, () => {
    process.stdout.write(
      `Secret-Redaction Proxy listening on http://${opts.host}:${opts.port}\n`
    );
    process.stdout.write(`Intercepting: ${config.allowlist.join(', ')}\n`);
    process.stdout.write('Point a harness at it:\n');
    process.stdout.write(`  $env:HTTPS_PROXY = "http://${opts.host}:${opts.port}"\n`);
    process.stdout.write('Press Ctrl+C to stop and print the session summary.\n\n');
  });

  const shutdown = () => {
    const summary = runtime.stats.summary(runtime.audit.path);
    process.stdout.write('\n' + summary + '\n');
    runtime.audit.sessionSummary({
      requestsProcessed: runtime.stats.requestsProcessed,
      redactions: runtime.stats.redactions,
      restorations: runtime.stats.restorations,
      restoreMisses: runtime.stats.restoreMisses,
      failClosedBlocks: runtime.stats.failClosedBlocks,
      byType: Object.fromEntries(runtime.stats.byType),
      byDetector: Object.fromEntries(runtime.stats.byDetector),
    });
    runtime.audit.close();
    proxy.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 500).unref();
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (require.main === module) {
  main();
}

module.exports = { createServer, parseArgs, pickStreamRestore };

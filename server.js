'use strict';

const http = require('node:http');
const https = require('node:https');
const http2 = require('node:http2');
const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { domainToASCII } = require('node:url');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const QUERY_TIMEOUT_MS = 7000;
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const RDAP_BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;

let rdapBootstrapCache = null;

const PROVIDERS = {
  google: {
    id: 'google',
    label: 'Google',
    address: '8.8.8.8',
    url: 'https://dns.google/resolve',
  },
  cloudflare: {
    id: 'cloudflare',
    label: 'Cloudflare',
    address: '1.1.1.1',
    url: 'https://cloudflare-dns.com/dns-query',
  },
};

const TYPE_CODES = {
  A: 1,
  NS: 2,
  PTR: 12,
  MX: 15,
  TXT: 16,
};

const RECORD_TYPE_KEYS = [
  'a',
  'mx',
  'ns',
  'spf',
  'dkim',
  'dmarc',
  'ptr',
  'registrar',
  'http',
];

const COMMON_DKIM_SELECTORS = [
  'default',
  'google',
  'dkim',
  'mail',
  's1',
  's2',
  'selector1',
  'selector2',
  'x',
];

const STATIC_FILES = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/styles.css': { file: 'styles.css', type: 'text/css; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
  '/favicon.svg': { file: 'favicon.svg', type: 'image/svg+xml' },
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function normalizeDomain(input) {
  let value = String(input || '').trim().toLowerCase();

  if (!value) {
    throw new HttpError(400, 'Enter a domain name to look up.');
  }

  if (value.length > 500) {
    throw new HttpError(400, 'That domain name is too long.');
  }

  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      value = new URL(value).hostname;
    } else {
      value = value.split('/')[0].split('?')[0].split('#')[0];
    }
  } catch {
    throw new HttpError(400, 'Enter a valid domain name, such as google.com.');
  }

  value = value.replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');

  const ascii = domainToASCII(value);
  if (!ascii) {
    throw new HttpError(400, 'Enter a valid domain name, such as google.com.');
  }

  if (net.isIP(ascii)) {
    throw new HttpError(400, 'Enter a domain name rather than an IP address.');
  }

  if (ascii.length > 253) {
    throw new HttpError(400, 'That domain name is too long.');
  }

  const labels = ascii.split('.');
  if (labels.length < 2) {
    throw new HttpError(400, 'Use a full domain name, such as example.com.');
  }

  const labelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
  if (!labels.every((label) => labelPattern.test(label))) {
    throw new HttpError(400, 'That domain name contains invalid characters.');
  }

  return ascii;
}

function normalizeTxt(raw) {
  const value = String(raw ?? '').trim();

  if (!value.includes('"')) {
    return value;
  }

  const chunks = [];
  const quoted = /"((?:\\.|[^"\\])*)"/g;
  let match;

  while ((match = quoted.exec(value)) !== null) {
    chunks.push(
      match[1].replace(/\\([0-9]{3}|.)/g, (_, escape) =>
        /^[0-9]{3}$/.test(escape)
          ? String.fromCharCode(Number.parseInt(escape, 10))
          : escape,
      ),
    );
  }

  return chunks.length ? chunks.join('') : value;
}

function cleanName(value) {
  return String(value ?? '').trim().replace(/\.$/, '');
}

function recordsOfType(result, code) {
  return result.answers.filter((answer) => Number(answer.type) === code);
}

function dedupeRecords(records) {
  const seen = new Set();
  return records.filter((record) => {
    const key = JSON.stringify(record);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function dohQuery(provider, name, type) {
  const url = new URL(provider.url);
  url.searchParams.set('name', name);
  url.searchParams.set('type', type);

  let response;
  try {
    response = await fetch(url, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(QUERY_TIMEOUT_MS),
    });
  } catch (error) {
    if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
      throw new Error(`The ${provider.label} resolver timed out.`);
    }
    throw new Error(`Could not reach the ${provider.label} resolver.`);
  }

  if (!response.ok) {
    throw new Error(
      `The ${provider.label} resolver returned HTTP ${response.status}.`,
    );
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`The ${provider.label} resolver returned an invalid response.`);
  }

  if (!data || typeof data.Status !== 'number') {
    throw new Error(`The ${provider.label} resolver returned an invalid response.`);
  }

  return {
    status: data.Status,
    answers: Array.isArray(data.Answer) ? data.Answer : [],
    authority: Array.isArray(data.Authority) ? data.Authority : [],
  };
}

async function querySafe(provider, name, type) {
  try {
    return { ok: true, ...(await dohQuery(provider, name, type)) };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : 'The DNS query failed.',
    };
  }
}

async function loadRdapBootstrap() {
  if (
    rdapBootstrapCache &&
    rdapBootstrapCache.expiresAt > Date.now() &&
    Array.isArray(rdapBootstrapCache.services)
  ) {
    return rdapBootstrapCache.services;
  }

  const response = await fetch(RDAP_BOOTSTRAP_URL, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(QUERY_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new Error(`RDAP bootstrap returned HTTP ${response.status}.`);
  }

  const data = await response.json();
  if (!data || !Array.isArray(data.services)) {
    throw new Error('RDAP bootstrap returned an invalid response.');
  }

  rdapBootstrapCache = {
    services: data.services,
    expiresAt: Date.now() + RDAP_BOOTSTRAP_TTL_MS,
  };
  return data.services;
}

function rdapRegistrarNames(data) {
  const names = new Set();

  function visit(entity) {
    if (!entity || typeof entity !== 'object') return;

    const roles = Array.isArray(entity.roles)
      ? entity.roles.map((role) => String(role).toLowerCase())
      : [];
    if (roles.includes('registrar') && Array.isArray(entity.vcardArray?.[1])) {
      const properties = entity.vcardArray[1];
      const nameProperty =
        properties.find(
          (property) =>
            Array.isArray(property) &&
            String(property[0]).toLowerCase() === 'fn',
        ) ||
        properties.find(
          (property) =>
            Array.isArray(property) &&
            String(property[0]).toLowerCase() === 'org',
        );
      const name =
        Array.isArray(nameProperty) && nameProperty[3]
          ? String(nameProperty[3]).trim()
          : '';
      if (name) names.add(name);
    }

    if (Array.isArray(entity.entities)) {
      for (const child of entity.entities) visit(child);
    }
  }

  if (Array.isArray(data?.entities)) {
    for (const entity of data.entities) visit(entity);
  }

  return [...names];
}

function normalizeHttpHeaders(headers) {
  const normalized = {};
  for (const [key, value] of Object.entries(headers || {})) {
    if (key.startsWith(':')) continue;
    normalized[key.toLowerCase()] = Array.isArray(value)
      ? value.join(', ')
      : String(value);
  }
  return normalized;
}

function requestHttp2Headers(url, redirectsLeft = 5) {
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    let settled = false;
    const client = http2.connect(parsed.origin);
    const timer = setTimeout(() => {
      finish(new Error('HTTP request timed out.'));
    }, QUERY_TIMEOUT_MS);

    function finish(error, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        client.close();
      } catch {
        // Ignore cleanup errors.
      }
      if (error) reject(error);
      else resolve(value);
    }

    client.once('error', (error) => finish(error));
    client.once('connect', () => {
      if (client.socket?.alpnProtocol !== 'h2') {
        finish(new Error('HTTP/2 was not negotiated.'));
        return;
      }

      const request = client.request({
        ':method': 'GET',
        ':path': `${parsed.pathname || '/'}${parsed.search || ''}`,
        'user-agent': 'Mozilla/5.0 (compatible; DNS-Checker/1.0)',
        accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
        'accept-encoding': 'gzip, deflate, br',
      });

      request.once('response', (headers) => {
        const status = Number(headers[':status']);
        const location = headers.location;
        if (
          [301, 302, 303, 307, 308].includes(status) &&
          location &&
          redirectsLeft > 0
        ) {
          request.close();
          finish(
            null,
            requestHeaders(new URL(String(location), parsed).toString(), redirectsLeft - 1),
          );
          return;
        }

        finish(null, {
          url: parsed.toString(),
          status,
          statusMessage: '',
          httpVersion: '2.0',
          headers: normalizeHttpHeaders(headers),
        });
      });
      request.once('error', (error) => finish(error));
      request.end();
    });
  });
}

function requestHttp1Headers(url, redirectsLeft = 5) {
  const parsed = new URL(url);
  const client = parsed.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.request(
      parsed,
      {
        method: 'GET',
        headers: {
          'user-agent': 'Mozilla/5.0 (compatible; DNS-Checker/1.0)',
          accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          'accept-encoding': 'gzip, deflate, br',
        },
        timeout: QUERY_TIMEOUT_MS,
      },
      (response) => {
        const status = Number(response.statusCode);
        const location = response.headers.location;
        if (
          [301, 302, 303, 307, 308].includes(status) &&
          location &&
          redirectsLeft > 0
        ) {
          response.resume();
          resolve(
            requestHeaders(
              new URL(String(location), parsed).toString(),
              redirectsLeft - 1,
            ),
          );
          return;
        }

        const result = {
          url: parsed.toString(),
          status,
          statusMessage: response.statusMessage || '',
          httpVersion: response.httpVersion || '1.1',
          headers: normalizeHttpHeaders(response.headers),
        };
        response.destroy();
        resolve(result);
      },
    );

    request.once('timeout', () => {
      request.destroy(new Error('HTTP request timed out.'));
    });
    request.once('error', reject);
    request.end();
  });
}

async function requestHeaders(url, redirectsLeft = 5) {
  const parsed = new URL(url);
  if (parsed.protocol === 'https:') {
    try {
      return await requestHttp2Headers(parsed.toString(), redirectsLeft);
    } catch {
      return requestHttp1Headers(parsed.toString(), redirectsLeft);
    }
  }
  return requestHttp1Headers(parsed.toString(), redirectsLeft);
}

async function makeHttpSection(domain) {
  let response;
  let usedFallback = false;

  try {
    response = await requestHeaders(`https://${domain}/`);
  } catch {
    try {
      usedFallback = true;
      response = await requestHeaders(`http://${domain}/`);
    } catch {
      return {
        status: 'error',
        records: [],
        error: 'The website could not be reached to inspect HTTP headers.',
      };
    }
  }

  const headers = response.headers || {};
  const records = [];

  function add(label, value) {
    if (value === null || value === undefined || String(value).trim() === '') {
      return;
    }
    records.push({ label, value: String(value).trim() });
  }

  add('Status', `${response.status} ${response.statusMessage}`.trim());
  add(
    'HTTP version',
    response.httpVersion === '2.0'
      ? 'HTTP/2'
      : `HTTP/${response.httpVersion}`,
  );
  add('Final URL', response.url);
  add('Web server', headers.server);
  add('Powered by', headers['x-powered-by']);

  const phpMatch = String(headers['x-powered-by'] || headers.server || '').match(
    /PHP\/([\d.]+)/i,
  );
  if (phpMatch) add('PHP version', phpMatch[1]);

  const compression = headers['content-encoding'];
  add('Compression', compression ? `${compression} enabled` : 'Not enabled');
  add('Content type', headers['content-type']);
  add(
    'HSTS',
    headers['strict-transport-security'] ? 'Enabled' : 'Not set',
  );

  const cdn =
    headers['cf-ray'] ? 'Cloudflare' : headers['x-served-by'] || headers.via;
  add('CDN / proxy', cdn);
  add('Cache', headers['cf-cache-status'] || headers['x-cache']);

  return {
    status: records.length ? 'found' : 'none',
    records,
    notes: usedFallback
      ? ['HTTPS could not be reached, so the HTTP endpoint was checked.']
      : [],
  };
}

async function makeRegistrarSection(domain) {
  let services;
  try {
    services = await loadRdapBootstrap();
  } catch (error) {
    return {
      status: 'error',
      error:
        error?.name === 'TimeoutError'
          ? 'The domain registrar lookup timed out.'
          : 'The domain registrar could not be checked.',
      records: [],
    };
  }

  const tld = domain.split('.').pop().toLowerCase();
  const service = services.find(
    ([tlds]) =>
      Array.isArray(tlds) &&
      tlds.some((candidate) => String(candidate).toLowerCase() === tld),
  );
  const baseUrl = service?.[1]?.[0];

  if (!baseUrl) {
    return {
      status: 'none',
      records: [],
      notes: ['No RDAP registrar service is available for this domain.'],
    };
  }

  let response;
  try {
    const lookupUrl = new URL(
      `domain/${encodeURIComponent(domain)}`,
      String(baseUrl).endsWith('/') ? String(baseUrl) : `${baseUrl}/`,
    );
    response = await fetch(lookupUrl, {
      headers: { accept: 'application/rdap+json' },
      signal: AbortSignal.timeout(QUERY_TIMEOUT_MS),
    });
  } catch (error) {
    return {
      status: 'error',
      error:
        error?.name === 'TimeoutError'
          ? 'The domain registrar lookup timed out.'
          : 'The domain registrar service could not be reached.',
      records: [],
    };
  }

  if (response.status === 404) {
    return {
      status: 'none',
      records: [],
      notes: ['No registrar information was found for this domain.'],
    };
  }

  if (!response.ok) {
    return {
      status: 'error',
      error: `The domain registrar service returned HTTP ${response.status}.`,
      records: [],
    };
  }

  let data;
  try {
    data = await response.json();
  } catch {
    return {
      status: 'error',
      error: 'The domain registrar service returned an invalid response.',
      records: [],
    };
  }

  const names = rdapRegistrarNames(data);
  return {
    status: names.length ? 'found' : 'none',
    records: names.map((name) => ({ value: name })),
    notes: names.length ? [] : ['The RDAP record did not identify a registrar.'],
  };
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;

  async function run() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, () => run()),
  );
  return results;
}

function makeAddressSection(result) {
  if (!result.ok) {
    return { status: 'error', error: result.error, records: [] };
  }

  const records = dedupeRecords(
    recordsOfType(result, TYPE_CODES.A).map((answer) => ({
      value: String(answer.data).trim(),
    })),
  );

  return { status: records.length ? 'found' : 'none', records };
}

function makeMxSection(result) {
  if (!result.ok) {
    return { status: 'error', error: result.error, records: [] };
  }

  const records = dedupeRecords(
    recordsOfType(result, TYPE_CODES.MX)
      .map((answer) => {
        const match = String(answer.data)
          .trim()
          .match(/^(\d+)\s+(\S+)\.?$/);
        if (!match) return null;

        const exchange = cleanName(match[2]);
        return {
          priority: Number(match[1]),
          exchange: exchange || '.',
          nullMx: !exchange,
        };
      })
      .filter(Boolean)
      .sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange)),
  );

  const notes = records.some((record) => record.nullMx)
    ? ['A null MX record (priority 0, host “.”) means this domain does not accept email.']
    : [];

  return { status: records.length ? 'found' : 'none', records, notes };
}

function makeNsSection(result) {
  if (!result.ok) {
    return { status: 'error', error: result.error, records: [] };
  }

  const records = dedupeRecords(
    recordsOfType(result, TYPE_CODES.NS).map((answer) => ({
      value: cleanName(answer.data),
    })),
  ).sort((a, b) => a.value.localeCompare(b.value));

  return { status: records.length ? 'found' : 'none', records };
}

async function makeNsAddressSection(provider, nsSection) {
  if (nsSection.status === 'error') {
    return {
      status: 'error',
      error: 'NS records could not be retrieved, so NS addresses were not checked.',
      groups: [],
    };
  }

  if (!nsSection.records.length) {
    return { status: 'none', groups: [], notes: [] };
  }

  const groups = await mapLimit(nsSection.records, 4, async (nsRecord) => {
    const result = await querySafe(provider, nsRecord.value, 'A');

    if (!result.ok) {
      return {
        host: nsRecord.value,
        status: 'error',
        error: result.error,
        addresses: [],
      };
    }

    const addresses = dedupeRecords(
      recordsOfType(result, TYPE_CODES.A).map((answer) => ({
        value: String(answer.data).trim(),
      })),
    );

    return {
      host: nsRecord.value,
      status: addresses.length ? 'found' : 'none',
      addresses,
    };
  });

  const total = groups.reduce((sum, group) => sum + group.addresses.length, 0);
  const failures = groups.filter((group) => group.status === 'error').length;
  const missing = groups.filter((group) => group.status === 'none').length;
  const notes = [];

  if (missing) {
    notes.push(
      `${missing} NS host${missing === 1 ? '' : 's'} had no A record.`,
    );
  }
  if (failures) {
    notes.push(
      `${failures} NS host lookup${failures === 1 ? '' : 's'} failed.`,
    );
  }

  return {
    status: total ? 'found' : failures ? 'error' : 'none',
    groups,
    notes,
  };
}

function txtRecords(result) {
  if (!result.ok) return null;

  return dedupeRecords(
    recordsOfType(result, TYPE_CODES.TXT).map((answer) => ({
      value: normalizeTxt(answer.data),
    })),
  );
}

function makeSpfSection(result) {
  const records = txtRecords(result);

  if (records === null) {
    return { status: 'error', error: result.error, records: [] };
  }

  const spf = records.filter((record) => /^v=spf1(?:\s|$)/i.test(record.value));
  const notes = [];

  if (spf.length > 1) {
    notes.push('Multiple SPF records were published. More than one SPF record is invalid.');
  }

  return {
    status: spf.length ? 'found' : 'none',
    records: spf,
    notes,
  };
}

function makeDmarcSection(result) {
  const records = txtRecords(result);

  if (records === null) {
    return { status: 'error', error: result.error, records: [] };
  }

  const dmarc = records.filter((record) => /^v=DMARC1(?:\s*;|\s*$)/i.test(record.value));

  return {
    status: dmarc.length ? 'found' : 'none',
    records: dmarc,
    notes: [],
  };
}

async function makeMxAddressSection(provider, mxSection) {
  if (mxSection.status === 'error') {
    return {
      status: 'error',
      error: 'MX records could not be retrieved, so MX addresses were not checked.',
      groups: [],
    };
  }

  if (!mxSection.records.length) {
    return {
      status: 'none',
      groups: [],
      notes: [],
    };
  }

  const resolvableMx = mxSection.records.filter((record) => !record.nullMx);
  const nullMxCount = mxSection.records.length - resolvableMx.length;

  if (!resolvableMx.length) {
    return {
      status: 'none',
      groups: [],
      notes: ['The null MX record means there is no mail server address to resolve.'],
    };
  }

  const groups = await mapLimit(resolvableMx, 4, async (mx) => {
    const result = await querySafe(provider, mx.exchange, 'A');

    if (!result.ok) {
      return {
        exchange: mx.exchange,
        priority: mx.priority,
        status: 'error',
        error: result.error,
        addresses: [],
      };
    }

    const addresses = dedupeRecords(
      recordsOfType(result, TYPE_CODES.A).map((answer) => ({
        value: String(answer.data).trim(),
      })),
    );

    return {
      exchange: mx.exchange,
      priority: mx.priority,
      status: addresses.length ? 'found' : 'none',
      addresses,
    };
  });

  const total = groups.reduce((sum, group) => sum + group.addresses.length, 0);
  const failures = groups.filter((group) => group.status === 'error').length;
  const missing = groups.filter((group) => group.status === 'none').length;
  const notes = [];

  if (nullMxCount) {
    notes.push('The null MX record was skipped because it does not accept email.');
  }
  if (missing) {
    notes.push(
      `${missing} MX host${missing === 1 ? '' : 's'} had no A record.`,
    );
  }
  if (failures) {
    notes.push(
      `${failures} MX host lookup${failures === 1 ? '' : 's'} failed.`,
    );
  }

  return {
    status: total ? 'found' : failures ? 'error' : 'none',
    groups,
    notes,
  };
}

function ptrName(ip) {
  return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

function hasDkimPublicKey(value) {
  const match = String(value).match(/(?:^|;)\s*p\s*=\s*([^;]*)/i);
  return Boolean(match && match[1].replace(/\s+/g, '').length);
}

async function makeDkimSection(provider, domain, customSelector) {
  const selectors = customSelector
    ? [customSelector]
    : COMMON_DKIM_SELECTORS;

  const scanned = await mapLimit(selectors, 4, async (selector) => {
    const name = `${selector}._domainkey.${domain}`;
    const result = await querySafe(provider, name, 'TXT');

    if (!result.ok) {
      return {
        selector,
        status: 'error',
        error: result.error,
        records: [],
        emptyRecords: [],
      };
    }

    const records = dedupeRecords(
      recordsOfType(result, TYPE_CODES.TXT).map((answer) => ({
        value: normalizeTxt(answer.data),
      })),
    );

    const usable = records.filter((record) => hasDkimPublicKey(record.value));
    const emptyRecords = records.filter((record) => !hasDkimPublicKey(record.value));

    return {
      selector,
      status: usable.length ? 'found' : 'none',
      records: usable,
      emptyRecords,
    };
  });

  const found = scanned.filter((entry) => entry.status === 'found');
  const failures = scanned.filter((entry) => entry.status === 'error');
  const empty = scanned.filter((entry) => entry.emptyRecords.length);
  const notes = [];

  if (customSelector) {
    notes.push(`Queried the custom selector “${customSelector}”.`);
  } else {
    notes.push(`Scanned ${selectors.length} common DKIM selectors.`);
  }

  if (failures.length) {
    notes.push(
      `${failures.length} selector${failures.length === 1 ? '' : 's'} could not be checked.`,
    );
  }

  if (empty.length) {
    notes.push(
      `${empty.length} selector${empty.length === 1 ? '' : 's'} publish${empty.length === 1 ? 'es' : ''} an empty p= revocation record, which cannot be used for signing.`,
    );
  }

  if (!found.length) {
    notes.push(
      customSelector
        ? 'No usable DKIM public key was found for this selector.'
        : 'No usable DKIM public key was found at the common selectors.',
    );
  }

  return {
    status: found.length ? 'found' : failures.length === scanned.length ? 'error' : 'none',
    selectors: found,
    revokedSelectors: empty.map((entry) => entry.selector),
    scannedSelectors: selectors,
    failedSelectors: failures.map((entry) => entry.selector),
    notes,
  };
}

async function makePtrSection(provider, aSection, mxAddressSection) {
  const targets = new Map();

  function addTarget(ip, source) {
    if (!targets.has(ip)) {
      targets.set(ip, { ip, sources: new Set() });
    }
    targets.get(ip).sources.add(source);
  }

  for (const record of aSection.records) {
    addTarget(record.value, 'A');
  }

  for (const group of mxAddressSection.groups || []) {
    for (const address of group.addresses) {
      addTarget(address.value, `MX ${group.exchange}`);
    }
  }

  if (!targets.size) {
    return {
      status: 'none',
      entries: [],
      notes: [],
    };
  }

  const allTargets = [...targets.values()];
  const entries = await mapLimit(allTargets, 6, async (target) => {
    const result = await querySafe(provider, ptrName(target.ip), 'PTR');

    if (!result.ok) {
      return {
        ip: target.ip,
        sources: [...target.sources],
        status: 'error',
        error: result.error,
        hostnames: [],
      };
    }

    const hostnames = dedupeRecords(
      recordsOfType(result, TYPE_CODES.PTR).map((answer) => ({
        value: cleanName(answer.data),
      })),
    );

    return {
      ip: target.ip,
      sources: [...target.sources],
      status: hostnames.length ? 'found' : 'none',
      hostnames,
    };
  });

  const found = entries.filter((entry) => entry.status === 'found');
  const failures = entries.filter((entry) => entry.status === 'error');
  const missing = entries.filter((entry) => entry.status === 'none');
  const notes = [];

  if (missing.length && found.length) {
    notes.push(
      `${missing.length} address${missing.length === 1 ? '' : 'es'} had no PTR record.`,
    );
  }
  if (failures.length) {
    notes.push(
      `${failures.length} reverse lookup${failures.length === 1 ? '' : 's'} failed.`,
    );
  }

  return {
    status: found.length ? 'found' : failures.length === entries.length ? 'error' : 'none',
    entries,
    notes,
  };
}

function countSectionRecords(key, section) {
  if (!section) return 0;

  if (key === 'mxA' || key === 'nsA') {
    return (section.groups || []).reduce(
      (sum, group) => sum + (group.addresses?.length || 0),
      0,
    );
  }
  if (key === 'dkim') {
    return (section.selectors || []).reduce(
      (sum, entry) => sum + (entry.records?.length || 0),
      0,
    );
  }
  if (key === 'ptr') {
    return (section.entries || []).reduce(
      (sum, entry) => sum + (entry.hostnames?.length || 0),
      0,
    );
  }
  return section.records?.length || 0;
}

function countRecords(sections) {
  return Object.entries(sections).reduce(
    (total, [key, section]) => total + countSectionRecords(key, section),
    0,
  );
}

function parseRecordTypes(url) {
  const raw = url.searchParams.get('types');
  if (raw === null) return new Set(RECORD_TYPE_KEYS);

  const types = [
    ...new Set(
      raw
        .split(',')
        .map((type) => type.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];

  if (!types.length) {
    throw new HttpError(400, 'Select at least one record type.');
  }

  if (types.some((type) => !RECORD_TYPE_KEYS.includes(type))) {
    throw new HttpError(400, 'One or more selected record types are not supported.');
  }

  return new Set(types);
}

const COMPARISON_LABELS = {
  a: 'A',
  mx: 'MX',
  ns: 'NS',
  spf: 'SPF',
  dkim: 'DKIM',
  dmarc: 'DMARC',
  ptr: 'PTR',
};

const IGNORED_MX_COMPARISON_HOSTS = new Set([
  'aspmx.l.google.com',
  'aspmx1.googlemail.com',
  'aspmx2.googlemail.com',
  'aspmx3.googlemail.com',
  'aspmx4.googlemail.com',
  'aspmx5.googlemail.com',
  'alt1.aspmx.l.google.com',
  'alt2.aspmx.l.google.com',
  'alt3.aspmx.l.google.com',
  'alt4.aspmx.l.google.com',
  'alt5.aspmx.l.google.com',
  'smtp.google.com',
]);

function comparisonValues(key, sections) {
  const section = sections?.[key];
  if (!section) return ['(not returned)'];
  if (section.status === 'error') {
    return [`(lookup failed: ${section.error || 'unknown error'})`];
  }

  if (key === 'mx') {
    const values = [];
    for (const record of section.records || []) {
      if (IGNORED_MX_COMPARISON_HOSTS.has(String(record.exchange).toLowerCase())) {
        continue;
      }
      values.push(`${record.priority} ${record.exchange}`);
    }

    const mxA = sections.mxA;
    if (mxA?.status === 'error') {
      values.push(`(MX address lookup failed: ${mxA.error || 'unknown error'})`);
    } else {
      for (const group of mxA?.groups || []) {
        if (IGNORED_MX_COMPARISON_HOSTS.has(String(group.exchange).toLowerCase())) {
          continue;
        }
        if (group.status === 'error') {
          values.push(`(${group.exchange} address lookup failed)`);
          continue;
        }
        for (const address of group.addresses || []) {
          values.push(`${group.exchange} -> ${address.value}`);
        }
      }
    }
    return [...new Set(values)].sort();
  }

  if (key === 'ns') {
    const values = (section.records || []).map((record) => record.value);
    const nsA = sections.nsA;
    if (nsA?.status === 'error') {
      values.push(`(NS address lookup failed: ${nsA.error || 'unknown error'})`);
    } else {
      for (const group of nsA?.groups || []) {
        if (group.status === 'error') {
          values.push(`(${group.host} address lookup failed)`);
          continue;
        }
        for (const address of group.addresses || []) {
          values.push(`${group.host} -> ${address.value}`);
        }
      }
    }
    return [...new Set(values)].sort();
  }

  if (key === 'dkim') {
    const values = [];
    for (const selector of section.selectors || []) {
      for (const record of selector.records || []) {
        values.push(`${selector.selector}: ${record.value}`);
      }
    }
    return [...new Set(values)].sort();
  }

  if (key === 'ptr') {
    const values = [];
    for (const entry of section.entries || []) {
      if (entry.status === 'error') {
        values.push(`${entry.ip} -> (lookup failed)`);
      } else if (!entry.hostnames?.length) {
        values.push(`${entry.ip} -> (none)`);
      } else {
        for (const hostname of entry.hostnames) {
          values.push(`${entry.ip} -> ${hostname.value}`);
        }
      }
    }
    return [...new Set(values)].sort();
  }

  return [
    ...new Set((section.records || []).map((record) => String(record.value))),
  ].sort();
}

function buildComparison(
  selectedTypes,
  primarySections,
  secondarySections,
  secondaryError,
  primaryProvider,
  secondaryProvider,
) {
  const comparedTypes = RECORD_TYPE_KEYS.filter(
    (key) => key !== 'registrar' && key !== 'http' && selectedTypes.has(key),
  );
  const base = {
    primary: { id: primaryProvider.id, label: primaryProvider.label },
    secondary: { id: secondaryProvider.id, label: secondaryProvider.label },
    comparedTypes,
    differences: [],
  };

  if (!comparedTypes.length) {
    return { ...base, status: 'not-applicable' };
  }

  if (secondaryError) {
    return {
      ...base,
      status: 'unavailable',
      error:
        secondaryError instanceof Error
          ? secondaryError.message
          : 'The second DNS upstream could not be checked.',
    };
  }

  const differences = [];
  for (const key of comparedTypes) {
    const primaryValues = comparisonValues(key, primarySections);
    const secondaryValues = comparisonValues(key, secondarySections);
    if (primaryValues.join('\n') !== secondaryValues.join('\n')) {
      differences.push({
        key,
        label: COMPARISON_LABELS[key] || key.toUpperCase(),
        primary: primaryValues,
        secondary: secondaryValues,
      });
    }
  }

  return {
    ...base,
    status: differences.length ? 'different' : 'match',
    differences,
  };
}

async function collectResolverSections(provider, domain, selectedTypes, rawSelector) {
  const dmarcName = `_dmarc.${domain}`;
  const wantsA = selectedTypes.has('a') || selectedTypes.has('ptr');
  const wantsMx = selectedTypes.has('mx') || selectedTypes.has('ptr');
  const wantsNs = selectedTypes.has('ns');
  const wantsSpf = selectedTypes.has('spf');
  const wantsDkim = selectedTypes.has('dkim');
  const wantsDmarc = selectedTypes.has('dmarc');
  const wantsPtr = selectedTypes.has('ptr');
  const wantsMxAddresses = selectedTypes.has('mx') || wantsPtr;

  const [aResult, mxResult, nsResult, txtResult, dmarcResult] =
    await Promise.all([
      wantsA ? querySafe(provider, domain, 'A') : null,
      wantsMx ? querySafe(provider, domain, 'MX') : null,
      wantsNs ? querySafe(provider, domain, 'NS') : null,
      wantsSpf ? querySafe(provider, domain, 'TXT') : null,
      wantsDmarc ? querySafe(provider, dmarcName, 'TXT') : null,
    ]);

  const baseResults = [aResult, mxResult, nsResult, txtResult, dmarcResult].filter(
    Boolean,
  );
  const successfulBaseQueries = baseResults.filter((result) => result.ok).length;

  if (baseResults.length && successfulBaseQueries === 0) {
    throw new HttpError(
      502,
      `The ${provider.label} resolver could not be reached. Check your connection and try again.`,
    );
  }

  if (
    baseResults.length &&
    baseResults.every((result) => result.ok && result.status === 3)
  ) {
    throw new HttpError(
      404,
      `No DNS records exist for ${domain}. Check the spelling and try again.`,
    );
  }

  const sections = {};
  let aSection = null;
  let mxSection = null;
  let mxASection = null;
  let nsSection = null;
  let nsASection = null;

  if (wantsA) {
    aSection = makeAddressSection(aResult);
    if (selectedTypes.has('a')) sections.a = aSection;
  }

  if (wantsMx) {
    mxSection = makeMxSection(mxResult);
    if (selectedTypes.has('mx')) sections.mx = mxSection;
  }

  if (wantsNs) {
    nsSection = makeNsSection(nsResult);
    sections.ns = nsSection;
  }
  if (wantsSpf) sections.spf = makeSpfSection(txtResult);
  if (wantsDmarc) sections.dmarc = makeDmarcSection(dmarcResult);

  const [resolvedMxA, resolvedNsA, dkim] = await Promise.all([
    wantsMxAddresses ? makeMxAddressSection(provider, mxSection) : null,
    wantsNs ? makeNsAddressSection(provider, nsSection) : null,
    wantsDkim ? makeDkimSection(provider, domain, rawSelector) : null,
  ]);
  mxASection = resolvedMxA;
  nsASection = resolvedNsA;

  if (selectedTypes.has('mx') && mxASection) sections.mxA = mxASection;
  if (selectedTypes.has('ns') && nsASection) sections.nsA = nsASection;
  if (dkim) sections.dkim = dkim;

  if (wantsPtr) {
    sections.ptr = await makePtrSection(provider, aSection, mxASection);
  }

  return { sections };
}

async function handleLookup(url, res) {
  const startedAt = Date.now();
  const domain = normalizeDomain(url.searchParams.get('domain'));
  const providerId = (url.searchParams.get('resolver') || 'google').toLowerCase();

  const provider = PROVIDERS[providerId];
  if (!provider) {
    throw new HttpError(400, 'Choose a supported DNS upstream.');
  }

  const secondaryProvider =
    provider.id === 'google' ? PROVIDERS.cloudflare : PROVIDERS.google;

  const rawSelector = String(url.searchParams.get('dkimSelector') || '').trim().toLowerCase();
  if (rawSelector && !/^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/i.test(rawSelector)) {
    throw new HttpError(400, 'That DKIM selector contains invalid characters.');
  }

  const selectedTypes = parseRecordTypes(url);
  const resolverTypes = new Set(
    [...selectedTypes].filter((type) => type !== 'registrar' && type !== 'http'),
  );
  const registrarPromise = selectedTypes.has('registrar')
    ? makeRegistrarSection(domain)
    : Promise.resolve(null);
  const httpPromise = selectedTypes.has('http')
    ? makeHttpSection(domain)
    : Promise.resolve(null);

  const secondaryPromise = resolverTypes.size
    ? collectResolverSections(
        secondaryProvider,
        domain,
        resolverTypes,
        rawSelector,
      ).catch((error) => ({ error }))
    : Promise.resolve({ sections: {} });

  const [primary, secondary, registrar, http] = await Promise.all([
    collectResolverSections(provider, domain, resolverTypes, rawSelector),
    secondaryPromise,
    registrarPromise,
    httpPromise,
  ]);

  const sections = primary.sections;
  if (registrar) sections.registrar = registrar;
  if (http) sections.http = http;

  const comparison = buildComparison(
    selectedTypes,
    primary.sections,
    secondary.sections,
    secondary.error,
    provider,
    secondaryProvider,
  );

  sendJson(res, 200, {
    ok: true,
    domain,
    resolver: {
      id: provider.id,
      label: provider.label,
      address: provider.address,
    },
    dkimSelector: rawSelector || null,
    queriedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    recordCount: countRecords(sections),
    recordSetCount: Object.keys(sections).length,
    comparison,
    sections,
  });
}

async function serveStatic(req, res, pathname) {
  const asset = STATIC_FILES[pathname];
  if (!asset) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' });
    res.end();
    return;
  }

  try {
    const body = await fs.readFile(path.join(PUBLIC_DIR, asset.file));
    res.writeHead(200, {
      'Content-Type': asset.type,
      'Content-Length': body.length,
      'Cache-Control': 'no-cache',
    });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch (error) {
    if (error.code === 'ENOENT') {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }
    throw error;
  }
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );

  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (url.pathname === '/api/dns') {
      if (req.method !== 'GET') {
        sendJson(res, 405, { ok: false, error: 'Method not allowed.' });
        return;
      }
      await handleLookup(url, res);
      return;
    }

    if (url.pathname === '/health') {
      sendJson(res, 200, { ok: true });
      return;
    }

    await serveStatic(req, res, url.pathname);
  } catch (error) {
    if (res.headersSent) {
      res.end();
      return;
    }

    if (error instanceof HttpError) {
      sendJson(res, error.status, { ok: false, error: error.message });
      return;
    }

    console.error('[dns-checker]', error);
    sendJson(res, 500, {
      ok: false,
      error: 'Something went wrong while looking up that domain.',
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`DNS Checker running at http://${HOST}:${PORT}`);
});

server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Set PORT to a free port and try again.`);
    process.exitCode = 1;
    return;
  }
  throw error;
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

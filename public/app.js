'use strict';

const SECTIONS = [
  { key: 'a', title: 'A' },
  { key: 'mx', title: 'MX' },
  { key: 'ns', title: 'NS' },
  { key: 'spf', title: 'SPF' },
  { key: 'dkim', title: 'DKIM' },
  { key: 'dmarc', title: 'DMARC' },
  { key: 'ptr', title: 'PTR' },
  { key: 'registrar', title: 'Domain registrar' },
  { key: 'http', title: 'HTTP headers' },
];

const EMPTY_TEXT = {
  a: 'No A record found.',
  mx: 'No MX record found.',
  ns: 'No NS records found.',
  http: 'No HTTP response headers found.',
  spf: 'No SPF record found.',
  dkim: 'No usable DKIM key found.',
  dmarc: 'No DMARC record found.',
  ptr: 'No PTR records found.',
  registrar: 'No registrar found.',
};

const PROVIDER_LABELS = {
  google: 'Google',
  cloudflare: 'Cloudflare',
};

const form = document.getElementById('lookup-form');
const domainInput = document.getElementById('domain');
const submitButton = document.getElementById('submit-button');
const submitLabel = document.getElementById('submit-label');
const statusRegion = document.getElementById('status-region');
const loadingView = document.getElementById('loading-view');
const loadingCard = document.getElementById('loading-card');
const errorView = document.getElementById('error-view');
const errorTitle = document.getElementById('error-title');
const errorMessage = document.getElementById('error-message');
const errorRetry = document.getElementById('error-retry');
const resultsView = document.getElementById('results-view');
const resultsTitle = document.getElementById('results-title');
const resultMeta = document.getElementById('result-meta');
const comparisonPanel = document.getElementById('comparison-panel');
const recordSections = document.getElementById('record-sections');
const noSelection = document.getElementById('no-selection');
const filterInputs = [...document.querySelectorAll('[data-filter]')];
const copyAllButton = document.getElementById('copy-all');
const copyLabel = document.getElementById('copy-label');
const refreshButton = document.getElementById('refresh-button');
const toast = document.getElementById('toast');

let activeController = null;
let lastResponse = null;
let sectionElements = new Map();
let copyResetTimer = null;
let toastTimer = null;
let filterRefreshTimer = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function providerLabelFor(id) {
  return PROVIDER_LABELS[id] || 'selected';
}

function readForm() {
  return {
    domain: domainInput.value.trim(),
    types: [...selectedKeys()],
  };
}

function setBusy(busy) {
  submitButton.disabled = busy;
  submitButton.classList.toggle('is-loading', busy);
  submitLabel.textContent = busy ? 'Looking up' : 'Look up';
  refreshButton.disabled = busy;
  copyAllButton.disabled =
    busy || !lastResponse || selectedKeys().size === 0;
  for (const input of filterInputs) input.disabled = busy;
}

function formatDuration(milliseconds) {
  if (!Number.isFinite(milliseconds)) return '';
  if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
  return `${(milliseconds / 1000).toFixed(1)} s`;
}

function showToast(message) {
  window.clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add('is-visible');
  toastTimer = window.setTimeout(() => {
    toast.classList.remove('is-visible');
  }, 2400);
}

function createLoadingSection() {
  const section = el('div', 'loading-section');
  section.append(
    el('div', 'skeleton skeleton-heading'),
    el('div', 'skeleton skeleton-line'),
    el('div', 'skeleton skeleton-line short'),
  );
  return section;
}

function showLoading(state) {
  resultsView.hidden = true;
  errorView.hidden = true;
  loadingView.hidden = false;
  loadingCard.replaceChildren(
    ...Array.from({ length: 4 }, () => createLoadingSection()),
  );
  statusRegion.textContent = `Looking up ${state.domain}.`;
}

function showError(message, statusCode, state) {
  loadingView.hidden = true;
  resultsView.hidden = true;
  errorView.hidden = false;

  errorTitle.textContent =
    statusCode === 404 ? 'No records found.' : 'Lookup failed.';
  errorMessage.textContent = message || 'Check the domain name and try again.';

  domainInput.setAttribute(
    'aria-invalid',
    statusCode === 400 || statusCode === 404 ? 'true' : 'false',
  );

  if (statusCode === 400) {
    domainInput.focus();
  }

  statusRegion.textContent = `Lookup failed for ${state.domain}. ${message}`;
}

function mxAddressGroup(mxASection, exchange) {
  return (
    (mxASection?.groups || []).find((group) => group.exchange === exchange) ||
    null
  );
}

function nsAddressGroup(nsASection, host) {
  return (
    (nsASection?.groups || []).find((group) => group.host === host) || null
  );
}

function countMxSection(mxSection, mxASection) {
  return (
    (mxSection?.records?.length || 0) +
    (mxASection?.groups || []).reduce(
      (total, group) => total + (group.addresses?.length || 0),
      0,
    )
  );
}

function countNsSection(nsSection, nsASection) {
  return (
    (nsSection?.records?.length || 0) +
    (nsASection?.groups || []).reduce(
      (total, group) => total + (group.addresses?.length || 0),
      0,
    )
  );
}

function countSection(key, section, mxASection, nsASection) {
  if (!section) return 0;
  switch (key) {
    case 'a':
    case 'http':
    case 'spf':
    case 'dmarc':
    case 'registrar':
      return section.records?.length || 0;
    case 'ns':
      return countNsSection(section, nsASection);
    case 'mx':
      return countMxSection(section, mxASection);
    case 'dkim':
      return (section.selectors || []).reduce(
        (total, selector) => total + (selector.records?.length || 0),
        0,
      );
    case 'ptr':
      return (section.entries || []).reduce(
        (total, entry) => total + (entry.hostnames?.length || 0),
        0,
      );
    default:
      return 0;
  }
}

function recordRow(record, options = {}) {
  const row = el('div', 'record-row');
  const main = el('div', 'record-main');
  main.append(
    el(
      'code',
      `record-value${options.txt ? ' txt' : ''}`,
      String(record.value),
    ),
  );
  row.append(main);
  return row;
}

function emptyState(text) {
  return el('div', 'empty-state', text);
}

function errorBlock(message) {
  return el('div', 'card-error', message || 'This record could not be retrieved.');
}

function addNotes(card, notes) {
  if (!notes || !notes.length) return;
  const wrapper = el('div', 'card-notes');
  for (const note of notes) {
    wrapper.append(el('p', 'card-note', note));
  }
  card.append(wrapper);
}

function renderSimpleRecords(key, body, section) {
  if (section.status === 'error') {
    body.append(errorBlock(section.error));
    return;
  }

  if (!section.records || !section.records.length) {
    body.append(emptyState(EMPTY_TEXT[key]));
    return;
  }

  for (const record of section.records) {
    body.append(recordRow(record, { txt: key === 'spf' || key === 'dmarc' }));
  }
}

function renderMx(body, section, mxASection) {
  if (section.status === 'error') {
    body.append(errorBlock(section.error));
    return;
  }

  if (!section.records || !section.records.length) {
    body.append(emptyState(EMPTY_TEXT.mx));
    return;
  }

  const addressesUnavailable =
    mxASection?.status === 'error'
      ? mxASection.error || 'MX addresses could not be retrieved.'
      : null;

  for (const [index, record] of section.records.entries()) {
    const block = el('div', 'mx-group');
    const head = el('div', 'group-head');
    const name = el('div', 'group-name');
    name.append(
      el('span', 'priority', String(record.priority)),
      el('code', 'record-value', record.exchange),
    );

    const addresses = el('div', 'group-address');
    addresses.id = `mx-addresses-${index}`;
    const group = mxAddressGroup(mxASection, record.exchange);

    if (!record.nullMx) {
      const toggle = el('button', 'address-toggle', 'Show');
      toggle.type = 'button';
      toggle.setAttribute('aria-expanded', 'false');
      toggle.setAttribute('aria-controls', addresses.id);
      toggle.setAttribute(
        'aria-label',
        `Show A records for ${record.exchange}`,
      );
      toggle.addEventListener('click', () => {
        const show = addresses.hidden;
        addresses.hidden = !show;
        toggle.textContent = show ? 'Hide' : 'Show';
        toggle.setAttribute('aria-expanded', String(show));
        toggle.setAttribute(
          'aria-label',
          `${show ? 'Hide' : 'Show'} A records for ${record.exchange}`,
        );
      });
      name.append(toggle);
      addresses.hidden = true;
    }

    if (record.nullMx) {
      addresses.append(
        el('p', 'group-message', 'Null MX - this domain does not accept email.'),
      );
    } else if (group?.status === 'error') {
      addresses.append(
        el('p', 'group-message', group.error || 'Address lookup failed.'),
      );
    } else if (addressesUnavailable) {
      addresses.append(el('p', 'group-message', addressesUnavailable));
    } else if (!group || !group.addresses?.length) {
      addresses.append(el('p', 'group-message', 'No A record found.'));
    } else {
      for (const address of group.addresses) {
        addresses.append(recordRow(address));
      }
    }

    head.append(name);
    block.append(head, addresses);
    body.append(block);
  }
}

function renderHttp(body, section) {
  if (section.status === 'error') {
    body.append(errorBlock(section.error));
    return;
  }

  if (!section.records || !section.records.length) {
    body.append(emptyState(EMPTY_TEXT.http));
    return;
  }

  for (const record of section.records) {
    const row = el('div', 'record-row http-row');
    const main = el('div', 'record-main http-line');
    main.append(
      el('span', 'http-label', record.label),
      el('code', 'record-value', record.value),
    );
    row.append(main);
    body.append(row);
  }
}

function renderNs(body, section, nsASection) {
  if (section.status === 'error') {
    body.append(errorBlock(section.error));
    return;
  }

  if (!section.records || !section.records.length) {
    body.append(emptyState(EMPTY_TEXT.ns));
    return;
  }

  const addressesUnavailable =
    nsASection?.status === 'error'
      ? nsASection.error || 'NS addresses could not be retrieved.'
      : null;

  for (const [index, record] of section.records.entries()) {
    const block = el('div', 'mx-group ns-group');
    const head = el('div', 'group-head');
    const name = el('div', 'group-name');
    name.append(el('code', 'record-value', record.value));

    const addresses = el('div', 'group-address');
    addresses.id = `ns-addresses-${index}`;
    addresses.hidden = true;
    const group = nsAddressGroup(nsASection, record.value);

    const toggle = el('button', 'address-toggle', 'Show');
    toggle.type = 'button';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-controls', addresses.id);
    toggle.setAttribute('aria-label', `Show A records for ${record.value}`);
    toggle.addEventListener('click', () => {
      const show = addresses.hidden;
      addresses.hidden = !show;
      toggle.textContent = show ? 'Hide' : 'Show';
      toggle.setAttribute('aria-expanded', String(show));
      toggle.setAttribute(
        'aria-label',
        `${show ? 'Hide' : 'Show'} A records for ${record.value}`,
      );
    });
    name.append(toggle);

    if (group?.status === 'error') {
      addresses.append(
        el('p', 'group-message', group.error || 'Address lookup failed.'),
      );
    } else if (addressesUnavailable) {
      addresses.append(el('p', 'group-message', addressesUnavailable));
    } else if (!group || !group.addresses?.length) {
      addresses.append(el('p', 'group-message', 'No A record found.'));
    } else {
      for (const address of group.addresses) {
        addresses.append(recordRow(address));
      }
    }

    head.append(name);
    block.append(head, addresses);
    body.append(block);
  }
}

function renderDkim(body, section) {
  if (section.status === 'error' && !(section.selectors || []).length) {
    body.append(errorBlock('The DKIM selectors could not be checked.'));
    return;
  }

  if (!section.selectors || !section.selectors.length) {
    body.append(emptyState(EMPTY_TEXT.dkim));
    return;
  }

  for (const selector of section.selectors) {
    const block = el('div', 'dkim-selector');
    const head = el('div', 'selector-head');
    head.append(
      el('span', 'selector-label', selector.selector),
      el('span', 'selector-caption', 'selector'),
    );
    block.append(head);

    for (const record of selector.records) {
      block.append(recordRow(record, { txt: true }));
    }

    body.append(block);
  }
}

function renderPtr(body, section) {
  if (section.status === 'error' && !(section.entries || []).length) {
    body.append(errorBlock('The reverse DNS lookups could not be completed.'));
    return;
  }

  if (!section.entries || !section.entries.length) {
    body.append(emptyState(EMPTY_TEXT.ptr));
    return;
  }

  for (const entry of section.entries) {
    const row = el('div', 'record-row');
    const main = el('div', 'record-main');
    const line = el('div', 'ptr-line');
    line.append(el('code', 'record-value', entry.ip), el('span', 'ptr-arrow', '→'));

    if (entry.status === 'error') {
      line.append(el('span', 'ptr-missing', 'Lookup failed'));
    } else if (!entry.hostnames || !entry.hostnames.length) {
      line.append(el('span', 'ptr-missing', 'No PTR record'));
    } else {
      line.append(
        el(
          'code',
          'record-value',
          entry.hostnames.map((hostname) => hostname.value).join(', '),
        ),
      );
    }

    main.append(line);
    if (entry.sources && entry.sources.length) {
      main.append(el('span', 'ptr-source', `from ${entry.sources.join(' · ')}`));
    }
    row.append(main);
    body.append(row);
  }
}

function buildSection(meta, section, mxASection, nsASection) {
  const wrapper = el('section', 'record-section');
  wrapper.dataset.category = meta.key;
  wrapper.setAttribute('aria-labelledby', `section-${meta.key}-title`);

  const head = el('div', 'section-head');
  const heading = el('h3', '', meta.title);
  heading.id = `section-${meta.key}-title`;

  const count = countSection(meta.key, section, mxASection, nsASection);
  let badgeText = 'None';
  let badgeClass = 'none';

  if (section.status === 'error') {
    badgeText = 'Error';
    badgeClass = 'error';
  } else if (count > 0) {
    badgeText = `${count} ${count === 1 ? 'record' : 'records'}`;
    badgeClass = 'found';
  }

  head.append(heading, el('span', `section-badge ${badgeClass}`, badgeText));

  const body = el('div', 'section-body');
  switch (meta.key) {
    case 'mx':
      renderMx(body, section, mxASection);
      break;
    case 'ns':
      renderNs(body, section, nsASection);
      break;
    case 'http':
      renderHttp(body, section);
      break;
    case 'dkim':
      renderDkim(body, section);
      break;
    case 'ptr':
      renderPtr(body, section);
      break;
    default:
      renderSimpleRecords(meta.key, body, section);
  }

  wrapper.append(head, body);
  const notes =
    meta.key === 'mx'
      ? [...new Set([...(section.notes || []), ...(mxASection?.notes || [])])]
      : meta.key === 'ns'
        ? [...new Set([...(section.notes || []), ...(nsASection?.notes || [])])]
        : section.notes;
  addNotes(wrapper, notes);
  return wrapper;
}

function addMetaChip(text) {
  const chip = el('span', 'meta-chip', text);
  chip.setAttribute('role', 'listitem');
  resultMeta.append(chip);
  return chip;
}

function selectedKeys() {
  return new Set(
    filterInputs
      .filter((input) => input.checked)
      .map((input) => input.dataset.filter),
  );
}

function applyFilters() {
  if (!lastResponse) return;

  const selected = selectedKeys();
  let visibleRecords = 0;
  let firstVisible = true;

  for (const [key, section] of sectionElements) {
    const visible = selected.has(key);
    section.hidden = !visible;
    section.classList.toggle('first-visible', visible && firstVisible);

    if (visible) {
      firstVisible = false;
      visibleRecords += countSection(
        key,
        lastResponse.sections[key],
        lastResponse.sections.mxA,
        lastResponse.sections.nsA,
      );
    }
  }

  noSelection.hidden = selected.size > 0;

  const countChip = document.getElementById('record-count-meta');
  if (countChip) {
    countChip.textContent = `${visibleRecords} ${
      visibleRecords === 1 ? 'record' : 'records'
    }`;
  }

  copyAllButton.disabled = selected.size === 0;
  statusRegion.textContent = selected.size
    ? `Showing ${selected.size} record types.`
    : 'No record types selected.';
}

function comparisonValuesNode(values) {
  const list = el('div', 'comparison-values');
  if (!values || !values.length) {
    list.append(el('span', 'comparison-empty', '(none)'));
    return list;
  }

  for (const value of values) {
    list.append(el('code', 'comparison-value', value));
  }
  return list;
}

function renderComparison(data) {
  const comparison = data.comparison;
  comparisonPanel.replaceChildren();
  comparisonPanel.hidden =
    !comparison ||
    (comparison.status !== 'different' && comparison.status !== 'unavailable');
  comparisonPanel.className = 'comparison-panel';

  if (comparisonPanel.hidden) return;

  const primaryLabel = comparison.primary?.label || 'Selected upstream';
  const secondaryLabel = comparison.secondary?.label || 'Other upstream';
  comparisonPanel.classList.add(`is-${comparison.status}`);

  const title = el('h3', 'comparison-title');
  title.textContent =
    comparison.status === 'different'
      ? 'Upstream results differ'
      : 'Upstream comparison unavailable';
  comparisonPanel.append(title);

  if (comparison.status === 'unavailable') {
    comparisonPanel.append(
      el(
        'p',
        'comparison-summary',
        `Could not compare with ${secondaryLabel}: ${comparison.error || 'the lookup failed.'}`,
      ),
    );
    return;
  }

  comparisonPanel.append(
    el(
      'p',
      'comparison-summary',
      `Differences were found between ${primaryLabel} and ${secondaryLabel}. This may indicate DNS propagation or cached answers. Compare both sets before relying on the record change.`,
    ),
  );

  for (const difference of comparison.differences || []) {
    const block = el('div', 'comparison-diff');
    const head = el('div', 'comparison-diff-head');
    head.append(el('strong', 'comparison-record', difference.label));
    block.append(head);

    for (const [side, label] of [
      ['primary', primaryLabel],
      ['secondary', secondaryLabel],
    ]) {
      const row = el('div', 'comparison-provider');
      row.append(
        el('span', 'comparison-provider-name', label),
        comparisonValuesNode(difference[side]),
      );
      block.append(row);
    }

    comparisonPanel.append(block);
  }
}

function renderResults(data) {
  lastResponse = data;

  resultsTitle.textContent = data.domain;
  resultMeta.replaceChildren();
  addMetaChip(
    data.comparison
      ? `Checked ${data.comparison.primary.label} + ${data.comparison.secondary.label}`
      : 'Checked both upstreams',
  );
  const countChip = addMetaChip(
    `${data.recordCount} ${data.recordCount === 1 ? 'record' : 'records'}`,
  );
  countChip.id = 'record-count-meta';
  addMetaChip(`Answered in ${formatDuration(data.durationMs)}`);

  sectionElements = new Map();
  const sections = SECTIONS.map((meta) => {
    const mxASection =
      meta.key === 'mx'
        ? data.sections.mxA || { status: 'none', groups: [] }
        : null;
    const nsASection =
      meta.key === 'ns'
        ? data.sections.nsA || { status: 'none', groups: [] }
        : null;
    const section = buildSection(
      meta,
      data.sections[meta.key] || { status: 'none', records: [] },
      mxASection,
      nsASection,
    );
    sectionElements.set(meta.key, section);
    return section;
  });
  recordSections.replaceChildren(...sections);

  const diffKeys = new Set(
    (data.comparison?.differences || []).map((difference) => difference.key),
  );
  for (const [key, section] of sectionElements) {
    section.classList.toggle('has-resolver-diff', diffKeys.has(key));
  }
  renderComparison(data);

  loadingView.hidden = true;
  errorView.hidden = true;
  resultsView.hidden = false;
  domainInput.setAttribute('aria-invalid', 'false');

  copyLabel.textContent = 'Copy shown';
  refreshButton.disabled = false;

  applyFilters();
}

function formatAllRecords(data) {
  const lines = [
    data.domain,
    `Checked: ${data.comparison?.primary?.label || 'Google'} + ${data.comparison?.secondary?.label || 'Cloudflare'}`,
  ];

  if (data.comparison?.status === 'different') {
    const primary = data.comparison.primary?.label || 'Selected upstream';
    const secondary = data.comparison.secondary?.label || 'Other upstream';
    lines.push(`Upstream comparison: ${primary} and ${secondary} differ`);
    for (const difference of data.comparison.differences || []) {
      lines.push(
        `  ${difference.label}: ${primary} ${difference.primary.join(', ') || '(none)'} | ${secondary} ${difference.secondary.join(', ') || '(none)'}`,
      );
    }
  } else if (data.comparison?.status === 'unavailable') {
    lines.push(
      `Upstream comparison unavailable: ${data.comparison.error || 'second upstream lookup failed'}`,
    );
  }

  lines.push('');

  const s = data.sections;
  const selected = selectedKeys();

  for (const meta of SECTIONS) {
    if (!selected.has(meta.key)) continue;
    lines.push(meta.title);

    if (meta.key === 'mx') {
      if (s.mx.records.length) {
        for (const record of s.mx.records) {
          lines.push(`  ${record.priority} ${record.exchange}`);

          if (record.nullMx) {
            lines.push('    (null MX - no mail service)');
            continue;
          }

          const group = mxAddressGroup(s.mxA, record.exchange);
          if (group?.status === 'error') {
            lines.push(`    (A lookup failed: ${group.error || 'unknown error'})`);
          } else if (group?.addresses?.length) {
            for (const address of group.addresses) {
              lines.push(`    ${address.value}`);
            }
          } else if (s.mxA?.status === 'error') {
            lines.push('    (A lookup failed)');
          } else {
            lines.push('    (no A record)');
          }
        }
      } else {
        lines.push('  (none)');
      }
    } else if (meta.key === 'ns') {
      if (s.ns.records.length) {
        for (const record of s.ns.records) {
          lines.push(`  ${record.value}`);
          const group = nsAddressGroup(s.nsA, record.value);
          if (group?.status === 'error') {
            lines.push(`    (A lookup failed: ${group.error || 'unknown error'})`);
          } else if (group?.addresses?.length) {
            for (const address of group.addresses) {
              lines.push(`    ${address.value}`);
            }
          } else if (s.nsA?.status === 'error') {
            lines.push('    (A lookup failed)');
          } else {
            lines.push('    (no A record)');
          }
        }
      } else {
        lines.push('  (none)');
      }
    } else if (meta.key === 'http') {
      if (s.http.records.length) {
        for (const record of s.http.records) {
          lines.push(`  ${record.label}: ${record.value}`);
        }
      } else {
        lines.push('  (none)');
      }
    } else if (meta.key === 'dkim') {
      if (s.dkim.selectors.length) {
        for (const selector of s.dkim.selectors) {
          lines.push(`  selector: ${selector.selector}`);
          for (const record of selector.records) {
            lines.push(`    ${record.value}`);
          }
        }
      } else {
        lines.push('  (none)');
      }
    } else if (meta.key === 'ptr') {
      if (s.ptr.entries.length) {
        for (const entry of s.ptr.entries) {
          const names = entry.hostnames.map((hostname) => hostname.value).join(', ');
          lines.push(`  ${entry.ip} → ${names || '(none)'}`);
        }
      } else {
        lines.push('  (none)');
      }
    } else if (s[meta.key].records.length) {
      for (const record of s[meta.key].records) {
        lines.push(`  ${record.value}`);
      }
    } else {
      lines.push('  (none)');
    }

    lines.push('');
  }

  return lines.join('\n').trim();
}

async function copyAllRecords() {
  if (!lastResponse || selectedKeys().size === 0) return;

  try {
    await navigator.clipboard.writeText(formatAllRecords(lastResponse));
    copyLabel.textContent = 'Copied';
    showToast('Copied.');
    window.clearTimeout(copyResetTimer);
    copyResetTimer = window.setTimeout(() => {
      copyLabel.textContent = 'Copy shown';
    }, 2000);
  } catch {
    showToast('Copy failed.');
  }
}

async function runLookup(state) {
  if (activeController) {
    activeController.abort();
  }

  const controller = new AbortController();
  activeController = controller;

  setBusy(true);
  showLoading(state);

  const params = new URLSearchParams();
  params.set('domain', state.domain);
  params.set('types', state.types.join(','));

  try {
    const response = await fetch(`/api/dns?${params.toString()}`, {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });

    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }

    if (!response.ok) {
      const error = new Error(
        payload?.error || `The lookup failed (HTTP ${response.status}).`,
      );
      error.status = response.status;
      throw error;
    }

    if (!payload?.ok || !payload.sections) {
      throw new Error('The DNS service returned an unexpected response.');
    }

    renderResults(payload);

    if (window.matchMedia('(max-width: 680px)').matches) {
      resultsView.scrollIntoView({ block: 'start' });
    }
  } catch (error) {
    if (controller.signal.aborted) return;

    const message =
      error instanceof TypeError
        ? 'Could not reach the local DNS service. Is the server running?'
        : error.message || 'Something went wrong.';

    showError(message, error.status, state);
  } finally {
    if (activeController === controller) {
      activeController = null;
      setBusy(false);
    }
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const state = readForm();

  if (!state.domain) {
    domainInput.setAttribute('aria-invalid', 'true');
    domainInput.focus();
    showToast('Enter a domain name.');
    return;
  }

  if (!state.types.length) {
    showToast('Select at least one record type.');
    return;
  }

  runLookup(state);
});

domainInput.addEventListener('input', () => {
  if (domainInput.getAttribute('aria-invalid') === 'true') {
    domainInput.setAttribute('aria-invalid', 'false');
  }
});

for (const input of filterInputs) {
  input.addEventListener('change', () => {
    const selected = selectedKeys();

    if (!selected.size) {
      applyFilters();
      showToast('Select at least one record type.');
      return;
    }

    if (!lastResponse) return;

    window.clearTimeout(filterRefreshTimer);
    filterRefreshTimer = window.setTimeout(() => {
      if (selectedKeys().size) runLookup(readForm());
    }, 180);
  });
}

copyAllButton.addEventListener('click', copyAllRecords);

refreshButton.addEventListener('click', () => {
  runLookup(readForm());
});

errorRetry.addEventListener('click', () => {
  runLookup(readForm());
});

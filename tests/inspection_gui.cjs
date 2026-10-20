// Optional browser smoke test: NODE_PATH=<playwright packages> node tests/inspection_gui.cjs
// Serve frontend on 127.0.0.1:18763 first. Backend responses are mocked; no live traffic is modified.
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const sxbn = require('../frontend/sxbn.js');
const apiSchema = JSON.parse(require('node:child_process').execFileSync('python3',
  ['-c', 'import sys,json; sys.path.insert(0,"src"); from inspection_api import api_schema; print(json.dumps(api_schema()))'],
  {encoding: 'utf8'}));
(async () => {
  const browser = await chromium.launch({headless: true,
    ...(process.env.CHROMIUM_PATH ? {executablePath: process.env.CHROMIUM_PATH} : {})});
  try {
    const page = await browser.newPage({viewport: {width: 1600, height: 1000}});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(() => localStorage.setItem('spider-backend', 'http://127.0.0.1:18765'));
    let state = {revision: 1, script: '', scope: 'chain', enabled: false, running: 0, runs: 0, errors: 0,
      recent: [], chain: [], traffic_rules: {rules: [], bypass_all: false},
      collection: {saved: 0, bytes: 0, limit_bytes: 1000000, directory: '/tmp/samples', errors: 0, last_error: ''}};
    const writes = [];
    let replayTest = false;
    let savedFlow = null;
    let frontendVersion = 'aaaaaaaaaaaa';
    await page.route('http://127.0.0.1:18763/', async route => {
      const response = await route.fetch();
      await route.fulfill({response, body: (await response.text()).replace(
        'name="frontend-version" content="development"',
        'name="frontend-version" content="aaaaaaaaaaaa"')});
    });
    await page.route('http://127.0.0.1:18763/frontend-version.json', route =>
      route.fulfill({json: {version: frontendVersion}}));
    await page.route('http://127.0.0.1:18765/**', async route => {
      const request = route.request();
      if (request.method() === 'OPTIONS') return route.fulfill({status: 204, headers: {
        'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*'}});
      let body = {};
      if (request.url().endsWith('/api/inspection/saved-flows') && request.method() === 'POST') {
        savedFlow = {...request.postDataJSON(), id: 'saved-test', format: 'spider-flow-v1', saved_at_ms: 123};
        body = {id: savedFlow.id, name: savedFlow.name, records: savedFlow.records.length};
      }
      if (request.url().includes('/api/inspection/saved-flows?')) body = {
        items: savedFlow ? [{id: savedFlow.id, name: savedFlow.name, records: savedFlow.records.length, saved_at_ms: 123}] : [],
        total: savedFlow ? 1 : 0, next: null};
      if (request.url().includes('/api/inspection/saved-flow?')) body = savedFlow;
      if (request.url().endsWith('/api/enrichment/replay')) {
        const inputs = sxbn.decode(request.postDataBuffer());
        const outputs = (replayTest ? inputs : []).map((item, replay_index) => sxbn.encode({
          type: 'enrichment', operation: 'test.replay', replay_index, replayed: true,
        }, new TextEncoder().encode('replayed')));
        outputs.push(sxbn.encode({type: 'replay-summary', records: inputs.length,
          outputs: inputs.length, incomplete_sessions: []}));
        return route.fulfill({body: Buffer.concat(outputs.map(item => Buffer.from(item))),
          contentType: 'application/octet-stream', headers: {'Access-Control-Allow-Origin': '*'}});
      }
      if (request.url().includes('/api/inspection/collections?')) {
        const matches = new URL(request.url()).searchParams.get('q') !== 'absent';
        body = {items: matches ? [{id: 'endpoint-test/123.json', endpoint: 'test',
          title: 'GET /needle', authority: 'www.example.test', side: 'L', bytes: 3,
          captured_at_ms: 123, protocols: ['HTTP/2'], content_types: ['application/json'],
          encodings: ['gzip'], operations: ['hpack.decode']}] : [], total: matches ? 1 : 0, all: 1, next: null};
      }
      if (request.url().includes('/api/inspection/sample?')) body = {
        format: 'spider-sample-v1', captured_at_ms: 123, collection: {endpoint: 'test'},
        event: {id: 'saved-sample', details: {info: {content: 'YWJj', side: 'L'}}},
        enrichments: [{metadata: {operation: 'test'}, content: 'eHl6'}],
        session_context: {test: true}};
      if (request.url().endsWith('/api/inspection/schema')) body = apiSchema;
      if (request.url().endsWith('/api/inspection/rules') && request.method() === 'POST') {
        state.traffic_rules = {...request.postDataJSON(), errors: []};
        body = state.traffic_rules;
      }
      if (request.url().endsWith('/api/inspection')) {
        if (request.method() === 'POST') {
          const data = request.postDataJSON(); writes.push(data);
          assert.equal(data.revision, state.revision);
          if (data.operation === 'deploy') {
            state.chain.push({id: 'script-1', name: data.name, script: data.script, enabled: false,
              version: 1, runs: 0, errors: 0, last_run_ms: null, scope: data.scope, filter: data.filter});
          } else if (data.operation === 'enable') state.chain[0].enabled = data.enabled;
          state.revision++;
        }
        body = state;
      }
      await route.fulfill({json: body, headers: {'Access-Control-Allow-Origin': '*'}});
    });
    page.on('dialog', dialog => dialog.accept());
    await page.goto('http://127.0.0.1:18763/');
    assert.equal(await page.locator('[data-activity-filter="sift"]').getAttribute('aria-pressed'), 'false');
    assert.equal(await page.evaluate(() => {
      activityRecords = []; activityUnread = 0;
      addActivity('system', 'TEST', 'visible');
      const unread = activityUnread;
      addActivity('sift', 'SIFT', 'hidden');
      return activityUnread === unread && byId('activity-summary').textContent === 'TEST: visible' &&
        !byId('activity-list').textContent.includes('hidden');
    }), true, 'Disabled SIFT must not affect the activity summary or unread count');
    const palette = await page.evaluate(() => {
      const fixture = document.createElement('div');
      fixture.hidden = true;
      fixture.innerHTML = '<div class="flow-follow-panel"><details class="flow-chunk"><summary>Payload</summary></details><span class="content-annotation h2-headers">Headers</span></div><div class="lane-card-head">Payload</div><span class="annotation-bytes h2-headers">Bytes</span>';
      document.body.append(fixture);
      const colors = selector => {
        const style = getComputedStyle(fixture.querySelector(selector));
        return [style.backgroundColor, style.color];
      };
      const result = {flow: colors('summary'), lane: colors('.lane-card-head'),
        rail: colors('.content-annotation'), bytes: colors('.annotation-bytes')};
      fixture.remove();
      return result;
    });
    assert.deepEqual(palette.flow, palette.lane);
    assert.deepEqual(palette.rail, palette.bytes);
    const sidebarWidth = await page.locator('#sidebar').evaluate(element => element.getBoundingClientRect().width);
    const workspaceWidth = await page.locator('.workspace').evaluate(element => element.getBoundingClientRect().width);
    await page.locator('#sidebar-toggle').click();
    assert.equal(await page.locator('#sidebar').isVisible(), false);
    assert.equal(await page.locator('#sidebar-toggle').getAttribute('aria-expanded'), 'false');
    assert((await page.locator('.workspace').evaluate(element => element.getBoundingClientRect().width)) > workspaceWidth + 200);
    await page.reload();
    assert.equal(await page.locator('#sidebar').isVisible(), false);
    await page.locator('#sidebar-toggle').focus();
    await page.keyboard.press('Enter');
    assert.equal(await page.locator('#sidebar').isVisible(), true);
    assert(Math.abs((await page.locator('#sidebar').evaluate(element => element.getBoundingClientRect().width)) - sidebarWidth) < 2);
    const sourceColumn = page.locator('#endpoint-columns > [data-dimension="src"]');
    const sourceBefore = (await sourceColumn.boundingBox()).width;
    const divider = page.locator('.endpoint-column-resizer[data-owner="src"]');
    const grip = await divider.boundingBox();
    await page.mouse.move(grip.x + grip.width / 2, grip.y + 12);
    await page.mouse.down();
    await page.mouse.move(grip.x + grip.width / 2 + 22, grip.y + 12);
    await page.mouse.up();
    const sourceAfter = (await sourceColumn.boundingBox()).width;
    assert(sourceAfter > sourceBefore + 15, JSON.stringify({sourceBefore, sourceAfter, grip, errors,
      layout: await page.locator('#endpoint-columns').evaluate(el => ({style: el.getAttribute('style'),
        grid: getComputedStyle(el).gridTemplateColumns, display: getComputedStyle(el).display,
        children: [...el.children].map(child => ({dimension: child.dataset.dimension, hidden: child.hidden}))}))}));
    await page.reload();
    assert(Math.abs((await sourceColumn.boundingBox()).width - sourceAfter) < 2);
    await divider.focus();
    await page.keyboard.press('ArrowLeft');
    assert((await sourceColumn.boundingBox()).width < sourceAfter - 8);
    await page.evaluate(() => {
      sessionGroupOrder = ['dport', 'src', 'dst'];
      sessionGroupsEnabled.delete('dst');
      renderEndpointBuilder();
    });
    assert.equal(await page.locator('.endpoint-column-resizer:visible').count(), 1);
    const ports = page.locator('#endpoint-columns > [data-dimension="dport"]');
    const portBefore = (await ports.boundingBox()).width;
    await page.locator('.endpoint-column-resizer[data-owner="dport"]').focus();
    await page.keyboard.press('ArrowRight');
    assert((await ports.boundingBox()).width > portBefore + 8);
    await page.evaluate(() => {
      sessionGroupOrder = ['src', 'dst', 'dport'];
      sessionGroupsEnabled.add('dst');
      renderEndpointBuilder();
    });
    await page.getByRole('button', {name: 'Inspection', exact: true}).click();
    await page.locator('#chain-connection').filter({hasText: 'enabled'}).waitFor();
    assert.equal(await page.locator('#workbench-tab .workbench-script').count(), 0);
    await page.locator('#library-new').click();
    await page.locator('#library-name').fill('GUI test');
    const editor = page.locator('.cm-content');
    await editor.fill('api.http1.');
    await editor.press('Control+Space');
    await page.locator('.cm-tooltip-autocomplete').waitFor();
    await page.getByRole('option').filter({hasText: 'available'}).click();
    assert.equal(await page.locator('#script-editor').inputValue(), 'api.http1.available');
    await editor.fill('api.http1.headers[0].');
    await editor.press('Control+Space');
    await page.getByRole('option').filter({hasText: 'name'}).click();
    assert.equal(await page.locator('#script-editor').inputValue(), 'api.http1.headers[0].name');
    await editor.fill('# api.http1.');
    await editor.press('Control+Space');
    assert.equal(await page.locator('.cm-tooltip-autocomplete').count(), 0);
    await editor.fill('if True:');
    await editor.press('End');
    await editor.press('Enter');
    await editor.pressSequentially('return None');
    assert.equal(await page.locator('#script-editor').inputValue(), 'if True:\n    return None');
    assert(await page.locator('.cm-lineNumbers').count());
    await editor.fill('return api.bytes.upper()');
    assert.equal(await page.locator('#library-deploy').isDisabled(), true);
    await page.locator('#library-save').click();
    assert.equal(writes.length, 0); // Save is never Deploy.
    await page.locator('#library-deploy').click();
    await page.locator('#chain-list').filter({hasText: 'GUI test'}).waitFor();
    assert.equal(writes[0].operation, 'deploy');
    assert.equal(state.chain[0].enabled, false);
    await page.getByRole('button', {name: 'Enable', exact: true}).click();
    await page.getByRole('button', {name: 'Disable', exact: true}).waitFor();
    await editor.fill('return None');
    assert.equal(state.chain[0].script, 'return api.bytes.upper()');
    await page.locator('#library-list').getByRole('button', {name: 'Script 1', exact: true}).click();
    assert.match(await editor.innerText(), /api\.print/);
    await page.locator('#library-list').getByRole('button', {name: 'GUI test', exact: true}).click();
    assert.equal(await editor.innerText(), 'return None');
    await page.getByRole('button', {name: 'API Reference', exact: true}).click();
    await page.locator('#api-reference-content details').first().locator('summary').click();
    await page.getByRole('button', {name: 'Insert example into editor'}).first().click();
    assert.match(await editor.innerText(), /api\.print/);
    await editor.fill('return None');
    await page.evaluate(() => {
      trafficRules = [{id: 'address:192.0.2.2', kind: 'address', value: '192.0.2.2', mode: 'focus'}];
      observedDestinations.set('192.0.2.2', {count: 1, lastSeenAt: Date.now()});
      renderEndpointBuilder();
    });
    await page.locator('#observed-destinations .endpoint-choice').first().click({button: 'right'});
    await page.getByRole('button', {name: '▣ Toggle Collection'}).click();
    await page.locator('#observed-destinations .collection-badge').waitFor();
    assert(state.traffic_rules.rules.some(rule => rule.mode === 'focus'));
    assert(state.traffic_rules.rules.some(rule => rule.mode === 'collect'));
    assert.equal(await page.locator('#observed-destinations .endpoint-choice').first().getAttribute('data-rule-mode'), 'focus');
    await page.screenshot({path: '/tmp/spider-inspection-workspace.png', fullPage: true});
    const spliceChecks = await page.evaluate(() => {
      const encode = text => new TextEncoder().encode(text);
      const wire = encode('HEADzipFRAMEzapTAIL');
      const item = {metadata: {operation: 'gzip.inflate', content_type: 'text/plain',
        source: {ranges: [[4, 7], [12, 15]], decoded_ranges: [[0, 18], [18, 21]]}},
        payload: encode('abcdefghijklmnopqrXYZ')};
      const record = {binaryPayload: wire, event: {id: 'splice-check',
        details: {info: {side: 'R', L7_payload_start: [4, 12],
          L7_payload_end: [7, 15], content_annotations: [[0, 4, 'h2.headers']]}}},
        enrichments: [item]};
      const oldScope = payloadScope;
      payloadScope = 'wire';
      const selected = flowPayloadSource(record, [record], {}, wire);
      const pre = document.createElement('pre');
      renderProjectedPayload(pre, selected.bytes, selected.derived, record, 'hex', true);
      const offsets = [...pre.querySelectorAll('.inflated-offset')].map(node => node.textContent.trim());
      const text = new TextDecoder().decode(selected.bytes);
      const untouched = [...pre.querySelectorAll('.h2-headers')].map(node => node.textContent).join('');
      const original = flowPayloadSource(record, [record],
        {originalPayloads: new Set([String(record.revision)])}, wire).bytes;
      payloadScope = 'l7';
      const l7 = new TextDecoder().decode(flowPayloadSource(record, [record], {}, wire).bytes);
      payloadScope = oldScope;
      const invalid = {...item, metadata: {...item.metadata, source: {ranges: [[4, 7], [12, 15]]}}};
      return {text, l7, offsets, untouched,
        original: new TextDecoder().decode(original), ambiguous: inflateEdits(invalid, wire.length)};
    });
    assert.equal(spliceChecks.text, 'HEADabcdefghijklmnopqrFRAMEXYZTAIL');
    assert.equal(spliceChecks.original, 'HEADzipFRAMEzapTAIL');
    assert.equal(spliceChecks.l7, 'abcdefghijklmnopqrXYZ');
    assert.deepEqual(spliceChecks.offsets, ['00000010', '00000020']);
    assert.match(spliceChecks.untouched, /HEAD/);
    assert.equal(spliceChecks.ambiguous, null);
    await page.evaluate(() => {
      const wire = new Uint8Array([31, 139, 8, 0]);
      payloadRecords.push({revision: 9901, binaryPayload: wire, cacheBytes: 100,
        event: {id: 'decoded-test', action: 'connection-content',
          details: {info: {side: 'R', session: 'tcp_192.0.2.1:1234+tcp_192.0.2.2:80',
            content_annotations: [[0, 1, 'h2.headers'], [1, 4, 'h2.data']]}}},
        enrichments: [{metadata: {operation: 'gzip.inflate', content_type: 'text/plain',
          source: {ranges: [[0, 4]]}},
          payload: new TextEncoder().encode('Decoded hello world')}]});
      payloadMode = 'ascii';
      openFlowTab('decoded-test');
    });
    const flow = page.locator('.flow-follow-panel:not([hidden])');
    await flow.locator('.flow-chunk > summary > small').click();
    assert.equal(await flow.locator('.flow-chunk').getAttribute('open'), '');
    await flow.locator('.flow-chunk > summary > .payload-fold').click();
    assert.equal(await flow.locator('.flow-chunk').getAttribute('open'), null);
    await flow.locator('.flow-chunk > summary > .payload-fold').press('Enter');
    assert.equal(await flow.locator('.flow-chunk').getAttribute('open'), '');
    assert.equal(await flow.locator('.content-annotation.h2-headers').count(), 1);
    assert.match(await flow.locator('.flow-chunk > pre').innerText(), /Decoded hello world/);
    assert.equal(await flow.locator('.derived-payload').count(), 1);
    await flow.locator('.enrichment-marker').click();
    assert.equal(await flow.locator('.derived-payload').count(), 0);
    assert.doesNotMatch(await flow.locator('.flow-chunk > pre').innerText(), /Decoded hello world/);
    await flow.locator('.enrichment-marker').click();
    await page.evaluate(() => setPayloadMode('hex'));
    assert.match(await flow.locator('.flow-chunk > pre').innerText(), /44 65 63 6f 64 65 64/);
    for (const view of ['stream', 'lanes']) {
      await flow.locator(`[data-flow-view="${view}"]`).click();
      assert.equal(await flow.locator('.derived-payload').count(), 1, view + ': ' + JSON.stringify(errors));
      assert.deepEqual(await flow.locator('.derived-payload').evaluate(card => {
        const body = card.querySelector('.annotation-bytes.inflated');
        const style = getComputedStyle(body);
        return {color: style.color, shadow: style.boxShadow};
      }), {color: 'rgb(189, 210, 197)', shadow: 'none'});
      assert.match(await flow.locator('.derived-payload pre').first().innerText(), /Decoded hello world/);
      await flow.locator('.enrichment-marker').click();
      assert.equal(await flow.locator('.derived-payload').count(), 0);
      await flow.locator('.enrichment-marker').click();
    }
    await page.screenshot({path: '/tmp/spider-decoded-payload.png', fullPage: true});
    await flow.locator('[data-flow-view="stream"]').click();
    const badgeFits = await flow.locator('.flow-stream-chunk > small').evaluate(el => {
      const box = el.getBoundingClientRect();
      return [...el.querySelectorAll('.enrichment-marker, .l7-marker')].every(badge =>
        badge.getBoundingClientRect().right <= box.right + 1);
    });
    assert(badgeFits, 'Stream badges must stay inside their metadata column');
    await page.evaluate(() => {
      payloadRecords.find(record => record.event.id === 'decoded-test').enrichments.unshift({
        metadata: {operation: 'hpack.decode', headers: [{name: ':status', value: '200'}]},
        payload: new Uint8Array(),
      });
      followedFlows.get('connection:decoded-test').renderedMode = null;
      renderFlowTab('connection:decoded-test');
    });
    for (const view of ['chunks', 'stream', 'lanes']) {
      await flow.locator(`[data-flow-view="${view}"]`).click();
      const headerBadge = flow.locator('.enrichment-marker').filter({hasText: 'H2 headers'});
      const bodyBadge = flow.locator('.enrichment-marker').filter({hasText: 'gzip decoded'});
      assert.equal(await headerBadge.count(), 1);
      assert.equal(await bodyBadge.count(), 1);
      if (view === 'chunks') {
        assert.equal(await headerBadge.getAttribute('aria-pressed'), 'false');
        assert.equal(await flow.locator('.inline-enrichments').isVisible(), false);
      }
      if (await headerBadge.getAttribute('aria-pressed') !== 'true') await headerBadge.click();
      assert.equal(await flow.locator('.content-annotation.h2-headers').count(), 1);
      assert.match(await flow.locator('.inline-enrichment-card > summary').innerText(), /H2 headers \(hpack.decode\)/);
      await flow.locator('.inline-enrichment-card > summary > b').click();
      assert.equal(await flow.locator('.inline-enrichment-card').getAttribute('open'), '');
      assert.match(await flow.locator('.inline-enrichments').innerText(), /:status.*200/s);
      assert.equal(await flow.locator('.inline-enrichment-card').count(), 1);
      assert.equal(await flow.locator('.derived-payload').evaluate(card => {
        const headers = card.querySelector('.inline-enrichments');
        const body = card.querySelector(':scope > .flow-payload-content, :scope > pre');
        const bounds = card.getBoundingClientRect();
        const bodyBounds = body.getBoundingClientRect();
        return Boolean(headers.compareDocumentPosition(body) & Node.DOCUMENT_POSITION_FOLLOWING) &&
          bodyBounds.left >= bounds.left && bodyBounds.right <= bounds.right;
      }), true, view + ': headers must precede body, which must fit inside its parent');
      await bodyBadge.click();
      assert.equal(await flow.locator('.derived-payload').count(), 0);
      assert.equal(await flow.locator('.inline-enrichments').isVisible(), true);
      await bodyBadge.click();
      assert.equal(await flow.locator('.derived-payload').count(), 1);
      assert.equal(await flow.locator('.inline-enrichments').isVisible(), true);
    }
    await flow.locator('[data-flow-view="stream"]').click();
    assert.equal(await page.evaluate(() => {
      const record = payloadRecords.find(record => record.event.id === 'decoded-test');
      record.enrichments.reverse();
      const followed = followedFlows.get('connection:decoded-test');
      followed.renderedMode = null;
      renderFlowTab(followed.key);
      const card = document.querySelector('.flow-stream-chunk.derived-payload');
      return Boolean(card.querySelector('.flow-payload-content').compareDocumentPosition(
        card.querySelector('.inline-enrichments')) & Node.DOCUMENT_POSITION_FOLLOWING);
    }), true, 'Reversed enrichment input must preserve its original order too');
    assert.equal(await page.evaluate(() => {
      endpointAggregates = [{id: 'hostname-glob:*.example.test', kind: 'hostname-glob', value: '*.example.test'}];
      const rules = restoreTrafficRules([{id: 'hostname-glob:*.example.test@192.0.2.2',
        kind: 'address', value: '192.0.2.2', mode: 'focus', matches: 4}]);
      trafficRules = rules;
      renderEndpointBuilder();
      return document.querySelector('#observed-destinations .aggregate').dataset.ruleMode;
    }), 'focus');
    await page.evaluate(() => {
      openFlowTab('decoded-test', 'service');
      openFlowTab('decoded-test', 'client');
      showTab(followedFlows.get('connection:decoded-test').id);
    });
    await page.reload();
    assert.equal(await page.locator('.flow-tab-button').count(), 3);
    assert.equal(await page.evaluate(() => followedFlows.get('connection:decoded-test').view), 'stream');
    assert.equal(await page.evaluate(() => activeTab === followedFlows.get('connection:decoded-test').id), true);
    assert.equal(await page.evaluate(() => [...followedFlows.values()].find(f => f.type === 'service').destinationHost), '192.0.2.2');
    await page.evaluate(() => closeFlowTab('connection:decoded-test'));
    await page.reload();
    assert.equal(await page.locator('.flow-tab-button').count(), 2);
    assert.equal(await page.locator('#frontend-version').innerText(), 'UI aaaaaaaaaaaa');
    frontendVersion = 'bbbbbbbbbbbb';
    await page.locator('#frontend-version').click();
    await page.locator('#frontend-version.update-available').waitFor();
    assert.match(await page.locator('#frontend-version').innerText(), /UI aaaaaaaaaaaa.*Update available/);
    page.removeAllListeners('dialog');
    page.once('dialog', dialog => dialog.dismiss());
    await page.locator('#frontend-version').click();
    assert.equal(await page.locator('meta[name="frontend-version"]').getAttribute('content'), 'aaaaaaaaaaaa');
    await page.evaluate(() => {
      payloadRecords.push({revision: 9999, binaryPayload: new Uint8Array([1, 2, 3, 4]),
        event: {id: 'large-inflate', details: {info: {side: 'R'}}},
        enrichments: [
          {metadata: {operation: 'hpack.decode', headers: [{name: ':status', value: '200'}]}, payload: new Uint8Array()},
          {metadata: {operation: 'gzip.inflate', content_type: 'text/plain', source: {ranges: [[0, 4]]}},
            payload: new Uint8Array(1024 * 1024).fill(65)},
        ]});
      payloadMode = 'hex'; payloadScope = 'wire';
      openFlowTab('large-inflate');
    });
    const large = page.locator('.flow-follow-panel:not([hidden])');
    assert(await large.locator('.flow-chunk > pre *').count() < 2000);
    await large.locator('.enrichment-marker').filter({hasText: 'H2 headers'}).click();
    assert.match(await large.locator('.inline-enrichments').innerText(), /:status.*200/s);
    assert.match(await large.locator('.payload-preview-more').innerText(), /4.*KiB/);
    await large.locator('.payload-preview-more').click();
    assert.match(await large.locator('.payload-preview-more').innerText(), /8.*KiB/);
    await page.evaluate(() => {
      payloadRecords.find(record => record.event.id === 'large-inflate').event.details.info.side = 'L';
    });
    await large.locator('[data-flow-view="lanes"]').click();
    await large.locator('.lane-card-expand').click();
    assert.equal(await large.locator('.lane-card > pre').evaluate(pre => {
      const before = pre.closest('.lane-board').querySelector('.lane-pending');
      renderFlowTab('connection:large-inflate');
      const sameBadge = before === pre.closest('.lane-board').querySelector('.lane-pending');
      pre.style.height = '80px';
      pre.scrollTop = 50;
      const style = getComputedStyle(pre);
      return sameBadge && pre.scrollTop > 0 && style.overflowY === 'auto' && style.resize === 'both';
    }), true, 'Lanes must keep badges stable and permit independent scrolling/resizing');
    const lanePreview = large.locator('.lane-card > pre');
    const box = await lanePreview.boundingBox();
    await page.mouse.move(box.x + box.width - 3, box.y + box.height - 3);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width - 3, box.y + box.height + 77, {steps: 5});
    await page.mouse.up();
    assert((await lanePreview.boundingBox()).height > box.height + 30, 'Corner drag must resize payload');
    await large.locator('[data-flow-collect]').click();
    assert(state.traffic_rules.rules.some(r => r.kind === 'session' && r.value === 'large-inflate' && r.mode === 'collect'));
    await large.locator('[data-flow-collect]').click();
    assert(!state.traffic_rules.rules.some(r => r.value === 'large-inflate'));
    await page.waitForFunction(() => !followedFlows.get('connection:large-inflate').replayPending);
    replayTest = true;
    await large.locator('[data-flow-replay]').click();
    await page.waitForFunction(() => !followedFlows.get('connection:large-inflate').replayPending);
    await large.locator('[data-flow-replay]').click();
    await page.waitForFunction(() => !followedFlows.get('connection:large-inflate').replayPending);
    assert.equal(await page.evaluate(() => payloadRecords.find(r => r.event.id === 'large-inflate')
      .enrichments.filter(e => e.metadata.operation === 'test.replay').length), 1, 'Replay merges without duplicate enrichments');
    await page.evaluate(() => showTab('inspection-tab'));
    await page.locator('#inspection-select-input').click();
    assert((await page.locator('.sample-picker [data-list]').textContent()).includes('GET /needle'));
    assert((await page.locator('.sample-picker [data-list]').textContent()).includes('application/json'));
    await page.screenshot({path: '/tmp/spider-sample-catalog.png'});
    await page.locator('.sample-picker [data-search]').fill('absent');
    await page.locator('.sample-picker [data-find]').click();
    await page.waitForFunction(() => document.querySelector('.sample-picker [data-status]').textContent.startsWith('0 / 1'));
    assert.equal(await page.locator('.sample-picker [data-list] button').count(), 0);
    await page.locator('.sample-picker [data-search]').fill('needle');
    await page.locator('.sample-picker [data-search]').press('Enter');
    await page.locator('.sample-picker [data-list] button').click();
    assert(!(await page.locator('.sample-picker [data-preview]').textContent()).includes('YWJj'));
    await page.locator('.sample-picker [data-use]').click();
    assert.equal(await page.evaluate(() => selectedPayload.event.id), 'saved-sample');
    assert.equal(await page.evaluate(() => new TextDecoder().decode(selectedPayload.enrichments[0].payload)), 'xyz');
    assert.equal(await page.locator('#accept-payload').isDisabled(), true);
    await page.locator('#inspection-select-input').click();
    await page.locator('.sample-picker [data-list] button').click();
    await page.locator('.sample-picker [data-follow]').click();
    await page.waitForFunction(() => followedFlows.get('saved:sample:endpoint-test/123.json')?.savedRecords?.length === 1);
    assert.deepEqual(await page.evaluate(() => {
      const flow = followedFlows.get('saved:sample:endpoint-test/123.json');
      const record = flow.savedRecords[0];
      return [new TextDecoder().decode(recordPayloadBytes(record)),
        new TextDecoder().decode(record.enrichments[0].payload), record.replayContextComplete,
        byId(flow.id).querySelector('[data-flow-collect]').hidden];
    }), ['abc', 'xyz', false, true]);
    page.on('dialog', dialog => dialog.type() === 'prompt' ? dialog.accept('Saved investigation') : dialog.accept());
    await page.evaluate(() => showTab(followedFlows.get('connection:large-inflate').id));
    await large.locator('[data-save-flow]').click();
    await page.waitForFunction(() => followedFlows.get('saved:saved-test')?.savedRecords?.length > 0);
    await page.waitForFunction(() => followedFlows.get('saved:sample:endpoint-test/123.json')?.savedRecords?.length === 1);
    assert.equal(savedFlow.name, 'Saved investigation');
    assert(savedFlow.records[0].enrichments.length > 0);
    const savedBytes = await page.evaluate(() => recordPayloadBytes(followedFlows.get('saved:saved-test').savedRecords[0]).length);
    await page.reload();
    await page.waitForFunction(() => followedFlows.get('saved:saved-test')?.savedRecords?.length > 0);
    await page.waitForFunction(() => followedFlows.get('saved:sample:endpoint-test/123.json')?.savedRecords?.length === 1);
    assert.equal(await page.evaluate(() => followedFlows.get('saved:saved-test').title), 'Saved investigation');
    assert.equal(await page.evaluate(() => recordPayloadBytes(followedFlows.get('saved:saved-test').savedRecords[0]).length), savedBytes);
    assert.equal(await page.evaluate(() => payloadRecords.length), 0, 'Saved snapshot must not enter live cache');
    assert.equal(await page.evaluate(() => byId(followedFlows.get('saved:saved-test').id)
      .querySelector('.flow-follow-head h2').textContent), 'Saved investigation');
    await page.evaluate(() => {
      closeFlowTab('saved:saved-test');
      showTab('workbench-tab');
    });
    await page.locator('#open-saved-sessions').click();
    await page.locator('.sample-picker [data-list] button').click();
    await page.waitForFunction(() => followedFlows.get('saved:saved-test')?.savedRecords?.length > 0);
    const idleRendering = await page.evaluate(async () => {
      const original = renderFlowTab;
      let calls = 0;
      renderFlowTab = (...args) => { calls++; return original(...args); };
      const tick = () => new Promise(resolve => requestAnimationFrame(resolve));
      try {
        await tick(); calls = 0;
        for (let i = 0; i < 5; i++) { scheduleRender(true, true); await tick(); }
        const saved = calls;
        const live = [...followedFlows.values()].find(flow => !flow.savedId);
        showTab(live.id);
        scheduleRender(true, true); await tick(); calls = 0;
        for (let i = 0; i < 5; i++) { scheduleRender(true, true); await tick(); }
        const unchanged = calls;
        Object.defineProperty(document, 'hidden', {configurable: true, value: true});
        scheduleRender(true, true);
        const hiddenScheduled = renderFrame !== null;
        original(live.key);
        const deferred = live.renderDeferred;
        delete document.hidden;
        document.dispatchEvent(new Event('visibilitychange'));
        await tick();
        return {saved, unchanged, hiddenScheduled, deferred, resumed: !live.renderDeferred};
      } finally { delete document.hidden; renderFlowTab = original; }
    });
    assert.deepEqual(idleRendering, {saved: 0, unchanged: 0, hiddenScheduled: false, deferred: true, resumed: true});
    assert.deepEqual(errors, []);
    console.log('Inspection GUI smoke test passed: library/save/deploy/enable/draft separation.');
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});

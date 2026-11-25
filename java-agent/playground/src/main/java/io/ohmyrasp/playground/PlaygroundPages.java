package io.ohmyrasp.playground;

/** HTML views for the playground and its block page. */
final class PlaygroundPages {
  private PlaygroundPages() {}

  static String renderBlocked(String hook, String algorithm, String message) {
    return """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>OhMyRasp Intercepted</title>
          <style>
            body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#111827;color:#f9fafb}
            main{max-width:860px;margin:0 auto;padding:48px 24px}
            .panel{border:1px solid #374151;background:#1f2937;border-radius:8px;padding:24px}
            h1{margin:0 0 12px;font-size:28px;letter-spacing:0}
            dl{display:grid;grid-template-columns:120px 1fr;gap:10px 16px;margin:24px 0 0}
            dt{color:#9ca3af}dd{margin:0;overflow-wrap:anywhere}
            a{color:#93c5fd}
          </style>
        </head>
        <body>
          <main>
            <section class="panel">
              <h1>Request intercepted</h1>
              <p>OhMyRasp redirected this request after a detector matched.</p>
              <dl>
                <dt>Hook</dt><dd>%s</dd>
                <dt>Algorithm</dt><dd>%s</dd>
                <dt>Message</dt><dd>%s</dd>
              </dl>
              <p><a href="/rasp/ui">Back to testbed</a></p>
            </section>
          </main>
        </body>
        </html>
        """
        .formatted(
            html(hook),
            html(algorithm),
            html(message));
  }

  static String renderUi(String cases, String environments) {
    return """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>OhMyRasp Testbed</title>
          <style>
            :root{color-scheme:light;--ink:#172033;--muted:#5d667a;--line:#d8dde8;--bg:#f5f7fb;--panel:#fff;--base:#2563eb;--prot:#b42318;--accent:#6d28d9}
            *{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:var(--bg);color:var(--ink)}
            header{background:#0f172a;color:#fff;padding:18px 24px;border-bottom:4px solid #2dd4bf}
            header h1{margin:0;font-size:24px;letter-spacing:0}header p{margin:6px 0 0;color:#cbd5e1}
            main{padding:18px 24px;max-width:1440px;margin:0 auto}
            .toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:16px}
            .toolbar code,.toolbar select{background:#e8edf6;border:1px solid var(--line);border-radius:6px;padding:7px 9px}
            .grid{display:grid;grid-template-columns:minmax(520px,1.1fr) minmax(420px,.9fr);gap:16px}
            table{width:100%%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
            th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:middle;font-size:14px}
            th{background:#eef2f8;color:#334155;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
            tr:last-child td{border-bottom:0}.category{color:var(--muted);font-size:12px}
            button{border:1px solid transparent;border-radius:6px;padding:8px 10px;color:#fff;cursor:pointer;min-width:96px}
            button.base{background:var(--base)}button.protected{background:var(--prot)}button.all{background:#0f766e}button.env{background:var(--accent)}
            button:disabled{opacity:.5;cursor:wait}
            .labs{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:0 0 16px}
            .lab{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
            .lab h2{font-size:15px;margin:0 0 6px}.lab p{font-size:13px;color:var(--muted);margin:0 0 8px}.lab code{font-size:12px}
            .result{background:var(--panel);border:1px solid var(--line);border-radius:8px;min-height:520px;padding:14px}
            .result h2{margin:0 0 12px;font-size:18px}.entry{border-top:1px solid var(--line);padding:10px 0}
            .entry:first-of-type{border-top:0}.tag{display:inline-block;border-radius:999px;padding:2px 8px;font-size:12px;color:#fff}
            .tag.baseline{background:var(--base)}.tag.protected{background:var(--prot)}
            pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1220;color:#d1e7ff;border-radius:6px;padding:10px;max-height:160px;overflow:auto}
            @media(max-width:980px){.grid{grid-template-columns:1fr}main{padding:14px}th:nth-child(2),td:nth-child(2){display:none}}
          </style>
        </head>
        <body>
          <header>
            <h1>OhMyRasp Comparative Testbed</h1>
            <p>Tomcat 9, 10, and 11 run as paired baseline and protected environments.</p>
          </header>
          <main>
            <div class="toolbar">
              <select id="environmentSelect"></select>
              <code id="environmentUrl"></code>
              <button class="env" id="runSelected">Run selected environment</button>
              <button class="base" id="runBaselines">Run all baselines</button>
              <button class="all" id="runProtected">Run all protected</button>
            </div>
            <section class="labs" id="labs"></section>
            <div class="grid">
              <table>
                <thead><tr><th>Case</th><th>Endpoint</th><th>Run</th></tr></thead>
                <tbody id="cases"></tbody>
              </table>
              <section class="result">
                <h2>Results</h2>
                <div id="results"></div>
              </section>
            </div>
          </main>
          <script>
            const cases = %s;
            const environments = %s;
            const labCatalog = %s;
            const host = location.hostname || 'localhost';
            for (const env of environments) {
              env.base = `${location.protocol}//${host}:${env.port}`;
              const option = document.createElement('option');
              option.value = env.id;
              option.textContent = env.label;
              environmentSelect.appendChild(option);
            }
            function selectedEnvironment() {
              return environments.find(env => env.id === environmentSelect.value) || environments[0];
            }
            function updateEnvironmentUrl() {
              const env = selectedEnvironment();
              environmentUrl.textContent = `${env.kind}: ${env.base}`;
            }
            environmentSelect.onchange = updateEnvironmentUrl;
            updateEnvironmentUrl();
            const labsContainer = document.getElementById('labs');
            for (const group of labCatalog.groups || []) {
              const article = document.createElement('article');
              article.className = 'lab';
              article.innerHTML = `<h2>${escapeHtml(group.label)}</h2><p>${escapeHtml((group.mechanics || []).join(' / '))}</p><code>${(group.labs || []).map(lab => escapeHtml(lab.name)).join(', ')}</code>`;
              labsContainer.appendChild(article);
            }
            const tbody = document.getElementById('cases');
            for (const item of cases) {
              const tr = document.createElement('tr');
              tr.innerHTML = `<td><strong>${item.name}</strong><div class="category">${item.category}</div></td><td><code>${item.path}</code></td><td><button class="env">Run selected</button></td>`;
              tr.querySelector('.env').onclick = () => runCase(item, selectedEnvironment());
              tbody.appendChild(tr);
            }
            runSelected.onclick = () => runSet([selectedEnvironment()], runSelected);
            runBaselines.onclick = () => runSet(environments.filter(env => env.kind === 'baseline'), runBaselines);
            runProtected.onclick = () => runSet(environments.filter(env => env.kind === 'protected'), runProtected);
            async function runSet(selected, button) {
              button.disabled = true;
              for (const env of selected) {
                for (const item of cases) await runCase(item, env);
              }
              button.disabled = false;
            }
            async function runCase(item, env) {
              const started = performance.now();
              let status = 'error', finalUrl = '', body = '';
              try {
                const response = await fetch(env.base + item.path, {redirect:'follow'});
                status = String(response.status);
                finalUrl = response.url;
                body = await response.text();
              } catch (error) {
                body = String(error);
              }
              const elapsed = Math.round(performance.now() - started);
              const entry = document.createElement('div');
              entry.className = 'entry';
              entry.innerHTML = `<span class="tag ${env.kind}">${env.label}</span> <strong>${item.name}</strong> <span>${status} / ${elapsed}ms</span><div><small>${finalUrl}</small></div><pre>${escapeHtml(body.slice(0, 1200))}</pre>`;
              results.prepend(entry);
            }
            function escapeHtml(value) {
              return value.replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
            }
          </script>
        </body>
        </html>
        """
        .formatted(cases, environments, LabCatalog.json());
  }

  private static String html(String value) {
    return value == null
        ? ""
        : value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
  }
}

# OhMyRASP False-Positive Report

> **Generated** by `scripts/fp-harness/FpReport.java` against the real `DetectorEngine`.
> Re-run via `scripts/run-fp-report.sh` after changing detectors.

## Method

A curated corpus of **169** benign-but-plausible inputs across **22** detector categories is run through the engine. Each input is presented with a realistic request context; where a value would be user-supplied it is placed in a request parameter so taint-aware detectors evaluate it as in production. A *false positive* is any detector returning a detection for legitimate input. This is a detector-precision probe on benign traffic, **not** a production-traffic false-positive rate.

## Result

| Category | Benign inputs | False positives | FP rate |
|----------|--------------:|----------------:|--------:|
| Internationalized report routes | 6 | 0 | 0.0% |
| Report field metadata | 2 | 0 | 0.0% |
| SQL queries | 27 | 0 | 0.0% |
| OS commands | 12 | 0 | 0.0% |
| Process dispatch | 4 | 0 | 0.0% |
| Outbound URLs | 23 | 0 | 0.0% |
| File reads | 15 | 0 | 0.0% |
| Directory listings | 4 | 0 | 0.0% |
| Temporary report output | 3 | 0 | 0.0% |
| File writes | 6 | 0 | 0.0% |
| File deletes | 4 | 0 | 0.0% |
| Archive writes | 5 | 0 | 0.0% |
| Deserialization classes | 9 | 0 | 0.0% |
| Expressions | 5 | 0 | 0.0% |
| OGNL expressions | 7 | 0 | 0.0% |
| JNDI names | 3 | 0 | 0.0% |
| DNS lookups | 6 | 0 | 0.0% |
| Ordinary deployment uploads | 3 | 0 | 0.0% |
| Upload filenames | 6 | 0 | 0.0% |
| JDBC URLs | 5 | 0 | 0.0% |
| Request parameters | 6 | 0 | 0.0% |
| Base64 decoding | 8 | 0 | 0.0% |
| **Overall** | **169** | **0** | **0.0%** |

No false positives observed across the corpus.

## Corpus

<details><summary>All benign inputs tested</summary>

**Internationalized report routes**

- `/admin/reports/資料`
- `/admin/reports/%E6%9D%B1%E4%BA%AC`
- `/admin/reports/%C5%81%C3%B3d%C5%BA`
- `/admin/reports/%F0%9F%93%8A`
- `/admin/reports/%25E6%259D%25B1`
- `/admin/reports/%31%32-%F0%9F%93%8A.csv`

**Report field metadata**

- `{"orders":[{"type":"# report heading"}]}`
- `{"table":"reports","column":"Select title"}`

**SQL queries**

- `select * from notes where title = 'union select'` (user input: `union select`)
- `select * from notes where label = 'build--release'` (user input: `build--release`)
- `insert into audit(message) values ('user''s sleep(5) example')`
- `/* mapped query */ select id from orders where id = 42` (user input: `42`)
- `select 'SQLJ.INSTALL_JAR( documentation' as excerpt`
- `/* CREATE ALIAS using ProcessBuilder is documented separately */ select 7`
- `select 'RUNSCRIPT FROM https://docs.invalid/manual' as excerpt`
- `select 'catalog'; select 2` (user input: `catalog`)
- `select id from orders where state = 'paid' -- billing report` (user input: `paid`)
- `select id from catalog -- describes information_schema in the manual`
- `select table_name from information_schema.tables`
- `select id from orders where id = 42 union select id from returns` (user input: `42`)
- `select id from invoices union /* archived */ all select id from archived_invo...`
- `select 'union select' as title union select description from articles` (user input: `union select`)
- `select id from orders where state='OPEN' and 1=1` (user input: `OPEN`)
- `select id from orders where state='OPEN' or 1=0` (user input: `OPEN`)
- `select id from orders where state='PAID' or 1=1.5` (user input: `PAID`)
- `select id, name from users where status = 'active'`
- `select * from orders where customer = 'O''Brien'` (user input: `O'Brien`)
- `select * from products where price between 100 and 200`
- `update sessions set last_seen = now() where id = 42` (user input: `42`)
- `select * from logs where message like '%timeout%'` (user input: `timeout`)
- `select email from users where id = 1001` (user input: `1001`)
- `insert into audit(action, actor) values('login', 'alice')` (user input: `alice`)
- `select * from catalog where title = 'The Lord of the Rings'` (user input: `The Lord of the Rings`)
- `select count(*) from orders where created_at > now() - interval '1 day'`
- `select * from cities where name = 'Côte d''Or'` (user input: `Côte d'Or`)

**OS commands**

- `printf %s O'Brien` (user input: `O'Brien`)
- `printf %s R&D` (user input: `R&D`)
- `printf %s Q1;Q2` (user input: `Q1;Q2`)
- `printf %s June|July` (user input: `June|July`)
- `git status`
- `/usr/bin/convert input.png output.jpg`
- `ffmpeg -i input.mp4 -vcodec copy output.mp4`
- `ls -la /var/app/data`
- `python3 /opt/app/report.py --month 2026-05` (user input: `2026-05`)
- `tar czf backup.tgz /var/app/uploads`
- `node /srv/app/index.js`
- `/usr/bin/pdftoppm -png /tmp/in.pdf /tmp/out`

**Process dispatch**

- `java.lang.reflect.Method`
- `example.spelling.MonthlyReport`
- `example.javascriptnotes.Catalog`
- `example.velocitymetrics.Recorder`

**Outbound URLs**

- `https://orders.example.test/api/orders/4981` (user input: `4981`)
- `https://search.example.test/?q=invoice` (user input: `invoice`)
- `http://10.2.3.4/actuator/health`
- `http://127.0.0.1/ready`
- `http://169.254.169.253/status`
- `http://[fe80::a%25FloorA]/report` (user input: `http://[fe80::a%25floora]/report`)
- `http://127.0.0.1/admin/reports`
- `http://10.0.0.5/admin/report-10` (user input: `10`)
- `https://reports.example.test/weekly` (user input: `https://reports.example.test/weekly`)
- `https://169.254.169.254.docs.example.test/reference`
- `https://docs.example.test/latest/meta-data/guide`
- `https://0xdocs.example.test/reference`
- `https://notdnslog.cn/status`
- `https://images.example.test/preview?src=https://cdn.example.test/image` (user input: `https://cdn.example.test/image`)
- `file:/srv/orders/lib/compiler.jar`
- `file:/opt/orders/WEB-INF/templates.xml`
- `file:/srv/orders/reports/4981.json` (user input: `4981`)
- `https://api.stripe.com/v1/charges`
- `https://hooks.slack.com/services/T000/B000/abcdef`
- `https://www.googleapis.com/oauth2/v3/certs`
- `https://cdn.example.com/assets/logo.png`
- `https://payments.partner.example.com/api/charge`
- `https://graph.microsoft.com/v1.0/me`

**File reads**

- `/etc/ssl/certs/ca-certificates.crt`
- `/proc/self/status`
- `/srv/reports/snapshot/etc/passwd`
- `/etc/hosts` (user input: `hosts`)
- `/srv/orders/4981.json` (user input: `4981`)
- `/srv/orders/4981.json` (user input: `/srv/orders/4981.json`)
- `/srv/reports/annual.csv` (user input: `/srv/reports/annual.csv`)
- `/srv/catalog/index` (user input: `/srv/catalog/index`)
- `/srv/reports/annual.csv` (user input: `annual.csv`)
- `/srv/images/drafts/../thumb.png` (user input: `drafts/../thumb.png`)
- `/var/app/uploads/photo.jpg`
- `/opt/app/config/application.yml`
- `/srv/data/reports/2026-05.csv`
- `/home/appuser/.config/app/settings.json`
- `/var/app/templates/invoice.html`

**Directory listings**

- `/srv/orders/exports` (user input: `orders`)
- `/srv/reports/catalog` (user input: `/srv/reports/catalog`)
- `/etc`
- `/proc`

**Temporary report output**

- `{"api":"Runtime.exec(String)","report":"weekly"}` (user input: `weekly`)
- `{"label":"Runtime.exec(String)"}` (user input: `Runtime.exec(String)`)
- `# reference: system("printf weekly")` (user input: `system("printf weekly")`)

**File writes**

- `/var/app/uploads/avatar-1001.png`
- `/tmp/app-export-2026-05.csv`
- `/srv/data/cache/thumb-42.jpg`
- `weekly.txt::$DATA`
- `index.txt::$INDEX`
- `/var/app/logs/audit-2026-06-06.log`

**File deletes**

- `/srv/reports/report-10.txt` (user input: `10`)
- `/srv/reports/invoice.csv` (user input: `invoice.csv`)
- `/srv/reports/invoice.csv` (user input: `/srv/reports/invoice.csv`)
- `/srv/app/WEB-INF/work.csv` (user input: `/srv/app/WEB-INF/work.csv`)

**Archive writes**

- `/srv/orders/drafts/../report.csv` (user input: `drafts/../report.csv`)
- `/srv/orders/report.csv` (user input: `../report.csv`)
- `/srv/orders/../orders/report.csv` (user input: `../orders/report.csv`)
- `/srv/orders/notes/report.csv` (user input: `/notes/report.csv`)
- `/srv/orders/drafts/../report.csv.bak` (user input: `../report.csv`)

**Deserialization classes**

- `java.util.ArrayList`
- `java.lang.String`
- `com.myapp.dto.OrderDto`
- `java.time.Instant`
- `java.util.LinkedHashMap`
- `com.myapp.model.Customer`
- `org.apache.commons.beanutils.BasicDynaBean`
- `org.apache.commons.beanutils.BasicDynaClass`
- `org.apache.commons.beanutils.DynaProperty`

**Expressions**

- `#{user.displayName}`
- `order.total > 100 ? 'priority' : 'standard'`
- `items[0].price * quantity`
- `customer.firstName + ' ' + customer.lastName`
- `#{T(java.lang.Math).max(a, b)}`

**OGNL expressions**

- `user.name`
- `#session.username`
- `top.id`
- `address.city`
- `person.age > 18`
- `%{getText('label.welcome')}`
- `order.items.size()`

**JNDI names**

- `java:comp/env/jdbc/AppDataSource`
- `java:comp/env/jms/QueueConnectionFactory`
- `java:global/AppEjb/UserService`

**DNS lookups**

- `api.partner.example.com`
- `db-primary.internal.example.com`
- `notdnslog.cn`
- `catalog.nonceye.io.`
- `smtp.example.com`
- `storage.googleapis.com`

**Ordinary deployment uploads**

- `weekly.jar`
- `component.war`
- `connector.ear`

**Upload filenames**

- `vacation-photo.jpg`
- `Q2-report-2026.pdf`
- `avatar.png`
- `export-2026-06.csv`
- `slides.pptx`
- `resume.docx`

**JDBC URLs**

- `jdbc:postgresql://db.internal:5432/app`
- `jdbc:mysql://db.internal:3306/app?useSSL=true&serverTimezone=UTC`
- `jdbc:h2:mem:testdb`
- `jdbc:oracle:thin:@db.internal:1521:orcl`
- `jdbc:sqlserver://db.internal;databaseName=app;encrypt=true`

**Request parameters**

- `I love <b>bold</b> and <i>italic</i> text` (user input: `I love <b>bold</b> and <i>italic</i> text`)
- `<p>Hello world</p>` (user input: `<p>Hello world</p>`)
- `<div class="card">welcome home</div>` (user input: `<div class="card">welcome home</div>`)
- `<ul><li>one</li><li>two</li></ul>` (user input: `<ul><li>one</li><li>two</li></ul>`)
- `prices: a < b, c > d` (user input: `prices: a < b, c > d`)
- `online surveys and onboarding tips` (user input: `online surveys and onboarding tips`)

**Base64 decoding**

- `SGVsbG8sIHdvcmxkIQ==`
- `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==`
- `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==`
- `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`
- `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
- `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==` (user input: `urlsafe`)
- `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` (user input: `urlsafe`)
- `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nA=` (user input: `mime`)

</details>

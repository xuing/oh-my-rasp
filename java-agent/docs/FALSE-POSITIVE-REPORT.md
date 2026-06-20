# OhMyRASP False-Positive Report

> **Generated** by `scripts/fp-harness/FpReport.java` against the real `DetectorEngine`.
> Re-run via `scripts/run-fp-report.sh` after changing detectors.

## Method

A curated corpus of **75** benign-but-plausible inputs across **13** detector categories is run through the engine. Each input is presented with a realistic request context; where a value would be user-supplied it is placed in a request parameter so taint-aware detectors evaluate it as in production. A *false positive* is any detector returning a detection for legitimate input. This is a detector-precision probe on benign traffic, **not** a production-traffic false-positive rate.

## Result

| Category | Benign inputs | False positives | FP rate |
|----------|--------------:|----------------:|--------:|
| SQL queries | 10 | 0 | 0.0% |
| OS commands | 8 | 0 | 0.0% |
| Outbound URLs | 6 | 0 | 0.0% |
| File reads | 5 | 0 | 0.0% |
| File writes | 4 | 0 | 0.0% |
| Deserialization classes | 6 | 0 | 0.0% |
| Expressions | 5 | 0 | 0.0% |
| OGNL expressions | 7 | 0 | 0.0% |
| JNDI names | 3 | 0 | 0.0% |
| DNS lookups | 4 | 0 | 0.0% |
| Upload filenames | 6 | 0 | 0.0% |
| JDBC URLs | 5 | 0 | 0.0% |
| Request parameters | 6 | 0 | 0.0% |
| **Overall** | **75** | **0** | **0.0%** |

No false positives observed across the corpus.

## Corpus

<details><summary>All benign inputs tested</summary>

**SQL queries**

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

- `git status`
- `/usr/bin/convert input.png output.jpg`
- `ffmpeg -i input.mp4 -vcodec copy output.mp4`
- `ls -la /var/app/data`
- `python3 /opt/app/report.py --month 2026-05` (user input: `2026-05`)
- `tar czf backup.tgz /var/app/uploads`
- `node /srv/app/index.js`
- `/usr/bin/pdftoppm -png /tmp/in.pdf /tmp/out`

**Outbound URLs**

- `https://api.stripe.com/v1/charges`
- `https://hooks.slack.com/services/T000/B000/abcdef`
- `https://www.googleapis.com/oauth2/v3/certs`
- `https://cdn.example.com/assets/logo.png`
- `https://payments.partner.example.com/api/charge`
- `https://graph.microsoft.com/v1.0/me`

**File reads**

- `/var/app/uploads/photo.jpg`
- `/opt/app/config/application.yml`
- `/srv/data/reports/2026-05.csv`
- `/home/appuser/.config/app/settings.json`
- `/var/app/templates/invoice.html`

**File writes**

- `/var/app/uploads/avatar-1001.png`
- `/tmp/app-export-2026-05.csv`
- `/srv/data/cache/thumb-42.jpg`
- `/var/app/logs/audit-2026-06-06.log`

**Deserialization classes**

- `java.util.ArrayList`
- `java.lang.String`
- `com.myapp.dto.OrderDto`
- `java.time.Instant`
- `java.util.LinkedHashMap`
- `com.myapp.model.Customer`

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
- `smtp.example.com`
- `storage.googleapis.com`

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

</details>

# Hello World demos

One minimal app per app type, all showing the same page (`hello.html`): a name
form that answers "Hello, &lt;name&gt;!" in the middle of the page. Each is
installable through `/install-app` with `"demo": true` and its folder as `path`
(e.g. `demos/python`) — the agent copies it from its own checkout, no clone —
and is listed in the Project5 apps manifest as `hello-<type>` with `isDemo`.
Each runs with its app type's default run command, except PHP: the type's
default, `php -S 0.0.0.0:443`, is PHP's built-in server, which cannot serve
HTTPS, so the PHP demo is a small server of its own and says so with
`php server.php`.

| Folder   | Run command (`app-cmd`)  | Built by                                   |
|----------|--------------------------|--------------------------------------------|
| `swift`  | `App serve --env production` | `swift build -c release` (SwiftNIO + NIOSSL) |
| `nodejs` | `npm start`              | `npm install` (no dependencies)            |
| `python` | `python3 app.py`         | a virtualenv (no requirements)             |
| `ruby`   | `ruby app.rb`            | nothing to build (no Gemfile)              |
| `go`     | `app`                    | `go build -o app .`                        |
| `php`    | `php server.php`         | nothing to build (no composer.json)        |
| `java`   | `java -jar app.jar`      | `mvn package`, jar copied to `app.jar`     |

Each also answers `GET /api/info` with JSON (`productName`, `version`,
`runtime`) — what the Project5 dashboard polls to show the app's card as
active.

Every app uses its standard library only (Swift needs SwiftNIO for a server),
listens on `$HOST:$PORT` (default `0.0.0.0:8080`), and serves HTTPS when
`TLS_CERT_PATH` and `TLS_KEY_PATH` are set — which the installer does, with a
self-signed certificate first and a Let's Encrypt one once a domain points at
the upplet. None needs a database.

Run one locally from its folder, e.g. `cd demos/python && python3 app.py`, then
open http://localhost:8080.

`hello.html` is the same file in every folder, so each app stays
self-contained when installed from its own `path`. Change them together.

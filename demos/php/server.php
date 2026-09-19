<?php
// Hello World demo — PHP, no extensions beyond openssl.
//
// PHP's built-in web server (php -S) cannot speak TLS, so this is a small
// server of its own: GET shows a name form; POST answers "Hello, <name>!" in the
// middle of the page. Listens on $HOST:$PORT (default 0.0.0.0:8080) and serves
// HTTPS when the installer has put TLS_CERT_PATH / TLS_KEY_PATH in the environment.

const RUNTIME = 'PHP';
$template = file_get_contents(__DIR__ . '/hello.html');

$form = '<h1>Hello World</h1><form method="post">'
      . '<input name="name" placeholder="Your name" autofocus required>'
      . '<button type="submit">Say hello</button></form>';

function greeting($name) {
    return '<h1>Hello, ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '!</h1><a href="/">Say hello again</a>';
}

function page($template, $content) {
    return str_replace('{{content}}', $content, str_replace('{{runtime}}', RUNTIME, $template));
}

$host = getenv('HOST') ?: '0.0.0.0';
$port = (int)(getenv('PORT') ?: 8080);
$cert = getenv('TLS_CERT_PATH');
$key  = getenv('TLS_KEY_PATH');
$tls  = $cert && $key;

$ctx = stream_context_create($tls ? ['ssl' => [
    'local_cert' => $cert,
    'local_pk' => $key,
    'verify_peer' => false,
]] : []);
$server = stream_socket_server("tcp://$host:$port", $errno, $errstr,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if (!$server) {
    fwrite(STDERR, "Cannot listen on $host:$port: $errstr\n");
    exit(1);
}
echo 'Hello World (' . RUNTIME . ') listening on ' . ($tls ? 'https' : 'http') . "://$host:$port\n";

while (true) {
    $client = @stream_socket_accept($server, -1);
    if (!$client) continue;
    stream_set_timeout($client, 10);
    // The handshake happens here, per connection, so a client that gives up
    // mid-handshake costs that connection and nothing else.
    if ($tls && !@stream_socket_enable_crypto($client, true, STREAM_CRYPTO_METHOD_TLS_SERVER)) {
        fclose($client);
        continue;
    }
    $requestLine = fgets($client);
    if ($requestLine === false) { fclose($client); continue; }
    $method = strtok($requestLine, ' ');
    $length = 0;
    while (($line = fgets($client)) !== false && trim($line) !== '') {
        if (stripos($line, 'content-length:') === 0) $length = (int)trim(substr($line, 15));
    }
    $content = $form;
    if ($method === 'POST') {
        $body = '';
        while (strlen($body) < $length && !feof($client)) {
            $chunk = fread($client, $length - strlen($body));
            if ($chunk === false || $chunk === '') break;
            $body .= $chunk;
        }
        parse_str($body, $fields);
        $name = trim((string)($fields['name'] ?? ''));
        $content = greeting($name === '' ? 'World' : $name);
    }
    $out = page($template, $content);
    fwrite($client, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        . 'Content-Length: ' . strlen($out) . "\r\nConnection: close\r\n\r\n" . $out);
    fclose($client);
}

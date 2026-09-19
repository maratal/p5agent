# Hello World demo — Ruby, standard library only (WEBrick left the standard
# library in Ruby 3.0, so this speaks just enough HTTP/1.1 itself).
#
# GET shows a name form; POST answers "Hello, <name>!" in the middle of the page.
# GET /api/info answers the product info a control panel polls for liveness.
# Listens on $HOST:$PORT (default 0.0.0.0:8080) and serves HTTPS when the
# installer has put TLS_CERT_PATH / TLS_KEY_PATH in the environment.
require 'socket'
require 'openssl'
require 'cgi'
require 'json'

RUNTIME = 'Ruby'
VERSION = '1.0.0'
TEMPLATE = File.read(File.join(__dir__, 'hello.html'), encoding: 'UTF-8')

FORM = '<h1>Hello World</h1><form method="post">' \
       '<input name="name" placeholder="Your name" autofocus required>' \
       '<button type="submit">Say hello</button></form>'

def greeting(name)
  "<h1>Hello, #{CGI.escapeHTML(name)}!</h1><a href=\"/\">Say hello again</a>"
end

def page(content)
  TEMPLATE.gsub('{{runtime}}') { RUNTIME }.gsub('{{content}}') { content }
end

def handle(client)
  request_line = client.gets or return
  method, target = request_line.split(' ')
  headers = {}
  while (line = client.gets) && line != "\r\n" && line != "\n"
    k, v = line.split(':', 2)
    headers[k.strip.downcase] = v.to_s.strip if k
  end
  if method == 'GET' && target.to_s.split('?').first == '/api/info'
    info = { productName: "Hello #{RUNTIME}", version: VERSION, runtime: "Ruby #{RUBY_VERSION}" }
    return respond(client, info.to_json, 'application/json')
  end
  content = FORM
  if method == 'POST'
    length = headers['content-length'].to_i
    body = length > 0 ? client.read(length).to_s : ''
    # By hand rather than URI.decode_www_form, which rejects raw non-ASCII bytes.
    fields = body.split('&').map { |pair| pair.split('=', 2).map { |s| CGI.unescape(s.to_s, 'UTF-8') } }.to_h
    name = fields['name'].to_s.strip
    content = greeting(name.empty? ? 'World' : name)
  end
  respond(client, page(content), 'text/html')
rescue StandardError => e
  warn "request failed: #{e.class}: #{e.message}"
ensure
  client.close rescue nil
end

def respond(client, text, content_type)
  out = text.b
  client.write("HTTP/1.1 200 OK\r\n" \
               "Content-Type: #{content_type}; charset=utf-8\r\n" \
               "Content-Length: #{out.bytesize}\r\n" \
               "Connection: close\r\n\r\n")
  client.write(out)
end

host = ENV['HOST'].to_s.empty? ? '0.0.0.0' : ENV['HOST']
port = (ENV['PORT'].to_s.empty? ? 8080 : ENV['PORT']).to_i
server = TCPServer.new(host, port)
scheme = 'http'
cert, key = ENV['TLS_CERT_PATH'].to_s, ENV['TLS_KEY_PATH'].to_s
unless cert.empty? || key.empty?
  ctx = OpenSSL::SSL::SSLContext.new
  pem = File.read(cert)
  chain = pem.scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m)
  ctx.cert = OpenSSL::X509::Certificate.new(chain.first)
  ctx.extra_chain_cert = chain.drop(1).map { |c| OpenSSL::X509::Certificate.new(c) }
  ctx.key = OpenSSL::PKey.read(File.read(key))
  server = OpenSSL::SSL::SSLServer.new(server, ctx)
  server.start_immediately = false   # handshake per connection, in its thread
  scheme = 'https'
end
$stdout.sync = true
puts "Hello World (#{RUNTIME}) listening on #{scheme}://#{host}:#{port}"

loop do
  begin
    client = server.accept
  rescue OpenSSL::SSL::SSLError, IOError, SystemCallError => e
    warn "accept failed: #{e.message}"
    next
  end
  Thread.new(client) do |c|
    begin
      c.accept if c.respond_to?(:accept)   # TLS handshake
      handle(c)
    rescue StandardError => e
      warn "connection failed: #{e.class}: #{e.message}"
      c.close rescue nil
    end
  end
end

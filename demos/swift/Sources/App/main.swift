// Hello World demo — Swift on SwiftNIO.
//
// GET shows a name form; POST answers "Hello, <name>!" in the middle of the page.
// GET /api/info answers the product info a control panel polls for liveness.
// Listens on $HOST:$PORT (default 0.0.0.0:8080) and serves HTTPS when the
// installer has put TLS_CERT_PATH / TLS_KEY_PATH in the environment. The
// installer runs the built "App" binary from the app directory, which is where
// hello.html is read from. Arguments (the default "serve --env production") are
// accepted and ignored: there is only one thing to serve.
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL

let runtimeName = "Swift"
let version = "1.0.0"
let template = (try? String(contentsOfFile: "hello.html", encoding: .utf8)) ?? "<main>{{content}}</main>"

let form = "<h1>Hello World</h1><form method=\"post\">"
    + "<input name=\"name\" placeholder=\"Your name\" autofocus required>"
    + "<button type=\"submit\">Say hello</button></form>"

func escapeHTML(_ s: String) -> String {
    s.replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&#x27;")
}

func greeting(_ name: String) -> String {
    "<h1>Hello, \(escapeHTML(name))!</h1><a href=\"/\">Say hello again</a>"
}

func page(_ content: String) -> String {
    template.replacingOccurrences(of: "{{runtime}}", with: runtimeName)
        .replacingOccurrences(of: "{{content}}", with: content)
}

// application/x-www-form-urlencoded → the value of one field.
func formValue(_ body: String, _ field: String) -> String {
    for pair in body.split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        let decode = { (s: Substring) in
            String(s).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String(s)
        }
        if decode(parts[0]) == field { return parts.count > 1 ? decode(parts[1]) : "" }
    }
    return ""
}

final class HelloHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private var head: HTTPRequestHead?
    private var body = ByteBuffer()

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h):
            head = h
            body.clear()
        case .body(var chunk):
            body.writeBuffer(&chunk)
        case .end:
            guard let h = head else { return }
            head = nil
            if h.method == .GET && h.uri.split(separator: "?").first == "/api/info" {
                let info = "{\"productName\":\"Hello \(runtimeName)\",\"version\":\"\(version)\",\"runtime\":\"Swift\"}"
                respond(context: context, keepAlive: h.isKeepAlive, body: info, contentType: "application/json")
                return
            }
            var content = form
            if h.method == .POST {
                let raw = body.readString(length: body.readableBytes) ?? ""
                let name = formValue(raw, "name").trimmingCharacters(in: .whitespacesAndNewlines)
                content = greeting(name.isEmpty ? "World" : name)
            }
            respond(context: context, keepAlive: h.isKeepAlive, body: page(content), contentType: "text/html")
        }
    }

    private func respond(context: ChannelHandlerContext, keepAlive: Bool, body: String, contentType: String) {
        var buffer = context.channel.allocator.buffer(capacity: body.utf8.count)
        buffer.writeString(body)
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "\(contentType); charset=utf-8")
        headers.add(name: "Content-Length", value: String(buffer.readableBytes))
        if !keepAlive { headers.add(name: "Connection", value: "close") }
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: .ok, headers: headers))), promise: nil)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        let done = context.writeAndFlush(wrapOutboundOut(.end(nil)))
        if !keepAlive {
            let channel = context.channel
            done.whenComplete { _ in channel.close(promise: nil) }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

func makeTLSContext() throws -> NIOSSLContext? {
    let env = ProcessInfo.processInfo.environment
    guard let cert = env["TLS_CERT_PATH"], let key = env["TLS_KEY_PATH"], !cert.isEmpty, !key.isEmpty else {
        return nil
    }
    let chain = try NIOSSLCertificate.fromPEMFile(cert).map { NIOSSLCertificateSource.certificate($0) }
    let privateKey = try NIOSSLPrivateKey(file: key, format: .pem)
    let config = TLSConfiguration.makeServerConfiguration(certificateChain: chain, privateKey: .privateKey(privateKey))
    return try NIOSSLContext(configuration: config)
}

let env = ProcessInfo.processInfo.environment
let host = env["HOST"].flatMap { $0.isEmpty ? nil : $0 } ?? "0.0.0.0"
let port = env["PORT"].flatMap { Int($0) } ?? 8080
let tlsContext = try makeTLSContext()

let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
let bootstrap = ServerBootstrap(group: group)
    .serverChannelOption(ChannelOptions.backlog, value: 256)
    .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
    .childChannelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
            if let tlsContext = tlsContext {
                try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tlsContext))
            }
            try channel.pipeline.syncOperations.configureHTTPServerPipeline(withErrorHandling: true)
            try channel.pipeline.syncOperations.addHandler(HelloHandler())
        }
    }
    .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

let channel = try bootstrap.bind(host: host, port: port).wait()
print("Hello World (\(runtimeName)) listening on \(tlsContext == nil ? "http" : "https")://\(host):\(port)")
fflush(stdout)
try channel.closeFuture.wait()

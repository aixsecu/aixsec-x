// AIXSEC-owned HTTP sender observer. No target-controlled code is evaluated.
// The adapter replaces the output placeholder with a JSON-quoted private path.
var Files = Java.type('java.nio.file.Files');
var Paths = Java.type('java.nio.file.Paths');
var Options = Java.type('java.nio.file.StandardOpenOption');
var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');
var output = Paths.get(__AIXSEC_OUTPUT__);
var lock = new (Java.type('java.util.concurrent.locks.ReentrantLock'))();
var transcript = output.resolveSibling('active-evidence.jsonl');
var byteLimit = 16 * 1024 * 1024;
function digest(value) {
    var bytes = new (Java.type('java.lang.String'))(value).getBytes('UTF-8');
    return String(Java.type('java.util.HexFormat').of().formatHex(
        Java.type('java.security.MessageDigest').getInstance('SHA-256').digest(bytes)));
}
function sensitive(name) {
    return /(?:password|passwd|secret|token|session|cookie|authorization|api.?key|csrf)/i.test(name);
}
function form(value) {
    return value.split('&').map(function(part) {
        var at = part.indexOf('=');
        var key = at < 0 ? part : part.slice(0, at);
        try { if (sensitive(decodeURIComponent(key.replace(/\+/g, ' ')))) return key + '=<redacted>'; }
        catch (ignored) { return key + '=<redacted>'; }
        return part;
    }).join('&');
}
function cleanJson(value) {
    if (!value || typeof value !== 'object') return value;
    Object.keys(value).forEach(function(key) {
        value[key] = sensitive(key) ? '<redacted>' : cleanJson(value[key]);
    });
    return value;
}
function sendingRequest(msg, initiator, helper) {}
function responseReceived(msg, initiator, helper) {
    if (initiator !== HttpSender.ACTIVE_SCANNER_INITIATOR) return;
    var rule = msg.getRequestHeader().getHeader('X-ZAP-Scan-ID');
    if (rule === null) return;
    var parameters = [];
    function names(values) {
        var it = values.iterator();
        while (it.hasNext()) parameters.push(String(it.next().getName()));
    }
    names(msg.getUrlParams());
    names(msg.getFormParams());
    var contentType = String(msg.getRequestHeader().getHeader('Content-Type') || '');
    if (contentType.indexOf('json') >= 0) {
        try {
            var body = JSON.parse(String(msg.getRequestBody()));
            if (body && typeof body === 'object' && !Array.isArray(body))
                parameters = parameters.concat(Object.keys(body));
        } catch (ignored) {}
    }
    function cookieNames(value) {
        if (value === null) return [];
        return String(value).split(';').map(function(part) {
            var at = part.indexOf('=');
            return (at < 0 ? part : part.slice(0, at)).trim();
        }).filter(function(name) { return name.length > 0; });
    }
    var setCookies = msg.getResponseHeader().getHeaderValues('Set-Cookie');
    var setCookieNames = [];
    if (setCookies !== null) {
        var cookieIt = setCookies.iterator();
        while (cookieIt.hasNext()) {
            var setCookie = String(cookieIt.next());
            setCookieNames = setCookieNames.concat(cookieNames(setCookie.split(';')[0]));
        }
    }
    var row = {url: String(msg.getRequestHeader().getURI()).split('?')[0].split('#')[0],
        method: String(msg.getRequestHeader().getMethod()), parameters: parameters,
        rule_id: String(rule), status: msg.getResponseHeader().getStatusCode(),
        set_cookie: msg.getResponseHeader().getHeader('Set-Cookie') !== null,
        redirect: msg.getResponseHeader().getHeader('Location') !== null,
        set_cookie_names: setCookieNames,
        request_cookie_names: cookieNames(msg.getRequestHeader().getHeader('Cookie')),
        location: String(msg.getResponseHeader().getHeader('Location') || ''),
        elapsed_ms: msg.getTimeElapsedMillis()};
    lock.lock();
    try {
        Files.writeString(output, JSON.stringify(row) + '\n', Options.CREATE, Options.APPEND);
        // Private bounded evidence; never copied to model context. Headers are omitted.
        var response = String(msg.getResponseBody());
        var request = String(msg.getRequestBody());
        var uri = String(msg.getRequestHeader().getURI());
        var at = uri.indexOf('?');
        var safeUri = at < 0 ? uri : uri.slice(0, at + 1) + form(uri.slice(at + 1));
        var safeBody = '';
        if (contentType.indexOf('application/x-www-form-urlencoded') >= 0) safeBody = form(request);
        else if (contentType.indexOf('json') >= 0) {
            try { safeBody = JSON.stringify(cleanJson(JSON.parse(request))); } catch (ignored) {}
        }
        var detail = Object.assign({}, row, {
            request_url: safeUri,
            request_body: safeBody.slice(0, 16384), response_body: response.slice(0, 65536),
            request_sha256: digest(String(msg.getRequestHeader().getURI()) + '\n' + request),
            response_sha256: digest(response),
            request_truncated: request.length > 16384, response_truncated: response.length > 65536,
            elapsed_ms: msg.getTimeElapsedMillis()
        });
        var line = new (Java.type('java.lang.String'))(JSON.stringify(detail) + '\n').getBytes('UTF-8');
        if ((!Files.exists(transcript) ? 0 : Files.size(transcript)) + line.length <= byteLimit)
            Files.write(transcript, line, Options.CREATE, Options.APPEND);
        else Files.writeString(output.resolveSibling('active-evidence-truncated'), 'true', Options.CREATE);
    }
    finally { lock.unlock(); }
}

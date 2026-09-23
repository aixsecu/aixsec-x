// AIXSEC-owned HTTP sender observer. No target-controlled code is evaluated.
// The adapter replaces the output placeholder with a JSON-quoted private path.
var Files = Java.type('java.nio.file.Files');
var Paths = Java.type('java.nio.file.Paths');
var Options = Java.type('java.nio.file.StandardOpenOption');
var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');
var output = Paths.get(__AIXSEC_OUTPUT__);
var lock = new (Java.type('java.util.concurrent.locks.ReentrantLock'))();
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
    var row = {url: String(msg.getRequestHeader().getURI()).split('?')[0].split('#')[0],
        method: String(msg.getRequestHeader().getMethod()), parameters: parameters,
        rule_id: String(rule), status: msg.getResponseHeader().getStatusCode()};
    lock.lock();
    try { Files.writeString(output, JSON.stringify(row) + '\n', Options.CREATE, Options.APPEND); }
    finally { lock.unlock(); }
}

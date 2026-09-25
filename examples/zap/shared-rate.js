// Shared per-origin request pacing across worker JVMs; lock remains private.
var rateFile = new (Java.type('java.io.RandomAccessFile'))(__AIXSEC_RATE_PATH__, 'rw');
var rateChannel = rateFile.getChannel();
var rateLocal = new (Java.type('java.util.concurrent.locks.ReentrantLock'))();
function sendingRequest(msg, initiator, helper) {
    if (initiator !== HttpSender.ACTIVE_SCANNER_INITIATOR) return;
    rateLocal.lock();
    try {
        var lease = rateChannel.lock();
        try {
            var now = Java.type('java.lang.System').currentTimeMillis();
            rateFile.seek(0);
            var last = rateFile.length() >= 8 ? rateFile.readLong() : 0;
            var delay = Math.max(0, __AIXSEC_RATE_MS__ - (now - last));
            if (delay > 0) Java.type('java.lang.Thread').sleep(delay);
            rateFile.seek(0);
            rateFile.writeLong(Java.type('java.lang.System').currentTimeMillis());
        } finally { lease.release(); }
    } finally { rateLocal.unlock(); }
}

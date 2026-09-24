// Export installed rule metadata; not a model-supplied scan policy.
var Control = Java.type('org.parosproxy.paros.control.Control');
var extension = Control.getSingleton().getExtensionLoader().getExtension('ExtensionActiveScan');
var plugins = extension.getPolicyManager().getDefaultScanPolicy().getPluginFactory().getAllPlugin();
var rows = [];
var iterator = plugins.iterator();
while (iterator.hasNext()) {
    var plugin = iterator.next();
    rows.push({id: plugin.getId(), name: String(plugin.getName()),
               category: plugin.getCategory(), cwe_id: plugin.getCweId()});
}
Java.type('java.nio.file.Files').writeString(
    Java.type('java.nio.file.Paths').get(__AIXSEC_OUTPUT__), JSON.stringify(rows));

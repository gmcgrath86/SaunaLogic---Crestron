Java.perform(function () {
  function log(s) { console.log(s); }

  function tryFetchLocalKey() {
    try {
      var PluginManager = Java.use('com.thingclips.sdk.core.PluginManager');
      var IThingDevicePlugin = Java.use('com.thingclips.smart.interior.api.IThingDevicePlugin');
      var plugin = PluginManager.service(IThingDevicePlugin.class);
      if (!plugin) {
        log('[fetch] device plugin not available');
        return;
      }
      var devList = plugin.getDevListCacheManager();
      if (!devList) {
        log('[fetch] devListCacheManager null');
        return;
      }
      var devId = '27703180e868e7eda84a';
      var dev = devList.getDev(devId);
      if (!dev) {
        log('[fetch] device not found for devId=' + devId);
        return;
      }
      if (dev.getName) log('[fetch] name=' + dev.getName());
      if (dev.getLocalKey) {
        var k = dev.getLocalKey();
        if (k) log('[fetch] localKey=' + k);
        else log('[fetch] localKey empty');
      }
      if (dev.getDevId) log('[fetch] devId=' + dev.getDevId());
    } catch (e) {
      log('[fetch-error] ' + e);
    }
  }

  setTimeout(tryFetchLocalKey, 2000);
  setInterval(tryFetchLocalKey, 8000);
});

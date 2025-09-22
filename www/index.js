var METHODS = [
  'addNetwork',
  'checkPermissions',
  'disableNetwork',
  'disconnect',
  'enableNetwork',
  'getConfiguredNetworks',
  'getConnectionInfo',
  'getCurrentNetwork',
  'getDhcpInfo',
  'getScanResults',
  'getWifiApConfiguration',
  'getWifiApState',
  'getWifiState',
  'isScanAlwaysAvailable',
  'isWifiApEnabled',
  'isWifiConnected',
  'isWifiEnabled',
  'reassociate',
  'reconnect',
  'removeNetwork',
  'removeAllSuggestions',
  'saveConfiguration',
  'setWifiApConfiguration',
  'setWifiApEnabled',
  'setWifiEnabled',
  'startScan',
  'updateNetwork'
];

var noop = function () {};
var slice = Array.prototype.slice;

var toError = function (obj) {
  if (!obj) return new Error('ERROR');
  if (obj instanceof Error) return obj;
  if (obj.hasOwnProperty('data')) return new Error(obj.data || 'ERROR');
  return new Error(obj);
};

var exec = function (method, args, cb) {
  var onsucces = function () {
    var args = slice.call(arguments);
    args.unshift(null);
    cb.apply(null, args);
  };

  var onerror = function (err) {
    cb(toError(err));
  };

  window.cordova.exec(onsucces, onerror, 'WifiManagerPlugin', method, args || []);
};

var WifiManager = function () {
  this.onnetworkidschanged = null;
  this.onnetworkstatechanged = null;
  this.onrssichanged = null;
  this.onscanresultsavailable = null;
  this.onsupplicantconnectionchange = null;
  this.onsupplicantstatechanged = null;
  this.onwifiapstatechanged = null;
  this.onwifistatechanged = null;
  this.onevent = null;
  this.onerror = null;

  var self = this;

  // The native side may call the onChange success callback with either:
  //  - a single object { event: 'NAME', data: ... }
  //  - two args: eventName, data
  //  - other shapes (strings, JSON-stringified payloads)
  // Accept any of those forms and normalize.
  exec('onChange', null, function () {
    var args = slice.call(arguments);
    var err = args[0];
    if (err) {
      if (self.onerror) self.onerror(err);
      return;
    }

    // success args follow
    var successArgs = args.slice(1);
    var eventName = null;
    var data = null;

    if (successArgs.length === 1) {
      var payload = successArgs[0];
      // payload may be JSON string
      if (typeof payload === 'string') {
        try {
          payload = JSON.parse(payload);
        } catch (e) {
          // leave as string
        }
      }
      if (payload && typeof payload === 'object' && payload.hasOwnProperty('event')) {
        eventName = payload.event;
        data = payload.hasOwnProperty('data') ? payload.data : null;
      } else {
        // If payload is a plain string or object without event, try best-effort
        eventName = (payload && payload.event) || null;
        data = payload;
      }
    } else if (successArgs.length >= 2) {
      eventName = successArgs[0];
      data = successArgs[1];
      if (typeof data === 'string') {
        try {
          data = JSON.parse(data);
        } catch (e) {}
      }
    }

    if (!eventName && data && data.event) eventName = data.event;
    // Debug: log incoming normalized events for troubleshooting Android 10/11 differences
    try {
      if (typeof console !== 'undefined' && console.debug) console.debug('WifiManager onChange:', eventName, data);
    } catch (e) {}
    if (!eventName) {
      // fallback: unknown event
      return;
    }

    // Special handling for Android 10+ authentication failures
    // The system might not emit traditional supplicant events, so we need to detect
    // connection failures through other means
    if (eventName === 'NETWORK_STATE_CHANGED' && data && data.networkInfo) {
      const networkInfo = data.networkInfo;
      console.log('[ANDROID11_DEBUG] WifiManager: Network state changed -', networkInfo.detailedState, networkInfo.state);
      console.log('[ANDROID11_DEBUG] WifiManager: Full networkInfo:', JSON.stringify(networkInfo));
      
      if (networkInfo.detailedState === 'FAILED' || 
          (networkInfo.detailedState === 'DISCONNECTED' && networkInfo.state === 'DISCONNECTED')) {
        // This might be an authentication failure
        console.log('[ANDROID11_DEBUG] WifiManager: Detected potential authentication failure');
        try {
          if (self.onevent) self.onevent('AUTHENTICATION_FAILED', { 
            reason: 'Network state changed to failed/disconnected',
            detailedState: networkInfo.detailedState,
            state: networkInfo.state
          });
        } catch (e) {
          console.error('[ANDROID11_DEBUG] WifiManager wrapper error handling AUTHENTICATION_FAILED', e);
        }
      }
    }

    var event = ('' + eventName).replace(/_/g, '').toLowerCase();
    var cb = self['on' + event];
    try {
      if (cb) cb.call(self, data);
      if (self.onevent) self.onevent(event, data);
    } catch (e) {
      // swallow errors to avoid breaking native callbacks
      console.error('WifiManager wrapper onChange handler error', e);
    }
  });
};

METHODS.forEach(function (method) {
  WifiManager.prototype[method] = function () {
    var args = slice.call(arguments);
    var cb = args[args.length - 1];

    if (typeof cb === 'function') args.pop();
    else cb = noop;

    exec(method, args, function () {
      var a = slice.call(arguments);
      var err = a[0];
      if (err) return cb(err);
      var succ = a.slice(1);
      var result = succ.length === 1 ? succ[0] : succ;

      // If result is a JSON string, try to parse it
      if (typeof result === 'string') {
        try {
          result = JSON.parse(result);
        } catch (e) {
          // keep original string
        }
      }

      try {
        if (result && typeof result === 'object' && result.hasOwnProperty('data')) {
          cb(null, result.data);
        } else {
          cb(null, result);
        }
      } catch (e) {
        cb(null, result);
      }
    });
  };
});

module.exports = new WifiManager();

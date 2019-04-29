package com.ly.wifi;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.util.Log;

import androidx.core.app.ActivityCompat;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.PluginRegistry;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import android.content.SharedPreferences;
import android.preference.PreferenceManager;

public class
WifiDelegate implements PluginRegistry.RequestPermissionsResultListener {
    private Activity activity;
    private WifiManager wifiManager;
    private PermissionManager permissionManager;
    private static final int REQUEST_ACCESS_FINE_LOCATION_PERMISSION = 1;
    private static final int REQUEST_CHANGE_WIFI_STATE_PERMISSION = 2;
    NetworkChangeReceiver networkReceiver;
    private String TAG = this.getClass().getSimpleName();
    private static final int REQUEST_ACCESS_COARSE_LOCATION_PERMISSION = 3;
    private ScanResultReceiver receiver;
    private WifiInfo info;

    interface PermissionManager {
        boolean isPermissionGranted(String permissionName);

        void askForPermission(String permissionName, int requestCode);
    }

    public WifiDelegate(final Activity activity, final WifiManager wifiManager) {
        this(activity, wifiManager, null, null, new PermissionManager() {

            @Override
            public boolean isPermissionGranted(String permissionName) {
                return ActivityCompat.checkSelfPermission(activity, permissionName) == PackageManager.PERMISSION_GRANTED;
            }

            @Override
            public void askForPermission(String permissionName, int requestCode) {
                ActivityCompat.requestPermissions(activity, new String[]{permissionName}, requestCode);
            }
        });
    }

    private MethodChannel.Result result;
    private MethodCall methodCall;

    WifiDelegate(
            Activity activity,
            WifiManager wifiManager,
            MethodChannel.Result result,
            MethodCall methodCall,
            PermissionManager permissionManager) {
        this.networkReceiver = new NetworkChangeReceiver();
        this.activity = activity;
        this.wifiManager = wifiManager;
        this.result = result;
        this.methodCall = methodCall;
        this.permissionManager = permissionManager;
    }

    public void getSSID(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        if(ActivityCompat.checkSelfPermission(activity, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
            launchSSID();
        } else {
            ActivityCompat.requestPermissions(activity, new String[] {Manifest.permission.ACCESS_FINE_LOCATION}, REQUEST_ACCESS_FINE_LOCATION_PERMISSION);
        }
    }

    public void getLevel(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        launchLevel();
    }

    private void launchSSID() {
        String wifiName = wifiManager != null ? wifiManager.getConnectionInfo().getSSID().replace("\"", "") : "";
        if (!wifiName.isEmpty()) {
            result.success(wifiName);
            clearMethodCallAndResult();
        } else {
            finishWithError("unavailable", "wifi name not available.");
        }
    }

    private void launchLevel() {
        int level = wifiManager != null ? wifiManager.getConnectionInfo().getRssi() : 0;
        if (level != 0) {
            if (level <= 0 && level >= -55) {
                result.success(3);
            } else if (level < -55 && level >= -80) {
                result.success(2);
            } else if (level < -80 && level >= -100) {
                result.success(1);
            } else {
                result.success(0);
            }
            clearMethodCallAndResult();
        } else {
            finishWithError("unavailable", "wifi level not available.");
        }
    }

    public void getIP(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        launchIP();
    }

    private void launchIP() {
        NetworkInfo info = ((ConnectivityManager) activity.getSystemService(Context.CONNECTIVITY_SERVICE)).getActiveNetworkInfo();
        if (info != null && info.isConnected()) {
            if (info.getType() == ConnectivityManager.TYPE_MOBILE) {
                try {
                    for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                        NetworkInterface intf = en.nextElement();
                        for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                            InetAddress inetAddress = enumIpAddr.nextElement();
                            if (!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
                                result.success(inetAddress.getHostAddress());
                                clearMethodCallAndResult();
                            }
                        }
                    }
                } catch (SocketException e) {
                    e.printStackTrace();
                }
            } else if (info.getType() == ConnectivityManager.TYPE_WIFI) {
                WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                String ipAddress = intIP2StringIP(wifiInfo.getIpAddress());
                result.success(ipAddress);
                clearMethodCallAndResult();
            }
        } else {
            finishWithError("unavailable", "ip not available.");
        }
    }

    private static String intIP2StringIP(int ip) {
        return (ip & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                (ip >> 24 & 0xFF);
    }

    public void getWifiList(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        if (!permissionManager.isPermissionGranted(Manifest.permission.ACCESS_COARSE_LOCATION)) {
            permissionManager.askForPermission(Manifest.permission.ACCESS_COARSE_LOCATION, REQUEST_ACCESS_COARSE_LOCATION_PERMISSION);
            return;
        }
        launchWifiList();
    }

    private void launchWifiList() {
        String key = methodCall.argument("key");
        Log.e(TAG, "Key -> " + key);
        List<HashMap> list = new ArrayList<>();
        if (wifiManager != null) {
            Log.e(TAG, "Wifi Manager not null");
            List<ScanResult> scanResultList = wifiManager.getScanResults();
            Log.e(TAG, "Scan result -> " + wifiManager.getScanResults().toString());
            for (ScanResult scanResult : scanResultList) {
                int level;
                if (scanResult.level <= 0 && scanResult.level >= -55) {
                    level = 3;
                } else if (scanResult.level < -55 && scanResult.level >= -80) {
                    level = 2;
                } else if (scanResult.level < -80 && scanResult.level >= -100) {
                    level = 1;
                } else {
                    level = 0;
                }
                HashMap<String, Object> maps = new HashMap<>();
                if (key.equals("all")) {
                    maps.put("ssid", scanResult.SSID);
                    maps.put("level", level);
                    list.add(maps);
                    Log.e(TAG, "Data -> " + list.toString());
                } else {
                    if (scanResult.SSID.contains(key)) {
                        maps.put("ssid", scanResult.SSID);
                        maps.put("level", level);
                        list.add(maps);
                    }
                    Log.e(TAG, "Data -> " + list.toString());
                }
            }
        }
        result.success(list);
        clearMethodCallAndResult();
    }

    public void getListWifi(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        if (!permissionManager.isPermissionGranted(Manifest.permission.ACCESS_COARSE_LOCATION)) {
            permissionManager.askForPermission(Manifest.permission.ACCESS_COARSE_LOCATION, REQUEST_ACCESS_COARSE_LOCATION_PERMISSION);
            return;
        }
        getListWifiNearby();
    }

    private void getListWifiNearby() {
        if(wifiManager != null) {
            receiver = new ScanResultReceiver();
            activity.registerReceiver(receiver, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
            wifiManager.startScan();
            Log.e(TAG, "Scanning...");
            result.success(receiver.getData());
            clearMethodCallAndResult();
        }
    }

    public void connection(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        if (!permissionManager.isPermissionGranted(Manifest.permission.CHANGE_WIFI_STATE)) {
            permissionManager.askForPermission(Manifest.permission.CHANGE_WIFI_STATE, REQUEST_ACCESS_FINE_LOCATION_PERMISSION);
            return;
        }
        connection();
    }

    private void connection() {
        String ssid = methodCall.argument("ssid");
        String password = methodCall.argument("password");
        WifiConfiguration wifiConfig = createWifiConfig(ssid, password);
        if (wifiConfig == null) {
            finishWithError("unavailable", "wifi config is null!");
            return;
        }
        int netId = wifiManager.addNetwork(wifiConfig);
        if (netId == -1) {
            result.success(0);
            clearMethodCallAndResult();
        } else {
            // support Android O
            // https://stackoverflow.com/questions/50462987/android-o-wifimanager-enablenetwork-cannot-work
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                wifiManager.enableNetwork(netId, true);
                wifiManager.reconnect();
                result.success(1);
                clearMethodCallAndResult();
            } else {
                networkReceiver.connect(netId);
            }
        }
    }

    private WifiConfiguration createWifiConfig(String ssid, String Password) {
        WifiConfiguration config = new WifiConfiguration();
        config.SSID = "\"" + ssid + "\"";
        config.allowedAuthAlgorithms.clear();
        config.allowedGroupCiphers.clear();
        config.allowedKeyManagement.clear();
        config.allowedPairwiseCiphers.clear();
        config.allowedProtocols.clear();
        WifiConfiguration tempConfig = isExist(wifiManager, ssid);
        if (tempConfig != null) {
            wifiManager.removeNetwork(tempConfig.networkId);
        }
        config.preSharedKey = "\"" + Password + "\"";
        config.hiddenSSID = true;
        config.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
        config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
        config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
        config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        config.status = WifiConfiguration.Status.ENABLED;
        return config;
    }

    public void openConnection(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        if (!permissionManager.isPermissionGranted(Manifest.permission.CHANGE_WIFI_STATE)) {
            permissionManager.askForPermission(Manifest.permission.CHANGE_WIFI_STATE, REQUEST_CHANGE_WIFI_STATE_PERMISSION);
            return;
        }
        openConnection();
    }

    private void openConnection() {
        String ssid = methodCall.argument("ssid");
        if(!checkIfNetworkExist(ssid)) {
            Log.e(TAG, "Network doesn't exist, add config and connecting now...");
            WifiConfiguration config = new WifiConfiguration();
            config.SSID = "\"" + ssid + "\"";
            config.hiddenSSID = true;
            config.priority = 0xBADBAD;
            config.status = WifiConfiguration.Status.CURRENT;
            config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
            if(wifiManager != null) {
                int id = wifiManager.addNetwork(config);
                wifiManager.disconnect();
                wifiManager.enableNetwork(id, true);
                wifiManager.reconnect();
            }
        } else {
            Log.e(TAG, "Network is exist, auto connecting now ...");
            int id = getNetworkId(ssid);
            wifiManager.disconnect();
            wifiManager.enableNetwork(id, true);
            wifiManager.reconnect();
        }
    }

    private String getSsid() {
        return wifiManager.getConnectionInfo().getSSID().replace("\"", "");
    }

    public void connectToNetwork(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        if (!permissionManager.isPermissionGranted(Manifest.permission.CHANGE_WIFI_STATE)) {
            permissionManager.askForPermission(Manifest.permission.CHANGE_WIFI_STATE, REQUEST_CHANGE_WIFI_STATE_PERMISSION);
            return;
        }
        connectToNetwork();
    }

    private void connectToNetwork() {
        String ssid = methodCall.argument("ssid");
        String pass = methodCall.argument("pass");
        if(!checkIfNetworkExist(ssid)) {
            WifiConfiguration conf = new WifiConfiguration();
            conf.SSID = "\"" + ssid + "\"";
            conf.preSharedKey = "\"" + pass + "\"";
            conf.priority = 0xBADBAD;
            conf.status = WifiConfiguration.Status.CURRENT;
            if(wifiManager != null) {
                int id = wifiManager.addNetwork(conf);
                wifiManager.disconnect();
                wifiManager.enableNetwork(id, true);
                wifiManager.reconnect();
            }
        } else {
            Log.e(TAG, "Network is exist, auto connecting now ...");
            int id = getNetworkId(ssid);
            wifiManager.disconnect();
            wifiManager.enableNetwork(id, true);
            wifiManager.reconnect();
        }

        if(getSsid().equals(ssid)) {
            Log.e(TAG, "Successfull to connect to network");
            result.success("success");
        } else {
            Log.e(TAG, "Failed to connect to network");
            result.success("failed");
        }
        clearMethodCallAndResult();
    }

    public int getNetworkId(String ssid) {
        int netId = 0;
        List<WifiConfiguration> list = wifiManager.getConfiguredNetworks();
        for(WifiConfiguration config : list) {
            if(config.SSID.equals(ssid)) {
                netId = config.networkId;
            }
        }
        return netId;
    }

    public boolean checkIfNetworkExist(String ssid) {
        if(!ssid.isEmpty()) {
            List<WifiConfiguration> list = wifiManager.getConfiguredNetworks();
            for(WifiConfiguration config : list) {
                if(config.SSID.equals(ssid)) {
                    return true;
                }
            }
        }
        return false;
    }

    private WifiConfiguration isExist(WifiManager wifiManager, String ssid) {
        List<WifiConfiguration> existingConfigs = wifiManager.getConfiguredNetworks();
        for (WifiConfiguration existingConfig : existingConfigs) {
            if (existingConfig.SSID.equals("\"" + ssid + "\"")) {
                return existingConfig;
            }
        }
        return null;
    }

    public void getGateway(MethodCall methodCall, MethodChannel.Result result) {
        if (!setPendingMethodCallAndResult(methodCall, result)) {
            finishWithAlreadyActiveError();
            return;
        }
        getGateway();
    }

    private void getGateway() {
        String gateway = "";
        if(wifiManager != null) {
            gateway = convertIp(wifiManager.getDhcpInfo().gateway);
            if(!gateway.isEmpty()) {
                result.success(gateway);
                clearMethodCallAndResult();
            } else {
                finishWithError("unavailable", "Can't get the gateway!");
            }
        } else {
            finishWithError("unavailable", "WifiManager is null!");
        }
    }

    private String convertIp(int ip) {
        return (ip & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 24) & 0xFF);
    }

    private boolean setPendingMethodCallAndResult(MethodCall methodCall, MethodChannel.Result result) {
        if (this.result != null) {
            return false;
        }
        this.methodCall = methodCall;
        this.result = result;
        return true;
    }

    @Override
    public boolean onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        boolean permissionGranted = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
        switch (requestCode) {
            case REQUEST_ACCESS_FINE_LOCATION_PERMISSION:
                if (permissionGranted) {
                    // Log.e(TAG, "Launch wifi list");
                    launchSSID();
                }
                break;
            case REQUEST_ACCESS_COARSE_LOCATION_PERMISSION:
                if(permissionGranted) {
                    Log.e(TAG, "Launch wifi list");
                    getListWifiNearby();
                }
                break;
            case REQUEST_CHANGE_WIFI_STATE_PERMISSION:
                if (permissionGranted) {
                    connection();
                }
                break;
            default:
                return false;
        }
        if (!permissionGranted) {
            clearMethodCallAndResult();
        }
        return true;
    }

    private void finishWithAlreadyActiveError() {
        finishWithError("already_active", "wifi is already active");
    }

    private void finishWithError(String errorCode, String errorMessage) {
        result.error(errorCode, errorMessage, null);
        clearMethodCallAndResult();
    }

    private void clearMethodCallAndResult() {
        methodCall = null;
        result = null;
    }

    private void setDefaults(String key, String value, Context context) {
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(key, value);
        editor.commit();
    }

    private String getDefault(String key, Context context) {
        SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(context);
        return pref.getString(key, null);
    }

    // support Android O
    // https://stackoverflow.com/questions/50462987/android-o-wifimanager-enablenetwork-cannot-work
    public class NetworkChangeReceiver extends BroadcastReceiver {
        private int netId;
        private boolean willLink = false;

        @Override
        public void onReceive(Context context, Intent intent) {
            NetworkInfo info = intent.getParcelableExtra(ConnectivityManager.EXTRA_NETWORK_INFO);
            if (info.getState() == NetworkInfo.State.DISCONNECTED && willLink) {
                wifiManager.enableNetwork(netId, true);
                wifiManager.reconnect();
                result.success(1);
                willLink = false;
                clearMethodCallAndResult();
            }
        }

        public void connect(int netId) {
            this.netId = netId;
            willLink = true;
            wifiManager.disconnect();
        }
    }

    public class ScanResultReceiver extends BroadcastReceiver {

        // List<Data> data = new ArrayList<>();
        JSONArray data = new JSONArray();
        List<ScanResult> scanResult = new ArrayList<>();

        @Override
        public void onReceive(Context context, Intent intent) {
            scanResult = wifiManager.getScanResults();
            info = wifiManager.getConnectionInfo();
            activity.unregisterReceiver(this);
            int index = 0;
            for(int i = 0; i < scanResult.size(); i++) {
                String ssid = scanResult.get(i).SSID;
                String status = "";
                String capabilities = scanResult.get(i).capabilities;
                int level = scanResult.get(i).level;
                try {
                    JSONObject isi = new JSONObject();
                    if(ssid.equals(info.getSSID().replace("\"", ""))) {
                        status = "Connected";
                        index = 0;
                        isi.put("ssid", info.getSSID().replace("\"", ""));
                        isi.put("level", getLevel(level));
                        isi.put("status", status);
                        isi.put("capabilities", capabilities);
                    } else {
                        status = "Not connected";
                        isi.put("ssid", ssid);
                        isi.put("level", getLevel(level));
                        isi.put("status", status);
                        isi.put("capabilities", capabilities);
                        index++;
                    }
                    data.put(index, isi);
                } catch(JSONException e) {
                    e.printStackTrace();
                }
            }
            setDefaults("result", data.toString(), activity.getApplicationContext());
        }

        public String getData() {
            return getDefault("result", activity.getApplicationContext());
        }

        private int getLevel(int level) {
            int result = 0;
            if (level <= 0 && level >= -55) {
                result = 1;
            } else if (level < -55 && level >= -80) {
                result = 2;
            } else if (level < -80 && level >= -100) {
                result = 3;
            } else {
                result = 0;
            }
            return result;
        }
    }

    // class Data {
    //     String ssid;
    //     int level;

    //     public Data(String ssid, int level) {
    //         this.level = level;
    //         this.ssid = ssid;
    //     }

    //     public int getLevel() {
    //         return this.level;
    //     }

    //     public String getSsid() {
    //         return this.ssid;
    //     }

    //     public void setLevel(int level) {
    //         this.level = level;
    //     }

    //     public void setSsid(String ssid) {
    //         this.ssid = ssid;
    //     }
    // }
}

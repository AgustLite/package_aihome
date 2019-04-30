#import "WifiPlugin.h"
#import <wifi/wifi-Swift.h>

@implementation WifiPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
[SwiftWifiPlugin registerWithRegistrar:registrar];
}
@end

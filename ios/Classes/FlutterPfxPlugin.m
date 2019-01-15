#import "FlutterPfxPlugin.h"
#import <flutter_pfx/flutter_pfx-Swift.h>

@implementation FlutterPfxPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftFlutterPfxPlugin registerWithRegistrar:registrar];
}
@end

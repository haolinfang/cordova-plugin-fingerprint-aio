#import "StorageUtil.h"

@implementation StorageUtil

+ (void)savePreference:(NSString *)key value:(NSString *)value {
    [[NSUserDefaults standardUserDefaults] setObject:value forKey:key];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

+ (NSString *)getPreference:(NSString *)key {
    return [[NSUserDefaults standardUserDefaults] stringForKey:key] ?: @"";
}

@end
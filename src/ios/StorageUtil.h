#import <Foundation/Foundation.h>

@interface StorageUtil : NSObject

+ (void)savePreference:(NSString *)key value:(NSString *)value;
+ (NSString *)getPreference:(NSString *)key;

@end
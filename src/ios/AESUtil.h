#import <Foundation/Foundation.h>

@interface AESUtil : NSObject

+ (NSString *)encryptCBC:(NSString *)plaintext key:(NSString *)key iv:(NSString *)iv;
+ (NSString *)decryptCBC:(NSString *)encryptedBase64 key:(NSString *)key iv:(NSString *)iv;

@end
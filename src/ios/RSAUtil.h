#import <Foundation/Foundation.h>

@interface RSAUtil : NSObject

+ (NSString *)encryptWithRSA:(NSString *)plaintext publicKeyStr:(NSString *)publicKeyStr;

@end
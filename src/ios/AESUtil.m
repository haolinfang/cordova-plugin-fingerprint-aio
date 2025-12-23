#import "AESUtil.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation AESUtil

+ (NSString *)encryptCBC:(NSString *)plaintext key:(NSString *)key iv:(NSString *)iv {
    @try {
        if (key.length == 0) {
            return nil;
        }
        
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
        
        if (ivData.length < 16) {
            NSMutableData *paddedIV = [ivData mutableCopy];
            [paddedIV increaseLengthBy:16 - ivData.length];
            ivData = paddedIV;
        } else if (ivData.length > 16) {
            ivData = [ivData subdataWithRange:NSMakeRange(0, 16)];
        }
        
        size_t bufferSize = plainData.length + kCCBlockSizeAES128;
        void *buffer = malloc(bufferSize);
        
        if (buffer == NULL) {
            return nil;
        }
        
        size_t numBytesEncrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                              kCCAlgorithmAES,
                                              kCCOptionPKCS7Padding,
                                              keyData.bytes,
                                              kCCKeySizeAES128,
                                              ivData.bytes,
                                              plainData.bytes,
                                              plainData.length,
                                              buffer,
                                              bufferSize,
                                              &numBytesEncrypted);
        
        NSString *encryptedBase64 = nil;
        
        if (cryptStatus == kCCSuccess) {
            NSData *encryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
            encryptedBase64 = [encryptedData base64EncodedStringWithOptions:0];
        } else {
            free(buffer);
            NSLog(@"AES加密失败，状态码: %d", cryptStatus);
            return nil;
        }
        
        free(buffer);
        return encryptedBase64;
        
    } @catch (NSException *exception) {
        NSLog(@"AES加密异常: %@", exception);
        return nil;
    }
}

+ (NSString *)decryptCBC:(NSString *)encryptedBase64 key:(NSString *)key iv:(NSString *)iv {
    @try {
        if (key.length == 0) {
            return nil;
        }
        
        NSString *cleanBase64 = [encryptedBase64 stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        
        NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:cleanBase64 
                                                                   options:0];
        if (!encryptedData) {
            NSLog(@"Base64解码失败");
            return nil;
        }
        
        NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
        
        if (ivData.length < 16) {
            NSMutableData *paddedIV = [ivData mutableCopy];
            [paddedIV increaseLengthBy:16 - ivData.length];
            ivData = paddedIV;
        } else if (ivData.length > 16) {
            ivData = [ivData subdataWithRange:NSMakeRange(0, 16)];
        }
        
        size_t bufferSize = encryptedData.length + kCCBlockSizeAES128;
        void *buffer = malloc(bufferSize);
        
        if (buffer == NULL) {
            return nil;
        }
        
        size_t numBytesDecrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                              kCCAlgorithmAES,
                                              kCCOptionPKCS7Padding,
                                              keyData.bytes,
                                              kCCKeySizeAES128,
                                              ivData.bytes,
                                              encryptedData.bytes,
                                              encryptedData.length,
                                              buffer,
                                              bufferSize,
                                              &numBytesDecrypted);
        
        NSString *decryptedString = nil;
        
        if (cryptStatus == kCCSuccess) {
            NSData *decryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
            decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
        } else {
            free(buffer);
            NSLog(@"AES解密失败，状态码: %d", cryptStatus);
            return nil;
        }
        
        free(buffer);
        return decryptedString;
        
    } @catch (NSException *exception) {
        NSLog(@"AES解密异常: %@", exception);
        return nil;
    }
}

@end
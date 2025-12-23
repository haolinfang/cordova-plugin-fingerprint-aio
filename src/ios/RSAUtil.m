#import "RSAUtil.h"
#import <Security/Security.h>

@implementation RSAUtil

+ (NSString *)encryptWithRSA:(NSString *)plaintext publicKeyStr:(NSString *)publicKeyStr {
    @try {
        // 移除PEM格式的头部和尾部
        NSString *publicKeyPEM = publicKeyStr;
        publicKeyPEM = [publicKeyPEM stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
        publicKeyPEM = [publicKeyPEM stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
        publicKeyPEM = [publicKeyPEM stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        publicKeyPEM = [publicKeyPEM stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        // Base64解码
        NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyPEM options:0];
        
        // 创建公钥
        CFDataRef publicKeyCFData = (__bridge CFDataRef)publicKeyData;
        SecKeyRef publicKey = NULL;
        
        CFDictionaryRef keyAttributes = (__bridge CFDictionaryRef)@{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
            (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
            (id)kSecAttrKeySizeInBits: @2048
        };
        
        publicKey = SecKeyCreateFromData(keyAttributes, publicKeyCFData, NULL);
        
        if (!publicKey) {
            NSLog(@"创建公钥失败");
            return nil;
        }
        
        // 加密数据
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        CFDataRef plainDataRef = (__bridge CFDataRef)plainData;
        
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionPKCS1;
        
        if (!SecKeyIsAlgorithmSupported(publicKey, kSecKeyOperationTypeEncrypt, algorithm)) {
            NSLog(@"算法不支持");
            CFRelease(publicKey);
            return nil;
        }
        
        CFErrorRef error = NULL;
        CFDataRef encryptedData = SecKeyCreateEncryptedData(publicKey, algorithm, plainDataRef, &error);
        
        if (error) {
            NSLog(@"加密失败: %@", error);
            CFRelease(publicKey);
            return nil;
        }
        
        // 转换为Base64字符串
        NSData *encryptedNSData = (__bridge NSData *)encryptedData;
        NSString *encryptedBase64 = [encryptedNSData base64EncodedStringWithOptions:0];
        
        // 释放资源
        CFRelease(encryptedData);
        CFRelease(publicKey);
        
        return encryptedBase64;
        
    } @catch (NSException *exception) {
        NSLog(@"RSA加密异常: %@", exception);
        return nil;
    }
}

@end
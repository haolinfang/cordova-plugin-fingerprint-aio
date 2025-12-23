import Foundation
import LocalAuthentication
import UIKit
import CommonCrypto
import Security

enum PluginError:Int {
    case BIOMETRIC_UNKNOWN_ERROR = -100
    case BIOMETRIC_UNAVAILABLE = -101
    case BIOMETRIC_AUTHENTICATION_FAILED = -102
    case BIOMETRIC_PERMISSION_NOT_GRANTED = -105
    case BIOMETRIC_NOT_ENROLLED = -106
    case BIOMETRIC_DISMISSED = -108
    case BIOMETRIC_SCREEN_GUARD_UNSECURED = -110
    case BIOMETRIC_LOCKED_OUT = -111
    case BIOMETRIC_SECRET_NOT_FOUND = -113
}

let AES_KEY = "a9s8d7f6g5h4j3k2"
let AES_IV = "z1x2c3v4b5n6m7q8"

/// Keychain errors we might encounter.
struct KeychainError: Error {
    var status: OSStatus

    var localizedDescription: String {
        if #available(iOS 11.3, *) {
            if let result = SecCopyErrorMessageString(status, nil) as String? {
                return result
            }
        }
        switch status {
            case errSecItemNotFound:
                return "Secret not found"
            case errSecUserCanceled:
                return "Biometric dissmissed"
            case errSecAuthFailed:
                return "Authentication failed"
            default:
                return "Unknown error \(status)"
        }
    }

    var pluginError: PluginError {
        switch status {
        case errSecItemNotFound:
            return PluginError.BIOMETRIC_SECRET_NOT_FOUND
        case errSecUserCanceled:
            return PluginError.BIOMETRIC_DISMISSED
        case errSecAuthFailed:
                return PluginError.BIOMETRIC_AUTHENTICATION_FAILED
        default:
            return PluginError.BIOMETRIC_UNKNOWN_ERROR
        }
    }
}

class Secret {

    private static let keyName: String = "__aio_key"

    private func getBioSecAccessControl(invalidateOnEnrollment: Bool) -> SecAccessControl {
        var access: SecAccessControl?
        var error: Unmanaged<CFError>?

        if #available(iOS 11.3, *) {
            access = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                invalidateOnEnrollment ? .biometryCurrentSet : .userPresence,
                &error)
        } else {
            access = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                invalidateOnEnrollment ? .touchIDCurrentSet : .userPresence,
                &error)
        }
        precondition(access != nil, "SecAccessControlCreateWithFlags failed")
        return access!
    }

    func save(_ secret: String, invalidateOnEnrollment: Bool) throws {
        let password = secret.data(using: String.Encoding.utf8)!

        // Build the query for use in the add operation.
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: Secret.keyName,
                                    kSecAttrAccessControl as String: getBioSecAccessControl(invalidateOnEnrollment: invalidateOnEnrollment),
                                    kSecValueData as String: password]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    func load(_ prompt: String) throws -> String {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: Secret.keyName,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnData as String : kCFBooleanTrue,
                                    kSecAttrAccessControl as String: getBioSecAccessControl(invalidateOnEnrollment: true),
                                    kSecUseOperationPrompt as String: prompt]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { throw KeychainError(status: status) }

        guard let passwordData = item as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8)
            else {
                throw KeychainError(status: errSecInternalError)
        }

        return password
    }

    func delete() throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: Secret.keyName]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }
}

@objc(Fingerprint) class Fingerprint : CDVPlugin {

    struct ErrorCodes {
        var code: Int
    }

    @objc(isAvailable:)
    func isAvailable(_ command: CDVInvokedUrlCommand){
        let authenticationContext = LAContext();
        var biometryType = "finger";
        var errorResponse: [AnyHashable: Any] = [
            "code": 0,
            "message": "Not Available"
        ];
        var error:NSError?;
        let params = command.argument(at: 0) as? [AnyHashable: Any] ?? [:]
        let allowBackup = params["allowBackup"] as? Bool ?? false
        let policy:LAPolicy = allowBackup ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics;
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Not available");
        let available = authenticationContext.canEvaluatePolicy(policy, error: &error);

        var results: [String : Any]

        if(error != nil){
            biometryType = "none";
            errorResponse["code"] = error?.code;
            errorResponse["message"] = error?.localizedDescription;
        }

        if (available == true) {
            if #available(iOS 11.0, *) {
                switch(authenticationContext.biometryType) {
                case .none:
                    biometryType = "none";
                case .touchID:
                    biometryType = "finger";
                case .faceID:
                    biometryType = "face"
                @unknown default:
                    errorResponse["message"] = "Unkown biometry type"
                }
            }

            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: biometryType);
        }else{
            var code: Int;
            switch(error!._code) {
                case Int(kLAErrorBiometryNotAvailable):
                    code = PluginError.BIOMETRIC_UNAVAILABLE.rawValue;
                    break;
                case Int(kLAErrorBiometryNotEnrolled):
                    code = PluginError.BIOMETRIC_NOT_ENROLLED.rawValue;
                    break;

                default:
                    code = PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue;
                    break;
            }
            results = ["code": code, "message": error!.localizedDescription];
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: results);
        }

        commandDelegate.send(pluginResult, callbackId:command.callbackId);
    }

    func justAuthenticate(_ command: CDVInvokedUrlCommand) {
        let authenticationContext = LAContext();
        let errorResponse: [AnyHashable: Any] = [
            "message": "Something went wrong"
        ];
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResponse);
        var reason = "Authentication";
        var policy:LAPolicy = .deviceOwnerAuthentication;
        let data  = command.arguments[0] as? [String: Any];

        if let disableBackup = data?["disableBackup"] as! Bool? {
            if disableBackup {
                authenticationContext.localizedFallbackTitle = "";
                policy = .deviceOwnerAuthenticationWithBiometrics;
            } else {
                if let fallbackButtonTitle = data?["fallbackButtonTitle"] as! String? {
                    authenticationContext.localizedFallbackTitle = fallbackButtonTitle;
                }else{
                    authenticationContext.localizedFallbackTitle = "Use Pin";
                }
            }
        }

        // Localized reason
        if let description = data?["description"] as! String? {
            reason = description;
        }

        authenticationContext.evaluatePolicy(
            policy,
            localizedReason: reason,
            reply: { [unowned self] (success, error) -> Void in
                if( success ) {
                    pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: "Success");
                }else {
                    if (error != nil) {

                        var errorCodes = [Int: ErrorCodes]()
                        var errorResult: [String : Any] = ["code":  PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue, "message": error?.localizedDescription ?? ""];

                        errorCodes[1] = ErrorCodes(code: PluginError.BIOMETRIC_AUTHENTICATION_FAILED.rawValue)
                        errorCodes[2] = ErrorCodes(code: PluginError.BIOMETRIC_DISMISSED.rawValue)
                        errorCodes[5] = ErrorCodes(code: PluginError.BIOMETRIC_SCREEN_GUARD_UNSECURED.rawValue)
                        errorCodes[6] = ErrorCodes(code: PluginError.BIOMETRIC_UNAVAILABLE.rawValue)
                        errorCodes[7] = ErrorCodes(code: PluginError.BIOMETRIC_NOT_ENROLLED.rawValue)
                        errorCodes[8] = ErrorCodes(code: PluginError.BIOMETRIC_LOCKED_OUT.rawValue)

                        let errorCode = abs(error!._code)
                        if let e = errorCodes[errorCode] {
                           errorResult = ["code": e.code, "message": error!.localizedDescription];
                        }

                        pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
                    }
                }
                self.commandDelegate.send(pluginResult, callbackId:command.callbackId);
            }
        );
    }

    func saveSecret(_ secretStr: String, command: CDVInvokedUrlCommand) {
        let data  = command.arguments[0] as AnyObject?;
        var pluginResult: CDVPluginResult
        do {
            let secret = Secret()
            try? secret.delete()
            let invalidateOnEnrollment = (data?.object(forKey: "invalidateOnEnrollment") as? Bool) ?? false
            try secret.save(secretStr, invalidateOnEnrollment: invalidateOnEnrollment)
            
            // 获取 RSA 加密的 secret
            if let rsaEncryptedSecret = encryptSecretWithRSA(secretStr) {
                pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: rsaEncryptedSecret);
            } else {
                let errorResult = ["code": PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue, "message": "RSA encryption failed"] as [String : Any];
                pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
            }
        } catch {
            let errorResult = ["code": PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue, "message": error.localizedDescription] as [String : Any];
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
        }
        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
        return
    }


    func loadSecret(_ command: CDVInvokedUrlCommand) {
        let data  = command.arguments[0] as AnyObject?;
        var prompt = "Authentication"
        if let description = data?.object(forKey: "description") as! String? {
            prompt = description;
        }
        var pluginResult: CDVPluginResult
        do {
            let result = try Secret().load(prompt)
            
            // 获取 RSA 加密的 secret
            if let rsaEncryptedSecret = encryptSecretWithRSA(result) {
                pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: rsaEncryptedSecret);
            } else {
                let errorResult = ["code": PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue, "message": "RSA encryption failed"] as [String : Any];
                pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
            }
        } catch {
            var code = PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue
            var message = error.localizedDescription
            if let err = error as? KeychainError {
                code = err.pluginError.rawValue
                message = err.localizedDescription
            }
            let errorResult = ["code": code, "message": message] as [String : Any]
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
        }
        self.commandDelegate.send(pluginResult, callbackId:command.callbackId)
    }

    @objc(authenticate:)
    func authenticate(_ command: CDVInvokedUrlCommand){
        justAuthenticate(command)
    }

    @objc(registerBiometricSecret:)
    func registerBiometricSecret(_ command: CDVInvokedUrlCommand){
        let data  = command.arguments[0] as AnyObject?;
        if let secret = data?.object(forKey: "secret") as? String {
            self.saveSecret(secret, command: command)
            return
        }
    }

    @objc(loadBiometricSecret:)
    func loadBiometricSecret(_ command: CDVInvokedUrlCommand){
        self.loadSecret(command)
    }

    override func pluginInitialize() {
        super.pluginInitialize()
    }
    
    // MARK: - RSA 加密方法
    
    private func encryptWithRSA(_ plaintext: String, publicKeyStr: String) -> String? {
        // 清理公钥字符串
        var cleanedKey = publicKeyStr
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: " ", with: "")
        
        // Base64 解码
        guard let keyData = Data(base64Encoded: cleanedKey) else {
            print("公钥 Base64 解码失败")
            return nil
        }
        
        // 创建公钥
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: 2048
        ]
        
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            print("创建公钥失败: \(error?.takeRetainedValue().localizedDescription ?? "未知错误")")
            return nil
        }
        
        // 加密数据
        guard let plainData = plaintext.data(using: .utf8) else {
            print("明文数据转换失败")
            return nil
        }
        
        let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
        
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            print("算法不支持")
            return nil
        }
        
        var encryptError: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, algorithm, plainData as CFData, &encryptError) as Data? else {
            print("加密失败: \(encryptError?.takeRetainedValue().localizedDescription ?? "未知错误")")
            return nil
        }
        
        return encryptedData.base64EncodedString()
    }
    
    private func encryptSecretWithRSA(_ secret: String) -> String? {
        do {
            // 1. 从 UserDefaults 获取加密的公钥
            let encryptedPubKey = getPreference("pubKey")
            
            if encryptedPubKey.isEmpty {
                print("公钥不存在")
                return nil
            }
            
            // 2. 使用 AES 解密公钥
            guard let decryptedPubKey = decryptAESCBC(encryptedPubKey, key: AES_KEY, iv: AES_IV) else {
                print("AES 解密公钥失败")
                return nil
            }
            
            // 3. 获取设备 UUID 和时间戳
            let deviceUUID = UIDevice.current.identifierForVendor?.uuidString ?? ""
            let timestamp = Int64(Date().timeIntervalSince1970)
            
            // 4. 构造加密字符串：Device.uuid + "##" + secret + "##" + timestamp
            let combinedString = "\(deviceUUID)##\(secret)##\(timestamp)"
            
            // 5. 使用 RSA 加密
            guard let rsaEncryptedSecret = encryptWithRSA(combinedString, publicKeyStr: decryptedPubKey) else {
                print("RSA 加密失败")
                return nil
            }
            
            return rsaEncryptedSecret
            
        } catch {
            print("RSA 加密异常: \(error)")
            return nil
        }
    }
    
    // MARK: - 存储工具方法（替代 StorageUtil）
    
    private func savePreference(_ key: String, value: String) {
        UserDefaults.standard.set(value, forKey: key)
        UserDefaults.standard.synchronize()
    }
    
    private func getPreference(_ key: String) -> String {
        return UserDefaults.standard.string(forKey: key) ?? ""
    }
    
    // MARK: - AES CBC 加解密方法（替代 AESUtil）
    
    private func encryptAESCBC(_ plaintext: String, key: String, iv: String) -> String? {
        guard let plainData = plaintext.data(using: .utf8),
              let keyData = key.data(using: .utf8) else {
            return nil
        }
        
        var ivData = iv.data(using: .utf8) ?? keyData
        
        // 确保IV长度为16字节
        if ivData.count < 16 {
            ivData = padData(ivData, toLength: 16)
        } else if ivData.count > 16 {
            ivData = ivData.subdata(in: 0..<16)
        }
        
        // 加密
        var encryptedBytes = [UInt8](repeating: 0, count: plainData.count + kCCBlockSizeAES128)
        var encryptedLength: Int = 0
        
        let cryptStatus = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            Array(keyData),
            kCCKeySizeAES128,
            Array(ivData),
            Array(plainData),
            plainData.count,
            &encryptedBytes,
            encryptedBytes.count,
            &encryptedLength
        )
        
        if cryptStatus == kCCSuccess {
            let encryptedData = Data(bytes: encryptedBytes, count: encryptedLength)
            return encryptedData.base64EncodedString()
        }
        
        return nil
    }
    
    private func decryptAESCBC(_ encryptedBase64: String, key: String, iv: String) -> String? {
        guard let encryptedData = Data(base64Encoded: encryptedBase64),
              let keyData = key.data(using: .utf8) else {
            return nil
        }
        
        var ivData = iv.data(using: .utf8) ?? keyData
        
        // 确保IV长度为16字节
        if ivData.count < 16 {
            ivData = padData(ivData, toLength: 16)
        } else if ivData.count > 16 {
            ivData = ivData.subdata(in: 0..<16)
        }
        
        // 解密
        var decryptedBytes = [UInt8](repeating: 0, count: encryptedData.count + kCCBlockSizeAES128)
        var decryptedLength: Int = 0
        
        let cryptStatus = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            Array(keyData),
            kCCKeySizeAES128,
            Array(ivData),
            Array(encryptedData),
            encryptedData.count,
            &decryptedBytes,
            decryptedBytes.count,
            &decryptedLength
        )
        
        if cryptStatus == kCCSuccess {
            let decryptedData = Data(bytes: decryptedBytes, count: decryptedLength)
            return String(data: decryptedData, encoding: .utf8)
        }
        
        return nil
    }
    
    private func padData(_ data: Data, toLength length: Int) -> Data {
        var paddedData = data
        if paddedData.count < length {
            paddedData.append(contentsOf: [UInt8](repeating: 0, count: length - paddedData.count))
        }
        return paddedData
    }
    
    // MARK: - MD5 计算方法（如果需要）
    
    private func md5(_ input: String) -> String {
        let data = Data(input.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        
        data.withUnsafeBytes {
            _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &digest)
        }
        
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
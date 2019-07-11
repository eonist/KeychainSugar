import Security
import Foundation
/**
 * - Note: Examples here: https://gist.github.com/s-aska/e7ad24175fb7b04f78e7
 */
public class KeyChainParser {
   /**
    * Returns a keychain item for PARAM: key
    * - EXAMPLE: KeyChainParser.load("eonist")?.stringValue//123abc
    * - NOTE: SecClass: kSecClassInternetPassword,kSecClassGenericPassword,kSecClassCertificate,kSecClassKey,kSecClassIdentity
    */
   public static func load(_ key: String, _ secClass: CFString = kSecClassGenericPassword) -> Data? {
      let query: CFDictionary = [
         kSecClass as String: secClass,
         kSecAttrAccount as String: key,
         kSecReturnData as String: kCFBooleanTrue!,
         kSecMatchLimit as String: kSecMatchLimitOne
      ] as CFDictionary
      //Swift.print("query: " + "\(query)")
      var dataTypeRef: AnyObject?
      let status = withUnsafeMutablePointer(to: &dataTypeRef) { SecItemCopyMatching(query, UnsafeMutablePointer($0)) }
      //Swift.print("status: " + "\(status)")
      if status == errSecSuccess {
         return dataTypeRef as? Data
      }
      return nil
   }
}
public class KeyChainUtils {
   /**
    * Convenience method
    */
   public static func dataValue(_ string: String) -> Data {
      return string.data(using: .utf8, allowLossyConversion: false)!
      //return string.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
   }
   /**
    * Convenience method
    */
   public static func stringValue(_ data: Data) -> String {
      return NSString(data: data, encoding: String.Encoding.utf8.rawValue)! as String
   }
}
extension String {
   public var dataValue: Data {/*Convenience method*/
      return KeyChainUtils.dataValue(self)
   }
}
extension KeyChainParser {
   /**
    * Returns password for PARAM: accountName
    * ## EXAMPLE:
    * KeyChainParser.password("eonist")//123abc
    * - NOTE: this methods exists because of: convenience and clearity of code
    */
   public static func password(_ accountName: String) -> String? {
      guard let data = KeyChainParser.load(accountName) else { return nil }
      return  String(data: data, encoding: .utf8)
   }
}
//extension Data {
//    public var stringValue: String {/*Convenience method*/
//        return KeyChainUtils.stringValue(self)
//    }
//}

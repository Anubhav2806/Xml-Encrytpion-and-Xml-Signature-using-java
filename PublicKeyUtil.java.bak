import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PublicKeyUtil{

 /**
  * Generates KeyPair specific to given algorithm
  * 
  * @param algorithm
  * @return
  * @throws NoSuchAlgorithmException
  */
 public static KeyPair getKeyPair(String algorithm)
   throws NoSuchAlgorithmException {
  KeyPairGenerator keyPairGenerator = KeyPairGenerator
    .getInstance(algorithm);
  return keyPairGenerator.generateKeyPair();
 }

 /**
  * Return PublicKey from given KeyPair
  * 
  * @param keyPair
  * @return
  */
 public static PublicKey getPublicKey(KeyPair keyPair) {
  return keyPair.getPublic();
 }

 /**
  * Return PrivateKey from given KeyPair
  * 
  * @param keyPair
  * @return
  */
 public static PrivateKey getPrivateKey(KeyPair keyPair) {
  return keyPair.getPrivate();
 }

 /**
  * Convert key to string.
  * 
  * @param key
  * 
  * @return String representation of key
  */
 public static String keyToString(Key key) {
  /* Get key in encoding format */
  byte encoded[] = key.getEncoded();

  /*
   * Encodes the specified byte array into a String using Base64 encoding
   * scheme
   */
  String encodedKey = Base64.getEncoder().encodeToString(encoded);

  return encodedKey;
 }

 /**
  * Save key to a file
  * 
  * @param key
  *            : key to save into file
  * @param fileName
  *            : File name to store
  */
 public static void saveKey(Key key, String fileName) {
  byte[] keyBytes = key.getEncoded();
  File keyFile = new File(fileName);
  FileOutputStream fOutStream = null;
  try {
   fOutStream = new FileOutputStream(keyFile);
   fOutStream.write(keyBytes);
  } catch (Exception e) {
   e.printStackTrace();
  } finally {
   if (fOutStream != null) {
    try {
     fOutStream.close();
    } catch (IOException e) {
     e.printStackTrace();
    }
   }
  }
 }

 /**
  * Returns the key stored in a file.
  * 
  * @param fileName
  * @return
  * @throws Exception
  */
 public static byte[] readKeyFromFile(String fileName) throws Exception {
  FileInputStream keyfis = new FileInputStream(fileName);
  byte[] key = new byte[keyfis.available()];
  keyfis.read(key);
  keyfis.close();
  return key;
 }

 /**
  * Generates public key from encoded byte array.
  * 
  * @param encoded
  * @param algorithm
  * @return
  * @throws Exception
  */
 public static PublicKey convertArrayToPubKey(byte encoded[],
   String algorithm) throws Exception {
  X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
  KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
  PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

  return pubKey;
 }

 /**
  * Generates private key from encoded byte array.
  * 
  * @param encoded
  * @param algorithm
  * @return
  * @throws Exception
  */
 public static PrivateKey convertArrayToPriKey(byte encoded[],
   String algorithm) throws Exception {
  PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
  KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
  PrivateKey priKey = keyFactory.generatePrivate(keySpec);
  return priKey;
 }

}
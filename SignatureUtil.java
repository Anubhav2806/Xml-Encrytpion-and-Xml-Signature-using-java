import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.Signature;

public class SignatureUtil {

 /**
  * Generates signature by taking file, PrivateKey and algorithm as input.
  * 
  * @param fileName
  *            : Generate signature for this file.
  * @param privateKey
  * @param algorithm
  * @return
  * @throws Exception
  */
 public static byte[] getSignature(String fileName, PrivateKey privateKey,
   String algorithm) throws Exception {

  /* Get instance of Signature object */
  Signature signature = Signature.getInstance(algorithm);

  /* Initialize Signature object */
  signature.initSign(privateKey);

  /* Feed data */
  feedData(signature, fileName);

  /* Generate signature */
  byte[] finalSig = signature.sign();

  return finalSig;
 }

 /**
  * Save signature to a file
  * 
  * @param fileName
  *            : Signature saved here
  * @param signature
  * @throws Exception
  */
 public static void saveSignature(String fileName, byte[] signature)
   throws Exception {
  FileOutputStream sigfos = new FileOutputStream(fileName);
  sigfos.write(signature);
  sigfos.close();
 }

 /**
  * Read signature from a file and convert it into byte array.
  * 
  * @param fileName
  *            : contains signature information
  * @return signature as byte array
  * @throws Exception
  */
 public static byte[] readSignatureFromFile(String fileName)
   throws Exception {
  return PublicKeyUtil.readKeyFromFile(fileName);
 }

 /**
  * Feed data to Signature instance
  * 
  * @param signature
  * @param fileName
  * @throws Exception
  */
 public static void feedData(Signature signature, String fileName)
   throws Exception {
  /* Supply the Signature Object the Data to Be Signed */
  FileInputStream fis = new FileInputStream(fileName);
  BufferedInputStream bufin = new BufferedInputStream(fis);
  byte[] buffer = new byte[1024];
  int len;
  while ((len = bufin.read(buffer)) >= 0) {
   signature.update(buffer, 0, len);
  }
  bufin.close();
 }

}
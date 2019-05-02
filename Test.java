import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;



class SecretKeyUtil {

 /**
  * Generate secret key for given algorithm
  * Generate secret key specific to this algorithm
  * return SecretKey
  */
 public static SecretKey getSecretKey(String algorithm) {
  KeyGenerator keyGenerator = null;
  try {
   keyGenerator = KeyGenerator.getInstance(algorithm);
  } catch (NoSuchAlgorithmException e) {
   e.printStackTrace();
  }
  return keyGenerator.generateKey();
 }

 /**
  * Convert secret key to string.
  * param secretKey
  * String representation of secret key
  */
 public static String keyToString(SecretKey secretKey) {
  /* Get key in encoding format */
  byte encoded[] = secretKey.getEncoded();

  /*
   * Encodes the specified byte array into a String using Base64 encoding
   * scheme
   */
  String encodedKey = Base64.getEncoder().encodeToString(encoded);

  return encodedKey;
 }

 /**
  * Save secret key to a file
  * Secret key to save into file
  * File name to store
  */
 public static void saveSecretKey(SecretKey secretKey, String fileName) {
  byte[] keyBytes = secretKey.getEncoded();
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
}

class XMLUtil {

 static {
  org.apache.xml.security.Init.init();
 }

 /**
  * Return DOM Document object for given xml file
  * 
  * @param xmlFile
  * @return
  * @throws Exception
  */
 public static Document getDocument(String xmlFile) throws Exception {
  /* Get the instance of BuilderFactory class. */
  DocumentBuilderFactory builder = DocumentBuilderFactory.newInstance();

  /* Instantiate DocumentBuilder object. */
  DocumentBuilder docBuilder = builder.newDocumentBuilder();

  /* Get the Document object */
  Document document = docBuilder.parse(xmlFile);
  return document;
 }

 /**
  * Save document to a file
  */
 public static void saveDocumentTo(Document document, String fileName)
   throws Exception {
  File encryptionFile = new File(fileName);
  FileOutputStream fOutStream = new FileOutputStream(encryptionFile);

  TransformerFactory factory = TransformerFactory.newInstance();
  Transformer transformer = factory.newTransformer();
  transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
  DOMSource source = new DOMSource(document);
  StreamResult result = new StreamResult(fOutStream);
  transformer.transform(source, result);

  fOutStream.close();
 }

 /**
  * Encrypt document with given algorithm and secret key.
  * 
  * @param document
  * @param secretKey
  * @param algorithm
  * @return
  * @throws Exception
  */
 public static Document encryptDocument(Document document,
   SecretKey secretKey, String algorithm) throws Exception {
  /* Get Document root element */
  Element rootElement = document.getDocumentElement();
  String algorithmURI = algorithm;
  XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
  NodeList N=rootElement.getChildNodes();
  	Node tobe=N.item(1);
  	System.out.println("encrypting "+ tobe.getNodeName());

  
  
  /* Initialize cipher with given secret key and operational mode */
  xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
  
  /* Process the contents of document */
  Element ee=(Element)tobe;
  xmlCipher.doFinal(document, ee);
  return document;
 }

 /**
  * Decrypt document using given key and algorithm
  */
 public static Document decryptDocument(Document document,
   SecretKey secretKey, String algorithm) throws Exception {
  Element encryptedDataElement = (Element) document
    .getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
      EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

  XMLCipher xmlCipher = XMLCipher.getInstance();

  xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
  xmlCipher.doFinal(document, encryptedDataElement);
  return document;
 }
}

public class Test {
 public static void main(String args[]) throws Exception {
  String xmlFile = "bookstore.xml";
  String encryptedFile = "encrypted.xml";
  String decryptedFile = "decrypted.xml";

  SecretKey secretKey = SecretKeyUtil.getSecretKey("AES");
  Document document = XMLUtil.getDocument(xmlFile);

  Document encryptedDoc = XMLUtil.encryptDocument(document, secretKey,
    XMLCipher.AES_128);
  XMLUtil.saveDocumentTo(encryptedDoc, encryptedFile);

  Document decryptedDoc = XMLUtil.decryptDocument(encryptedDoc,
    secretKey, XMLCipher.AES_128);
  XMLUtil.saveDocumentTo(decryptedDoc, decryptedFile);

  System.out.println("Done");
 }
}

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
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator.*;
import javax.crypto.*;
import java.util.*;
import java.io.*;
import javax.crypto.Cipher.*;
import java.nio.charset.Charset;
import javax.crypto.spec.IvParameterSpec;
public class signme{
	public static void main(String []args)throws Exception{
        DocumentBuilderFactory builder = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = builder.newDocumentBuilder();
        Document doc = docBuilder.parse("bookstore.xml");
        org.apache.xml.security.Init.init();
        Element canonElem =XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS( null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS );
        SignatureAlgorithm signatureAlgorithm =new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1); 
        XMLSignature sig = new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);
       // System.out.println(sig.getTagName());
        Element root = doc.getDocumentElement();
        root.appendChild(sig.getElement());
        KeyPairGenerator k=KeyPairGenerator.getInstance("RSA");
        KeyPair key=k.generateKeyPair();
        PrivateKey pk=key.getPrivate();
        PublicKey pub=key.getPublic();
        sig.addKeyInfo(pub);
        sig.sign(pk);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
  		Transformer transformer = transformerFactory.newTransformer();
  		DOMSource source = new DOMSource(doc);
  		StreamResult streamResult =  new StreamResult(System.out);
  		transformer.transform(source, streamResult);
           

		   
	}
}
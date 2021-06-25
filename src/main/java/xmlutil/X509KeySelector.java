package xmlutil;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

public class X509KeySelector extends KeySelector {

	public KeySelectorResult select(
	  KeyInfo          keyInfo,
    Purpose          purpose,
    AlgorithmMethod  method,
		XMLCryptoContext context) throws KeySelectorException
  {

    //Find <X509Data> inside <KeyInfo>
		Iterator keyInfoIterator = keyInfo.getContent().iterator();
		while (keyInfoIterator.hasNext()) {
      XMLStructure info = (XMLStructure) keyInfoIterator.next();
      if (info instanceof X509Data) {
        //Find <X509Certificate> inside <X509Data>
        X509Data x509Data         = (X509Data) info;
        Iterator x509DataIterator = x509Data.getContent().iterator();
        while (x509DataIterator.hasNext()) {
          Object object = x509DataIterator.next();
          if (object instanceof X509Certificate) {
            X509Certificate x509Certificate = (X509Certificate) object;
            PublicKey       publicKey       = x509Certificate.getPublicKey();
            return new SimpleKeySelectorResult(publicKey);
          }
        }
      }
    }

    //THROW EXCEPTION
		throw new KeySelectorException("No key found!");

	}

}

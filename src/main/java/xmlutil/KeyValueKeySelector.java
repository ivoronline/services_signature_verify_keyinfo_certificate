package xmlutil;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import java.security.KeyException;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.List;

//This Class is used when validating with <KeyInfo>
public class KeyValueKeySelector extends KeySelector {

  public KeySelectorResult select(
    KeyInfo          keyInfo,
    Purpose          purpose,
    AlgorithmMethod  method,
    XMLCryptoContext context) throws KeySelectorException
  {

    //Find <KeyValue> inside <KeyInfo>
    try {
      Iterator keyInfoIterator = keyInfo.getContent().iterator();
      while (keyInfoIterator.hasNext()) {
        XMLStructure xmlStructure = (XMLStructure) keyInfoIterator.next();;
        if (xmlStructure instanceof KeyValue) {
          KeyValue  keyValue  = (KeyValue) xmlStructure;
          PublicKey publicKey = keyValue.getPublicKey();
          return new SimpleKeySelectorResult(publicKey);
        }
      }
    }
    catch (KeyException ke) { throw new KeySelectorException(ke); }

    //THROW EXCEPTION
		throw new KeySelectorException("No key found!");

  }

}
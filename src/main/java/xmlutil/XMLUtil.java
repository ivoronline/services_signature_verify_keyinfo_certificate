package xmlutil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;

public class XMLUtil {

  //================================================================================
  // READ XML FROM FILE
  //================================================================================
  // Document document = readXMLFromFile(fileXMLInput);
  public static Document readXMLFromFile(String fileName) throws Exception {

    //READ DOCUMENT FROM FILE
    DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
                           documentFactory.setNamespaceAware(true);
    InputStream            inputStream     = XMLUtil.class.getResourceAsStream(fileName);
    Document               document        = documentFactory.newDocumentBuilder().parse(inputStream);

    //RETURN DOCUMENT
    return document;

  }

  //================================================================================
  // VALIDATE SIGNATURE USING KEY INFO
  //================================================================================
  // boolean valid = XMLUtil.validateSignatureUsingKeyinfo(document, "Person");
  public static boolean validateSignatureUsingKeyinfo(Document document) throws Exception  {

    //VALIDATE SIGNATURE USING KeyValue FROM <KeyInfo>
    Node                signatureNode = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
    DOMValidateContext  valContext    = new DOMValidateContext(new X509KeySelector(), signatureNode);
                        valContext.setIdAttributeNS((Element) signatureNode.getParentNode(),null,"Id"); //FIX
    XMLSignatureFactory factory       = XMLSignatureFactory.getInstance("DOM");
    XMLSignature        signature     = factory.unmarshalXMLSignature(valContext);
    boolean             valid         = signature.validate(valContext);

    //RETURN RESULT
    return valid;

  }

}

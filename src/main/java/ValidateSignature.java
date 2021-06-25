import org.w3c.dom.Document;
import xmlutil.XMLUtil;

public class ValidateSignature {

  static String fileXMLInput1 = "/PersonSignedKey.xml";
  static String fileXMLInput2 = "/PersonSignedWithKeyInfo.xml";
  static String fileXMLInput3 = "/PersonSignedCertificate.xml";

  //================================================================================
  // MAIN
  //================================================================================
  public static void main(String[] args) throws Exception {
    Document document = XMLUtil.readXMLFromFile(fileXMLInput3);
    boolean  valid    = XMLUtil.validateSignatureUsingKeyinfo(document);
    System.out.println(valid);
  }

}

	public void validateXml() throws Exception {
		Security.addProvider(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		java.io.ByteArrayInputStream vb = new java.io.ByteArrayInputStream(
				Files.readAllBytes(new File("SignedFile.xml").toPath()));

		Document doc2 = dbf.newDocumentBuilder().parse(vb);
		NodeList nl = doc2.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0) {
			throw new Exception("Cannot find Signature element");
		}

		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", java.security.Security.getProvider("XMLDSig"));

		// Unmarshal the XMLSignature.

		// Create a DOMValidateContext and specify a KeySelector and document context.
		DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));

		XMLSignature signature = fac.unmarshalXMLSignature(valContext);

		// Validate the XMLSignature.
		boolean coreValidity = signature.validate(valContext);

		// Check core validation status.
		if (coreValidity == false) {
			String validateError;
			validateError = "Signature core validation status:false";
			boolean sv = signature.getSignatureValue().validate(valContext);
			validateError = validateError + " | Signature validation status:" + sv;
			if (sv == false || true) {
				validateError = validateError + " | References: ";
				// Check the validation status of each Reference.
				@SuppressWarnings("rawtypes")
				Iterator g = signature.getSignedInfo().getReferences().iterator();
				while (g.hasNext()) {
					Reference r = (Reference) g.next();
					boolean refValid = r.validate(valContext);
					validateError = validateError + "{ref[" + r.getURI() + "] validity status: " + refValid + "}";
				}
			}
			throw new Exception(validateError);
		} else {
			System.out.println("Signature passed core validation");
		}

	}

	public static void main(String[] args) throws Exception {
		XmlSigningAndValidate xmlSigningAndValidate = new XmlSigningAndValidate();
		xmlSigningAndValidate.signXml();
		xmlSigningAndValidate.validateXml();
	}

}

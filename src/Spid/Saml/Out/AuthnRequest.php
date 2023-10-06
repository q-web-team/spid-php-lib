<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Interfaces\RequestInterface;
use Italia\Spid\Spid\Saml\Settings;
use Italia\Spid\Spid\Saml\SignatureUtils;

class AuthnRequest extends Base implements RequestInterface
{
    public function generateXml()
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $entityId = $this->idp->sp->settings['sp_entityid'];

        $idpEntityId = $this->idp->metadata['idpEntityId'];
        $assertID = $this->idp->assertID;
        $assertID = 3;
        $attrID = $this->idp->attrID;
       
        $level = $this->idp->level;
        $force = $level > 1 ? "true" : "false";
        
        $authnRequestXml = <<<XML
<saml2p:AuthnRequest 
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="$id" 
    Version="2.0"
    IssueInstant="$issueInstant"
    Destination="$idpEntityId"
    ForceAuthn="$force"
   AssertionConsumerServiceIndex="1" 
AttributeConsumingServiceIndex="1"
    >
    <saml2:Issuer
        xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" 
	    Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        NameQualifier="https://login.comune.cittadella.pd.it/spid">https://login.comune.cittadella.pd.it/spid</saml2:Issuer>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://www.spid.gov.it/SpidL$level</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>
XML;

        $xml = new \SimpleXMLElement($authnRequestXml);

        if (!is_null($attrID)) {
            $xml->addAttribute('AttributeConsumingServiceIndex', $attrID);
        }
        $this->xml = $xml->asXML();
    }
    
     public function generateXmlCIE()
    {
       
        $id = $this->generateID();
        
        $issueInstant = $this->generateIssueInstant();
        $entityId = $this->idp->sp->settings['sp_entityid'];

        $idpEntityId = $this->idp->metadata['idpEntityId'];
        $assertID = $this->idp->assertID;
        // 1 se Qweb è fornitore
        $assertID = 1;
        $attrID = $this->idp->attrID;
       
        $level = 3;
        $force = $level > 1 ? "true" : "false";
        
        $authnRequestXml = <<<XML
<saml2p:AuthnRequest 
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" 
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" 
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
    ID="$id" 
    Version="2.0"
    IssueInstant="$issueInstant"
    Destination="https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO"
    ForceAuthn="$force"
   AssertionConsumerServiceIndex="$assertID" 
AttributeConsumingServiceIndex="$assertID"
    >
    <saml2:Issuer
       
	    Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        NameQualifier="https://login.comune.cittadella.pd.it/spid"
        >https://login.comune.cittadella.pd.it/spid</saml2:Issuer>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL$level</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>
XML;

        $xml = new \SimpleXMLElement($authnRequestXml);

        if (!is_null($attrID)) {
            $xml->addAttribute('AttributeConsumingServiceIndex', $attrID);
        }
        $this->xml = $xml->asXML();
    }

    public function redirectUrl($redirectTo = null) : string
    {
           if($this->idp->idpFileName!='cie')
           {
            $location = parent::getBindingLocation(Settings::BINDING_REDIRECT);
            if (is_null($this->xml)) {$this->generateXml();}
                $this->xml = SignatureUtils::signXml($this->xml, $this->idp->sp->settings);
                return parent::redirect($location, $redirectTo);
            }
            else{
                 $location = "https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO";
                 $this->generateXmlCIE();
                 $this->xml = SignatureUtils::signXml($this->xml, $this->idp->sp->settings);
                 return parent::postFormCIE($location, $redirectTo);
            }
        
        
    }

    public function httpPost($redirectTo = null) : string
    {
       if($this->idp->idpFileName!='cie')
           {
            $location = parent::getBindingLocation(Settings::BINDING_REDIRECT);
            if (is_null($this->xml)) {$this->generateXml();}
            }
            else{
           
                 $location = "https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO";
                if (is_null($this->xml)) {$this->generateXml();}
                 $this->generateXmlCIE();
            }
        $this->xml = SignatureUtils::signXml($this->xml, $this->idp->sp->settings);
        return parent::postForm($location, $redirectTo);
    }
}

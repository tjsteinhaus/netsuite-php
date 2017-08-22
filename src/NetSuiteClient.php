<?php
/**
 * This file is part of the SevenShores/NetSuite library.
 *
 * @package    ryanwinchester/netsuite-php
 * @author     Ryan Winchester <fungku@gmail.com>
 * @copyright  Copyright (c) Ryan Winchester
 * @license    http://www.apache.org/licenses/LICENSE-2.0 Apache-2.0
 * @link       https://github.com/ryanwinchester/netsuite-php
 * created:    2015-01-22  1:04 PM
 */

namespace NetSuite;

use NetSuite\Classes\ApplicationInfo;
use NetSuite\Classes\Passport;
use NetSuite\Classes\Preferences;
use NetSuite\Classes\RecordRef;
use NetSuite\Classes\SearchPreferences;
use NetSuite\Classes\TokenPassport;
use NetSuite\Classes\TokenPassportSignature;
use SoapClient;
use SoapHeader;

class NetSuiteClient
{
	private $nsversion = null;

    public $client = null;
    public $passport = null;
    public $applicationInfo = null;
    public $tokenPassport = null;
    private $soapHeaders = array();
    private $userequest = true;
    private $usetba = false;
    protected $classmap = null;
    public $generated_from_endpoint = "";
    protected $tokenGenerator = null;


    protected function __construct($wsdl=null, $options=array()) {

        if (!isset($wsdl)) {
             if (!defined('NS_HOST')) {
                throw new Exception('Webservice host must be specified');
             }
             if (!defined('NS_ENDPOINT')) {
                throw new Exception('Webservice endpoint must be specified');
             }
             $wsdl = NS_HOST . "/wsdl/v" . NS_ENDPOINT . "_0/netsuite.wsdl";
             $nsversion = NS_ENDPOINT;
        }

        if (!extension_loaded('soap')) {
            // check for loaded SOAP extension
            $soap_warning = 'The SOAP PHP extension is not loaded. Please modify the extension settings in php.ini accordingly.';
            trigger_error($soap_warning, E_USER_WARNING);
        }

        if (!extension_loaded('openssl') && substr($wsdl, 0, 5) == "https") {
            // check for loaded SOAP extension
            $soap_warning = 'The Open SSL PHP extension is not loaded and you are trying to use HTTPS protocol. Please modify the extension settings in php.ini accordingly.';
            trigger_error($soap_warning, E_USER_WARNING);
        }

        if ( $this->generated_from_endpoint != NS_ENDPOINT ) {
            // check for the endpoint compatibility failed, but it might still be compatible. Issue only warning
            $endpoint_warning = 'The NetSuiteService classes were generated from the '.$this->generated_from_endpoint .' endpoint but you are running against ' . NS_ENDPOINT;
            trigger_error($endpoint_warning, E_USER_WARNING);
        }

        $options['classmap'] = $this->classmap;
        $options['trace'] = 1;
        $options['connection_timeout'] = 5;
        $options['cache_wsdl'] = WSDL_CACHE_BOTH;
        $httpheaders = "PHP-SOAP/" . phpversion() . " + NetSuite PHP Toolkit " . $this->nsversion;

        if (defined('NS_HOST') && defined('NS_ENDPOINT')) {
            $options['location'] = NS_HOST . "/services/NetSuitePort_" . NS_ENDPOINT;
        }
        $options['keep_alive'] = false; // do not maintain http connection to the server.
        $options['features'] = SOAP_SINGLE_ELEMENT_ARRAYS;

        $context = array('http' =>
            array(
                'header' => 'Authorization: dnwdjewdnwe'
            )
        );
        //$options['stream_context'] = stream_context_create($context);

        $options['user_agent'] =  $httpheaders;
        if (defined('NS_ACCOUNT') && defined('NS_EMAIL') && defined('NS_PASSWORD')) {
            $this->setPassport(NS_ACCOUNT, NS_EMAIL, defined('NS_ROLE')?NS_ROLE:null, NS_PASSWORD);
        }
        if (defined('NS_APPID')) {
            $this->setApplicationInfo(NS_APPID);
        }
        $this->client = new SoapClient($wsdl, $options);
    }

    public function setPassport($nsaccount, $nsemail, $nsrole, $nspassword) {
        $this->passport = new Passport();
        $this->passport->account = $nsaccount;
        $this->passport->email = $nsemail;
        $this->passport->password = $nspassword;
        if (isset($nsrole)) {
            $this->passport->role = new RecordRef();
            $this->passport->role->internalId = $nsrole;
        }
    }


    public function setApplicationInfo($nsappid) {
        $this->applicationInfo = new ApplicationInfo();
        $this->applicationInfo->applicationId = $nsappid;
        $this->addHeader("applicationInfo", $this->applicationInfo);
    }

    protected function setTokenPassport($tokenPassport) {
        $this->tokenPassport = $tokenPassport;
    }

    public function useRequestLevelCredentials($option) {
         $this->userequest = $option;
    }

    public function setPreferences ($warningAsError = false, $disableMandatoryCustomFieldValidation = false, $disableSystemNotesForCustomFields = false,  $ignoreReadOnlyFields = false, $runServerSuiteScriptAndTriggerWorkflows = null)
    {
        $sp = new Preferences();
        $sp->warningAsError = $warningAsError;
        $sp->disableMandatoryCustomFieldValidation = $disableMandatoryCustomFieldValidation;
        $sp->disableSystemNotesForCustomFields = $disableSystemNotesForCustomFields;
        $sp->ignoreReadOnlyFields = $ignoreReadOnlyFields;
        $sp->runServerSuiteScriptAndTriggerWorkflows = $runServerSuiteScriptAndTriggerWorkflows;

        $this->addHeader("preferences", $sp);
    }

    public function clearPreferences() {
        $this->clearHeader("preferences");
    }

    public function setSearchPreferences ($bodyFieldsOnly = true, $pageSize = 50, $returnSearchColumns = true)
    {
        $sp = new SearchPreferences();
        $sp->bodyFieldsOnly = $bodyFieldsOnly;
        $sp->pageSize = $pageSize;
        $sp->returnSearchColumns = $returnSearchColumns;

        $this->addHeader("searchPreferences", $sp);
    }

    public function clearSearchPreferences() {
        $this->clearHeader("searchPreferences");
    }

    public function addHeader($header_name, $header) {
        $this->soapHeaders[$header_name] = new SoapHeader("ns", $header_name, $header);
    }
    public function clearHeader($header_name) {
        unset($this->soapHeaders[$header_name]);
    }

    protected function makeSoapCall($operation, $parameter) {
        if ($this->userequest) {
            // use request level credentials, add passport as a SOAP header
            $this->clearHeader("tokenPassport");
            $this->addHeader("passport", $this->passport);
            $this->addHeader("applicationInfo", $this->applicationInfo);
            // SoapClient, even with keep-alive set to false, keeps sending the JSESSIONID cookie back to the server on subsequent requests. Unsetting the cookie to prevent this.
            $this->client->__setCookie("JSESSIONID");
        } else if ($this->usetba) {
            if (isset($this->tokenGenerator)) {
                $token = $this->tokenGenerator->generateTokenPassport();
                $this->setTokenPassport($token);
            }
            $this->addHeader("tokenPassport", $this->tokenPassport);
            $this->clearHeader("passport");
            $this->clearHeader("applicationInfo");
        } else {
            $this->clearHeader("passport");
            $this->clearHeader("tokenPassport");
            $this->addHeader("applicationInfo", $this->applicationInfo);
        }

        $response = $this->client->__soapCall($operation, array($parameter), NULL, $this->soapHeaders);

        if ( file_exists(dirname(__FILE__) . '/nslog') ) {
            // log the request and response into the nslog directory. Code taken from PHP toolkit
            // REQUEST
            $req = dirname(__FILE__) . '/nslog' . "/" . date("Ymd.His") . "." . milliseconds() . "-" . $operation . "-request.xml";
            $Handle = fopen($req, 'w');
            $Data = $this->client->__getLastRequest();

            $Data = cleanUpNamespaces($Data);

            $xml = simplexml_load_string($Data, 'SimpleXMLElement', LIBXML_NOCDATA);

            $passwordFields = $xml->xpath("//password | //password2 | //currentPassword | //newPassword | //newPassword2 | //ccNumber | //ccSecurityCode | //socialSecurityNumber");

            foreach ($passwordFields as &$pwdField) {
                (string)$pwdField[0] = "[Content Removed for Security Reasons]";
            }

            $stringCustomFields = $xml->xpath("//customField[@xsitype='StringCustomFieldRef']");

            foreach ($stringCustomFields as $field) {
                (string)$field->value = "[Content Removed for Security Reasons]";
            }

            $xml_string = str_replace('xsitype', 'xsi:type', $xml->asXML());

            fwrite($Handle, $xml_string);
            fclose($Handle);

            // RESPONSE
            $resp = dirname(__FILE__) . '/nslog' . "/" . date("Ymd.His") . "." . milliseconds() . "-" . $operation . "-response.xml";
            $Handle = fopen($resp, 'w');
            $Data = $this->client->__getLastResponse();
            fwrite($Handle, $Data);
            fclose($Handle);

        }

        return $response;

    }

    public function setHost($hostName) {
        return $this->client->__setLocation($hostName . "/services/NetSuitePort_" . NS_ENDPOINT);
    }

    public function setTokenGenerator(iTokenPassportGenerator $generator = null) {
        $this->tokenGenerator = $generator;
        if ($generator != null) {
          $this->usetba = true;
          $this->userequest = false;
        } else {
          $this->usetba = false;
        }
    }
}

/**
 * iTokenPassportGenerator
 */
interface iTokenPassportGenerator {
    /**
     * returns one time Token Passport
     */
    public function generateTokenPassport();
}

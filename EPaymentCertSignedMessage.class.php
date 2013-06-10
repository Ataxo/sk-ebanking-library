<?php
/*
    Copyright 2012 Ataxo Interactive a.s.
*/
require_once dirname(__FILE__).'/EPaymentMessage.class.php';
use Nette\Diagnostics\Debugger;
abstract class EPaymentCertSignedMessage extends EPaymentMessage {
    protected $merchantKey;//private merchant key 
    protected $bankKey;//public bank key
    protected $fields;
    public function __construct($merchantKeyLink,$bankKeyLink) {
        if(!file_exists($merchantKeyLink))
            throw new \Nette\FileNotFoundException('File with merchant key was not found on: '.$merchantKeyLink);
        if(!file_exists($bankKeyLink))
            throw new \Nette\FileNotFoundException('File with bank key was not found on: '.$bankKeyLink);
        
        $fp = fopen($merchantKeyLink, "r");
        $this->merchantKey = fread($fp, filesize($merchantKeyLink));
        fclose($fp);
        
        $fp = fopen($bankKeyLink, "r");
        $this->bankKey = fread($fp, filesize($bankKeyLink));
        fclose($fp);
    }
    public function computeSign($string, $secret) {
        if (!$this->isValid)
            throw new Exception(__METHOD__.": Message was not validated.");
        try {
            $pkeyid = openssl_get_privatekey($this->merchantKey, $secret);
            openssl_sign($string, $sign, $pkeyid);
            $sign = base64_encode($sign);
            openssl_free_key($pkeyid);
            return $sign;
        } catch (Exception $e) {
            return false;
        }
    }
    public function validateBankSign($signBase,$sign) {
        if (!$this->isValid)
            throw new Exception(__METHOD__.": Message was not validated.");
        try {
            $pubkeyid = openssl_get_publickey($this->bankKey);
            $sign = base64_decode($sign);
            $result = openssl_verify($signBase, $sign, $pubkeyid);
            openssl_free_key($pubkeyid);
            return (($result==1) ? true : false);
        } catch (Exception $e) {
            Debugger::log($e,Debugger::ERROR);
            return false;
        }
    }
}
<?php
/*
	Copyright 2012 Ataxo Interactive a.s.
*/
class MuzoPaymentRequest extends EPaymentCertSignedMessage implements IEPaymentHttpRedirectPaymentRequest {
    const Muzo_EPayment_URL_Base = "https://3dsecure.gpwebpay.com";
    private $redirectUrlBase = self::Muzo_EPayment_URL_Base;
    private $provider;

    public function SetRedirectUrlBase($url) {
        $this->redirectUrlBase = $url;
    }

    public function __construct($merchantKeyLink, $bankKeyLink) {
        parent::__construct($merchantKeyLink, $bankKeyLink);
        $this->readOnlyFields = array('DIGEST','DIGEST1');
        $this->requiredFields = array('OPERATION', 'MERCHANTNUMBER', 'ORDERNUMBER', 'AMOUNT', 'CURRENCY', 'DEPOSITFLAG', 'URL');
        $this->optionalFields = array('MERORDERNUM', 'DESCRIPTION', 'MD');

        $this->provider = 'rb';
    }

    public function getSignatureBase() {
        $sb = "{$this->MERCHANTNUMBER}|{$this->OPERATION}|{$this->ORDERNUMBER}|{$this->AMOUNT}|{$this->CURRENCY}|{$this->DEPOSITFLAG}";
        if(!isempty($this->MERORDERNUM))
            $sb .= "|{$this->MERORDERNUM}";
            
        $sb .= "|{$this->URL}";
        
        if(!isempty($this->DESCRIPTION))
            $sb .= "|{$this->DESCRIPTION}";
        if(!isempty($this->MD))
            $sb .= "|{$this->MD}";
        return $sb;
    }

    protected function validateData() {
        try {
            if (!preg_match('/^[0-9A-Z_]{4,20}$/i', $this->OPERATION)) throw new Exception('Operation type is in wrong format');
            if (!preg_match('/^[0-9]{1,15}$/i', $this->ORDERNUMBER)) throw new Exception('Order number is in wrong format');
            if (!preg_match('/^[0-9]{1,15}$/i', $this->AMOUNT)) throw new Exception('Amount is in wrong format');
            if (!preg_match('/^[0-3]{1,3}$/i', $this->CURRENCY)) throw new Exception('Currency is in wrong format');
            if(!($this->DEPOSITFLAG == 0 || $this->DEPOSITFLAG == 1)) throw new Exception('Deposit flag is in wrong format');
            if(!isempty($this->MERORDERNUM))
                if (!preg_match('/^[0-9]{1,30}$/i', $this->MERORDERNUM)) throw new Exception('Merordernum is in wrong format');

            if(!isempty($this->DESCRIPTION))
                if (!preg_match('/^[\x20-\x7E]{1,255}$/', $this->DESCRIPTION)) throw new Exception('Description is in wrong format');
            if(!isempty($this->MD))
                if (!preg_match('/^[\x20-\x7E]{1,255}$/', $this->MD)) throw new Exception('Description is in wrong format');
            return true;

        } catch (Exception $e) {
            throw $e;
            return false;
        }
    }
    public function SignMessage($password) {
        $this->fields['DIGEST'] = $this->computeSign($this->getSignatureBase(), $password);
        $this->fields['DIGEST1'] = $this->computeSign($this->getSignatureBase().'|'.$this->MERCHANTNUMBER, $password);
    }
    public function GetRedirectUrl() {
        $url = $this->redirectUrlBase;

        //pridani id banky
        $url .= "/{$this->provider}/order.do?";
        $url .= "MERCHANTNUMBER={$this->MERCHANTNUMBER}&OPERATION={$this->OPERATION}&ORDERNUMBER={$this->ORDERNUMBER}&AMOUNT={$this->AMOUNT}&CURRENCY={$this->CURRENCY}&DEPOSITFLAG={$this->DEPOSITFLAG}";
        $urlenc = urlencode($this->URL);
        $url .= "&URL={$urlenc}";		

        if(!isempty($this->MERORDERNUM))
                $url .= "&MERORDERNUM={$this->MERORDERNUM}";

        if(!isempty($this->DESCRIPTION)){
                $desc = urlencode($this->DESCRIPTION);
                $url .= "&DESCRIPTION={$desc}";
        }

        if(!isempty($this->MD)){
                $md = urlencode($this->MD);
                $url .= "&MD={$md}";
        }
        $urlenc = urlencode($this->DIGEST);
        $url .= "&DIGEST={$urlenc}";
        $urlenc = urlencode($this->DIGEST1);
        $url .= "&DIGEST1={$urlenc}";
        return $url;
    }
}
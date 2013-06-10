<?php
/*
	Copyright 2012 Ataxo Interactive a.s.
*/
use Nette\Diagnostics\Debugger;
class MuzoPaymentHttpResponse extends EPaymentCertSignedMessage implements IEPaymentHttpPaymentResponse {
    public function __construct($merchantKeyLink,$bankKeyLink){
        parent::__construct($merchantKeyLink,$bankKeyLink);
        $this->readOnlyFields = array('OPERATION', 'ORDERNUMBER', 'MERORDERNUM', 'MD', 'PRCODE', 'SRCODE','RESULTTEXT', 'DIGEST', 'DIGEST1');
        $this->requiredFields = array('MERCHANTNUMBER');

        $fields = $_GET;

        foreach($this->readOnlyFields as $field)
                $this->fields[$field] = isset($fields[$field]) ? $fields[$field] : null;
    }

    protected function validateData() {
        return true;
    }

    protected function getSignatureBase($digest = 'first') {
        $sign = "{$this->OPERATION}|{$this->ORDERNUMBER}";
        if($this->MERORDERNUM != '')
            $sign .= "|{$this->MERORDERNUM}";
        if($this->MD != '')
            $sign .= "|{$this->MD}";
        $sign .= "|{$this->PRCODE}|{$this->SRCODE}|{$this->RESULTTEXT}";
        if($digest == 'second')
            $sign .= "|{$this->MERCHANTNUMBER}";
        return $sign;
    }

    protected $isVerified = false;
    public function VerifySignature($fake) {
        if($this->validateBankSign($this->getSignatureBase(), $this->DIGEST))
            if($this->validateBankSign($this->getSignatureBase('second'), $this->DIGEST1))
                $this->isVerified = true;
        return $this->isVerified;
    }
    public function GetPaymentResponse() {
        try{
            if (!$this->isVerified)
                throw new Exception(__METHOD__.": Message was not verified yet.");

            $this->fields['PRCODE'] = (int)$this->PRCODE;
            $this->fields['SRCODE'] = (int)$this->SRCODE;
            
            if($this->PRCODE == 0)
                return IEPaymentHttpPaymentResponse::RESPONSE_SUCCESS;
            else{
                if($this->PRCODE == 28 || $this->PRCODE == 30 || $this->PRCODE == 35 ||$this->PRCODE == 1000){
                    if($this->PRCODE == 28){
                        switch($this->SRCODE){
                            case 3000:
                                $message = _('Declined in 3D. Cardholder not authenticated in 3D. Contact your card issuer.');
                                break;
                            case 3002:
                                $message = _('Not Authenticated in 3D. Issuer or Cardholder not participating in 3D. Contact your card issuer.');
                                break;
                            case 3004:
                                $message = _('Not Authenticated in 3D. Issuer or Cardholder not enrolled. Contact your card issuer.');
                                break;
                            case 3005:
                                $message = _('Declined in 3D. Technical problem during Cardholder authentication. Contact your card issuer.');
                                break;
                            case 3006:
                                $message = _('Declined in 3D. Technical problem during Cardholder authentication.');
                                break;
                            case 3007:
                                $message = _('Declined in 3D. Acquirer technical problem. Contact the merchant.');
                                break;
                            case 3008:
                                $message = _('Declined in 3D. Unsupported card product. Contact your card issuer.');
                                break;
                            default:
                                throw new Exception("Problem with payment response from bank: PRCODE {$this->PRCODE}, SRCODE {$this->SRCODE}, RESULTTEXT {$this->RESULTTEXT}");
                                break;
                        }
                    }
                    elseif($this->PRCODE == 30){
                        switch($this->SRCODE){
                            case 1001:
                                $message = _('Declined in AC, Card blocked.');
                                break;
                            case 1002:
                                $message = _('Declined in AC, Declined.');
                                break;
                            case 1003:
                                $message = _('Declined in AC, Card problem.');
                                break;
                            case 1004:
                                $message = _('Declined in AC, Technical problem in authorization process.');
                                break;
                            case 1005:
                                $message = _('Declined in AC, Account problem.');
                                break; 
                            default:
                                throw new Exception("Problem with payment response from bank: PRCODE {$this->PRCODE}, SRCODE {$this->SRCODE}, RESULTTEXT {$this->RESULTTEXT}");
                                break;
                        }
                    }
                    elseif($this->PRCODE == 35)
                        return IEPaymentHttpPaymentResponse::RESPONSE_TIMEOUT;
                    else
                        $message = _('Technical problem in payment gateway.');
                    
                    return $message;
                }
                else
                    throw new Exception("Problem with payment response from bank: PRCODE {$this->PRCODE}, SRCODE {$this->SRCODE}, RESULTTEXT {$this->RESULTTEXT}");
            }
        }
        catch(Exception $e){
            Debugger::log($e, Debugger::ERROR);
            return IEPaymentHttpPaymentResponse::RESPONSE_FAIL;
        }
    }
}
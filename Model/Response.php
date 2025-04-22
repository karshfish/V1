<?php

declare(strict_types=1);
class Response
{
    private bool $success;
    private array $message = array();
    private int $httpStatusCode;
    private  $data;
    private $toCache = false;
    private $resposeData = array();
    public function setSuccess($success)
    {
        $this->success = $success;
    }
    public function setHttpStatusCode($httpStatusCode)
    {
        $this->httpStatusCode = $httpStatusCode;
    }
    public function addMessage($message)
    {
        $this->message[] = $message;
    }
    public function setData($data)
    {
        $this->data = $data;
    }
    public function toCache($toCache)
    {
        $this->toCache = $toCache;
    }
    public function send()
    {
        //telling the browser that the content is json
        header('Content-type: application/json;charset=utf-8');
        //if toCache is true then cache the response for 60 seconds
        if ($this->toCache == true) {
            header('Cache-control: max-age=60');
        }
        //explicitly telling the clint not to store cache if toCache is false then do not cache the response 
        else {
            header('Cache-control: no-cache, no-store');
        }
        if (($this->success !== false && $this->success !== true) || !is_numeric($this->httpStatusCode)) {
            http_response_code(500);
            $this->resposeData['statusCode'] = 500;
            $this->resposeData['success'] = false;
            $this->addMessage("Response creation error");
            $this->resposeData['messages'] = $this->message;
        } else {
            http_response_code($this->httpStatusCode);
            $this->resposeData['statusCode'] = $this->httpStatusCode;
            $this->resposeData['success'] = $this->success;
            $this->resposeData['messages'] = $this->message;
            $this->resposeData['data'] = $this->data;
        }
        echo json_encode($this->resposeData);
    }
}

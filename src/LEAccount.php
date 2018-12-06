<?php

namespace LEClient;

/**
 * LetsEncrypt Account class, containing the functions and data associated with a LetsEncrypt account.
 * PHP version 5.2.0
 * MIT License
 * Copyright (c) 2018 Youri van Weegberg
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 * @version    1.1.4
 * @link       https://github.com/yourivw/LEClient
 * @since      Class available since Release 1.0.0
 */
class LEAccount
{
    private $connector;

    public $id;
    public $key;
    public $contact;
    public $agreement;
    public $initialIp;
    public $createdAt;
    public $status;

    private $log;

    public $url;

    /**
     * Initiates the LetsEncrypt Account class.
     * @param LEConnector $connector
     * @param array       $email The array of strings containing e-mail addresses. Only used when creating a new account.
     */
    public function __construct($connector, $email)
    {
        $this->connector = $connector;

        if (!($this->url = $this->getLEAccount())) {
            $this->url = $this->createLEAccount($email);
        }

        $this->connector->setKid($this->url);

        $this->getLEAccountData();
    }

    /**
     * Creates a new LetsEncrypt account.
     * @param array $email The array of strings containing e-mail addresses.
     * @return bool|object
     */
    private function createLEAccount($email)
    {
        $contact = array_map(function ($addr) {
            return empty($addr) ? '' : (strpos($addr, 'mailto') === false ? 'mailto:' . $addr : $addr);
        }, $email);

        $sign = $this->connector->signRequestJWK(['contact' => $contact, 'termsOfServiceAgreed' => true], $this->connector->newAccount);
        $post = $this->connector->post($this->connector->newAccount, $sign);
        if (strpos($post['header'], "201 Created") !== false) {
            if (preg_match('~Location: (\S+)~i', $post['header'], $matches)) return trim($matches[1]);
        }
        return false;
    }

    /**
     * Gets the LetsEncrypt account URL associated with the stored account keys.
     * @return bool|object
     */
    private function getLEAccount()
    {
        $sign = $this->connector->signRequestJWK(['onlyReturnExisting' => true], $this->connector->newAccount);
        $post = $this->connector->post($this->connector->newAccount, $sign);

        if (strpos($post['header'], "200 OK") !== false) {
            if (preg_match('~Location: (\S+)~i', $post['header'], $matches)) return trim($matches[1]);
        }
        return false;
    }

    /**
     * Gets the LetsEncrypt account data from the account URL.
     */
    private function getLEAccountData()
    {
        $sign = $this->connector->signRequestKid(['' => ''], $this->url);
        $post = $this->connector->post($this->url, $sign);
        if (strpos($post['header'], "200 OK") !== false) {
            $this->id        = $post['body']['id'];
            $this->key       = $post['body']['key'];
            $this->contact   = $post['body']['contact'];
            $this->agreement = isset($post['body']['agreement']) ? $post['body']['agreement'] : '';
            $this->initialIp = $post['body']['initialIp'];
            $this->createdAt = $post['body']['createdAt'];
            $this->status    = $post['body']['status'];
        } else {
            throw new \RuntimeException('Account data cannot be found.');
        }
    }

    /**
     * Updates account data. Now just supporting new contact information.
     * @param array $email The array of strings containing e-mail adresses.
     * @return boolean    Returns true if the update is successful, false if not.
     */
    public function updateAccount($email)
    {
        $contact = array_map(function ($addr) {
            return empty($addr) ? '' : (strpos($addr, 'mailto') === false ? 'mailto:' . $addr : $addr);
        }, $email);

        $sign = $this->connector->signRequestKid(['contact' => $contact], $this->url);
        $post = $this->connector->post($this->url, $sign);
        if (strpos($post['header'], "200 OK") !== false) {
            $this->id        = $post['body']['id'];
            $this->key       = $post['body']['key'];
            $this->contact   = $post['body']['contact'];
            $this->agreement = isset($post['body']['agreement']) ? $post['body']['agreement'] : '';
            $this->initialIp = $post['body']['initialIp'];
            $this->createdAt = $post['body']['createdAt'];
            $this->status    = $post['body']['status'];
            return true;
        } else {
            return false;
        }
    }

}

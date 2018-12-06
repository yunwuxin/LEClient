<?php

namespace LEClient;

/**
 * Main LetsEncrypt Client class, works as a framework for the LEConnector, LEAccount, LEOrder and LEAuthorization classes.
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
class LEClient
{
    const LE_PRODUCTION = 'https://acme-v02.api.letsencrypt.org';
    const LE_STAGING    = 'https://acme-staging-v02.api.letsencrypt.org';

    private $baseURL;

    private $connector;
    private $account;

    /**
     * Initiates the LetsEncrypt main client.
     * @param array|string $email   The array of strings containing e-mail addresses. Only used in this function when creating a new account.
     * @param string       $privateKey
     * @param string       $acmeURL ACME URL, can be string or one of predefined values: LE_STAGING or LE_PRODUCTION. Defaults to LE_STAGING.
     */
    public function __construct($email, $privateKey = null, $acmeURL = LEClient::LE_PRODUCTION)
    {
        if (is_bool($acmeURL)) {
            if ($acmeURL === true) $this->baseURL = LEClient::LE_STAGING;
            elseif ($acmeURL === false) $this->baseURL = LEClient::LE_PRODUCTION;
        } elseif (is_string($acmeURL)) {
            $this->baseURL = $acmeURL;
        } else throw new \RuntimeException('acmeURL must be set to string or bool (legacy).');

        if (empty($privateKey)) {
            list($privateKey,) = LEFunctions::RSAgenerateKeys();
        }

        $this->connector = new LEConnector($this->baseURL, $privateKey);

        $this->account = new LEAccount($this->connector, (array) $email);
    }

    /**
     * Returns the LetsEncrypt account used in the current client.
     * @return LEAccount    The LetsEncrypt Account instance used by the client.
     */
    public function getAccount()
    {
        return $this->account;
    }

    /**
     * Returns a LetsEncrypt order. If an order exists, this one is returned. If not, a new order is created and returned.
     * @param array|string $domains   The array of strings containing the domain names on the certificate.
     * @param string       $keyType   Type of the key we want to use for certificate. Can be provided in ALGO-SIZE format (ex. rsa-4096 or ec-256) or simple "rsa" and "ec" (using default sizes)
     * @param string       $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) at which the certificate becomes valid. Defaults to the moment the order is finalized. (optional)
     * @param string       $notAfter  A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) until which the certificate is valid. Defaults to 90 days past the moment the order is finalized. (optional)
     * @return LEOrder    The LetsEncrypt Order instance which is either retrieved or created.
     */
    public function createOrder($domains, $keyType = 'rsa-4096', $notBefore = '', $notAfter = '')
    {
        return new LEOrder($this->connector, (array) $domains, $keyType, $notBefore, $notAfter);
    }
}

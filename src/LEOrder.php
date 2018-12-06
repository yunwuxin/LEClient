<?php

namespace LEClient;

/**
 * LetsEncrypt Order class, containing the functions and data associated with a specific LetsEncrypt order.
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
class LEOrder
{
    private $connector;

    private $basename;
    private $privateKey;
    private $orderURL;
    private $keyType;
    private $keySize;

    public  $status;
    public  $expires;
    public  $identifiers;
    private $authorizationURLs;

    /** @var LEAuthorization[] */
    public $authorizations;

    public $finalizeURL;
    public $certificateURL;


    const CHALLENGE_TYPE_HTTP = 'http-01';
    const CHALLENGE_TYPE_DNS  = 'dns-01';

    /**
     * Initiates the LetsEncrypt Order class. If the base name is found in the $keysDir directory, the order data is requested. If no order was found locally, if the request is invalid or when there is a change in domain names, a new order is created.
     * @param LEConnector $connector The LetsEncrypt Connector instance to use for HTTP requests.
     * @param array       $domains   The array of strings containing the domain names on the certificate.
     * @param string      $keyType   Type of the key we want to use for certificate. Can be provided in ALGO-SIZE format (ex. rsa-4096 or ec-256) or simple "rsa" and "ec" (using default sizes)
     * @param string      $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) at which the certificate becomes valid.
     * @param string      $notAfter  A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) until which the certificate is valid.
     */
    public function __construct($connector, $domains, $keyType, $notBefore, $notAfter)
    {
        $this->connector = $connector;

        if ($keyType == 'rsa') {
            $this->keyType = 'rsa';
            $this->keySize = 4096;
        } elseif ($keyType == 'ec') {
            $this->keyType = 'ec';
            $this->keySize = 256;
        } else {
            preg_match_all('/^(rsa|ec)\-([0-9]{3,4})$/', $keyType, $keyTypeParts, PREG_SET_ORDER, 0);

            if (!empty($keyTypeParts)) {
                $this->keyType = $keyTypeParts[0][1];
                $this->keySize = intval($keyTypeParts[0][2]);
            } else throw new \RuntimeException('Key type \'' . $keyType . '\' not supported.');
        }

        $this->createOrder($domains, $notBefore, $notAfter);
    }

    /**
     * Creates a new LetsEncrypt order and fills this instance with its data. Subsequently creates a new RSA keypair for the certificate.
     * @param array  $domains   The array of strings containing the domain names on the certificate.
     * @param string $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) at which the certificate becomes valid.
     * @param string $notAfter  A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) until which the certificate is valid.
     */
    private function createOrder($domains, $notBefore = '', $notAfter = '')
    {
        if (preg_match('~(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|^$)~', $notBefore) AND preg_match('~(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|^$)~', $notAfter)) {

            $dns = [];
            foreach ($domains as $domain) {
                if (preg_match_all('~(\*\.)~', $domain) > 1) throw new \RuntimeException('Cannot create orders with multiple wildcards in one domain.');
                $dns[] = ['type' => 'dns', 'value' => $domain];
            }
            $payload = ["identifiers" => $dns, 'notBefore' => $notBefore, 'notAfter' => $notAfter];
            $sign    = $this->connector->signRequestKid($payload, $this->connector->newOrder);
            $post    = $this->connector->post($this->connector->newOrder, $sign);

            if (strpos($post['header'], "201 Created") !== false) {
                if (preg_match('~Location: (\S+)~i', $post['header'], $matches)) {
                    $this->orderURL = trim($matches[1]);

                    if ($this->keyType == "rsa") {
                        list($this->privateKey) = LEFunctions::RSAgenerateKeys($this->keySize);
                    } elseif ($this->keyType == "ec") {
                        list($this->privateKey) = LEFunctions::ECgenerateKeys($this->keySize);
                    } else {
                        throw new \RuntimeException('Key type \'' . $this->keyType . '\' not supported.');
                    }

                    $this->status            = $post['body']['status'];
                    $this->expires           = $post['body']['expires'];
                    $this->identifiers       = $post['body']['identifiers'];
                    $this->authorizationURLs = $post['body']['authorizations'];
                    $this->finalizeURL       = $post['body']['finalize'];
                    if (array_key_exists('certificate', $post['body'])) $this->certificateURL = $post['body']['certificate'];
                    $this->updateAuthorizations();

                } else {
                    throw new \RuntimeException('New-order returned invalid response.');
                }
            } else {
                throw new \RuntimeException('Creating new order failed.');
            }
        } else {
            throw new \RuntimeException('notBefore and notAfter fields must be empty or be a string similar to 0000-00-00T00:00:00Z');
        }
    }

    /**
     * Fetches the latest data concerning this LetsEncrypt Order instance and fills this instance with the new data.
     */
    private function updateOrderData()
    {
        $get = $this->connector->get($this->orderURL);
        if (strpos($get['header'], "200 OK") !== false) {
            $this->status            = $get['body']['status'];
            $this->expires           = $get['body']['expires'];
            $this->identifiers       = $get['body']['identifiers'];
            $this->authorizationURLs = $get['body']['authorizations'];
            $this->finalizeURL       = $get['body']['finalize'];
            if (array_key_exists('certificate', $get['body'])) $this->certificateURL = $get['body']['certificate'];
            $this->updateAuthorizations();
        }
    }

    /**
     * Fetches the latest data concerning all authorizations connected to this LetsEncrypt Order instance and creates and stores a new LetsEncrypt Authorization instance for each one.
     */
    private function updateAuthorizations()
    {
        $this->authorizations = [];
        foreach ($this->authorizationURLs as $authURL) {
            if (filter_var($authURL, FILTER_VALIDATE_URL)) {
                $auth = new LEAuthorization($this->connector, $authURL);
                if ($auth != false) $this->authorizations[] = $auth;
            }
        }
    }

    /**
     * Walks all LetsEncrypt Authorization instances and returns whether they are all valid (verified).
     * @return boolean    Returns true if all authorizations are valid (verified), returns false if not.
     */
    public function allAuthorizationsValid()
    {
        if (count($this->authorizations) > 0) {
            foreach ($this->authorizations as $auth) {
                if ($auth->status != 'valid') return false;
            }
            return true;
        }
        return false;
    }

    /**
     * Get all pending LetsEncrypt Authorization instances and return the necessary data for verification. The data in the return object depends on the $type.
     * @param int $type       The type of verification to get. Supporting http-01 and dns-01. Supporting LEOrder::CHALLENGE_TYPE_HTTP and LEOrder::CHALLENGE_TYPE_DNS. Throws
     *                        a Runtime Exception when requesting an unknown $type. Keep in mind a wildcard domain authorization only accepts LEOrder::CHALLENGE_TYPE_DNS.
     * @return array|bool Returns an array with verification data if successful, false if not pending LetsEncrypt Authorization instances were found. The return array always
     *                        contains 'type' and 'identifier'. For LEOrder::CHALLENGE_TYPE_HTTP, the array contains 'filename' and 'content' for necessary the authorization file.
     *                        For LEOrder::CHALLENGE_TYPE_DNS, the array contains 'DNSDigest', which is the content for the necessary DNS TXT entry.
     */

    public function getPendingAuthorizations($type)
    {
        $authorizations = [];

        $privateKey = openssl_pkey_get_private($this->connector->privateKey);
        $details    = openssl_pkey_get_details($privateKey);

        $header = [
            "e"   => LEFunctions::Base64UrlSafeEncode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n"   => LEFunctions::Base64UrlSafeEncode($details["rsa"]["n"])

        ];
        $digest = LEFunctions::Base64UrlSafeEncode(hash('sha256', json_encode($header), true));

        foreach ($this->authorizations as $auth) {
            if ($auth->status == 'pending') {
                $challenge = $auth->getChallenge($type);
                if ($challenge['status'] == 'pending') {
                    $keyAuthorization = $challenge['token'] . '.' . $digest;
                    switch (strtolower($type)) {
                        case LEOrder::CHALLENGE_TYPE_HTTP:
                            $authorizations[] = ['type' => LEOrder::CHALLENGE_TYPE_HTTP, 'identifier' => $auth->identifier['value'], 'filename' => $challenge['token'], 'content' => $keyAuthorization];
                            break;
                        case LEOrder::CHALLENGE_TYPE_DNS:
                            $DNSDigest        = LEFunctions::Base64UrlSafeEncode(hash('sha256', $keyAuthorization, true));
                            $authorizations[] = ['type' => LEOrder::CHALLENGE_TYPE_DNS, 'identifier' => $auth->identifier['value'], 'DNSDigest' => $DNSDigest];
                            break;
                    }
                }
            }
        }

        return count($authorizations) > 0 ? $authorizations : false;
    }

    /**
     * Sends a verification request for a given $identifier and $type. The function itself checks whether the verification is valid before making the request.
     * Updates the LetsEncrypt Authorization instances after a successful verification.
     * @param string  $identifier The domain name to verify.
     * @param int     $type       The type of verification. Supporting LEOrder::CHALLENGE_TYPE_HTTP and LEOrder::CHALLENGE_TYPE_DNS.
     * @param boolean $localcheck Whether to verify the authorization locally before making the authorization request to LE. Optional, default to true.
     * @return boolean    Returns true when the verification request was successful, false if not.
     */
    public function verifyPendingOrderAuthorization($identifier, $type, $localcheck = true)
    {
        $privateKey = openssl_pkey_get_private($this->connector->privateKey);
        $details    = openssl_pkey_get_details($privateKey);

        $header = [
            "e"   => LEFunctions::Base64UrlSafeEncode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n"   => LEFunctions::Base64UrlSafeEncode($details["rsa"]["n"])

        ];
        $digest = LEFunctions::Base64UrlSafeEncode(hash('sha256', json_encode($header), true));

        foreach ($this->authorizations as $auth) {
            if ($auth->identifier['value'] == $identifier) {
                if ($auth->status == 'pending') {
                    $challenge = $auth->getChallenge($type);
                    if ($challenge['status'] == 'pending') {
                        $keyAuthorization = $challenge['token'] . '.' . $digest;
                        switch ($type) {
                            case LEOrder::CHALLENGE_TYPE_HTTP:
                                if ($localcheck == false OR LEFunctions::checkHTTPChallenge($identifier, $challenge['token'], $keyAuthorization)) {
                                    $sign = $this->connector->signRequestKid(['keyAuthorization' => $keyAuthorization], $challenge['url']);
                                    $post = $this->connector->post($challenge['url'], $sign);
                                    if (strpos($post['header'], "200 OK") !== false) {
                                        while ($auth->status == 'pending') {
                                            sleep(1);
                                            $auth->updateData();
                                        }
                                        return true;
                                    }
                                }
                                break;
                            case LEOrder::CHALLENGE_TYPE_DNS:
                                $DNSDigest = LEFunctions::Base64UrlSafeEncode(hash('sha256', $keyAuthorization, true));
                                if ($localcheck == false OR LEFunctions::checkDNSChallenge($identifier, $DNSDigest)) {
                                    $sign = $this->connector->signRequestKid(['keyAuthorization' => $keyAuthorization], $challenge['url']);
                                    $post = $this->connector->post($challenge['url'], $sign);
                                    if (strpos($post['header'], "200 OK") !== false) {
                                        while ($auth->status == 'pending') {
                                            sleep(1);
                                            $auth->updateData();
                                        }
                                        return true;
                                    }
                                }
                                break;
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * Deactivate an LetsEncrypt Authorization instance.
     * @param string $identifier The domain name for which the verification should be deactivated.
     * @return boolean    Returns true is the deactivation request was successful, false if not.
     */
    public function deactivateOrderAuthorization($identifier)
    {
        foreach ($this->authorizations as $auth) {
            if ($auth->identifier['value'] == $identifier) {
                $sign = $this->connector->signRequestKid(['status' => 'deactivated'], $auth->authorizationURL);
                $post = $this->connector->post($auth->authorizationURL, $sign);
                if (strpos($post['header'], "200 OK") !== false) {
                    $this->updateAuthorizations();
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Generates a Certificate Signing Request for the identifiers in the current LetsEncrypt Order instance. If possible, the base name will be the certificate
     * common name and all domain names in this LetsEncrypt Order instance will be added to the Subject Alternative Names entry.
     * @return string    Returns the generated CSR as string, unprepared for LetsEncrypt. Preparation for the request happens in finalizeOrder()
     */
    public function generateCSR()
    {
        $domains = array_map(function ($dns) {
            return $dns['value'];
        }, $this->identifiers);

        $CN = $domains[0];

        $dn = [
            "commonName" => $CN
        ];

        $san         = implode(",", array_map(function ($dns) {
            return "DNS:" . $dns;
        }, $domains));
        $tmpConf     = tmpfile();
        $tmpConfMeta = stream_get_meta_data($tmpConf);
        $tmpConfPath = $tmpConfMeta["uri"];

        fwrite($tmpConf,
            'HOME = .
			RANDFILE = $ENV::HOME/.rnd
			[ req ]
			default_bits = ' . $this->keySize . '
			default_keyfile = privkey.pem
			distinguished_name = req_distinguished_name
			req_extensions = v3_req
			[ req_distinguished_name ]
			countryName = Country Name (2 letter code)
			[ v3_req ]
			basicConstraints = CA:FALSE
			subjectAltName = ' . $san . '
			keyUsage = nonRepudiation, digitalSignature, keyEncipherment');

        $privateKey = openssl_pkey_get_private($this->privateKey);
        $csr        = openssl_csr_new($dn, $privateKey, ['config' => $tmpConfPath, 'digest_alg' => 'sha256']);
        openssl_csr_export($csr, $csr);
        return $csr;
    }

    /**
     * Checks, for redundancy, whether all authorizations are valid, and finalizes the order. Updates this LetsEncrypt Order instance with the new data.
     * @param string $csr The Certificate Signing Request as a string. Can be a custom CSR. If empty, a CSR will be generated with the generateCSR() function.
     * @return boolean    Returns true if the finalize request was successful, false if not.
     */
    public function finalizeOrder($csr = '')
    {
        if ($this->status == 'pending' || $this->status == 'ready') {
            if ($this->allAuthorizationsValid()) {
                if (empty($csr)) $csr = $this->generateCSR();
                if (preg_match('~-----BEGIN\sCERTIFICATE\sREQUEST-----(.*)-----END\sCERTIFICATE\sREQUEST-----~s', $csr, $matches)) $csr = $matches[1];
                $csr  = trim(LEFunctions::Base64UrlSafeEncode(base64_decode($csr)));
                $sign = $this->connector->signRequestKid(['csr' => $csr], $this->finalizeURL);
                $post = $this->connector->post($this->finalizeURL, $sign);
                if (strpos($post['header'], "200 OK") !== false) {
                    $this->status            = $post['body']['status'];
                    $this->expires           = $post['body']['expires'];
                    $this->identifiers       = $post['body']['identifiers'];
                    $this->authorizationURLs = $post['body']['authorizations'];
                    $this->finalizeURL       = $post['body']['finalize'];
                    if (array_key_exists('certificate', $post['body'])) $this->certificateURL = $post['body']['certificate'];
                    $this->updateAuthorizations();

                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Gets whether the LetsEncrypt Order is finalized by checking whether the status is processing or valid. Keep in mind, a certificate is not yet available when the status still is processing.
     * @return boolean    Returns true if finalized, false if not.
     */
    public function isFinalized()
    {
        return ($this->status == 'processing' || $this->status == 'valid');
    }

    /**
     * Requests the certificate for this LetsEncrypt Order instance, after finalization. When the order status is still 'processing', the order will be polled max
     * four times with five seconds in between. If the status becomes 'valid' in the meantime, the certificate will be requested. Else, the function returns false.
     * @return boolean    Returns true if the certificate is stored successfully, false if the certificate could not be retrieved or the status remained 'processing'.
     */
    public function getCertificate()
    {
        $polling = 0;
        while ($this->status == 'processing' && $polling < 4) {
            sleep(5);
            $this->updateOrderData();
            $polling++;
        }
        if ($this->status == 'valid' && !empty($this->certificateURL)) {
            $get = $this->connector->get($this->certificateURL);
            if (strpos($get['header'], "200 OK") !== false) {
                return $get['body'];
            }
        }
        return false;
    }

    public function getPrivateKey()
    {
        return $this->privateKey;
    }

}

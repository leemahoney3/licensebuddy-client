<?php

namespace LicenseBuddy\Client;

use Carbon\Carbon;
use LicenseBuddy\Client\OfflineKey;

/**
 * License Buddy Client
 *
 * Clientside validation for the License Buddy WHMCS module
 *
 * @package    WHMCS
 * @author     Lee Mahoney <lee@leemahoney.dev>
 * @copyright  Copyright (c) Lee Mahoney 2022
 * @license    MIT License
 * @version    1.0.0
 * @link       https://leemahoney.dev
 */


/**
 * LicenseBuddy Validator Class
 */
class Validator {

    /**
     * Errors array
     *
     * @var array
     */
    private $errors = [];
    

    /**
     * Remote License Server Url
     *
     * @var string
     */
    private $remoteUrl;

    /**
     * Amount of days before calling home to do a license check
     *
     * @var int
     */
    private $sleepDays;

    /**
     * Amount of days to allow no contact (after the $sleepDays) with the licensing server before invalidating the offline key
     *
     * @var int
     */
    private $offlineDays;

    /**
     * Whether or not to allow an offline key or always call home on each check
     *
     * @var boolean
     */
    private $allowOffline;

    /**
     * The offline key
     *
     * @var string
     */
    private $offlineKey;

    /**
     * The license key
     *
     * @var string
     */
    private $licenseKey;

    /**
     * The application key used to validate the license belongs to the correct product
     *
     * @var string
     */
    private $applicationKey;
    
    /**
     * Initialize the instance
     * 
     * @param array $config The configuration passed to the validator
     */
    public function __construct(array $config = []) {

        if (empty($config)) {
            $this->setError('local', 'No configuration variables passed');
            return false;
        }

        if (empty($config['remoteUrl'])) {
            $this->setError('local', 'No remote url passed, cannot perform license check');
            return false;;
        }

        if (empty($config['applicationKey'])) {
            $this->setError('local', 'No application key passed, cannot perform license check');
            return false;
        }

        $this->remoteUrl        = isset($config['remoteUrl']) && !empty($config['remoteUrl']) ? $config['remoteUrl'] : '';
        $this->applicationKey   = isset($config['applicationKey']) && !empty($config['applicationKey']) ? $config['applicationKey'] : '';
        $this->allowOffline     = isset($config['allowOffline']) && is_bool($config['allowOffline']) ? $config['allowOffline'] : true;
        $this->offlineDays      = isset($config['offlineDays']) && is_numeric($config['offlineDays']) ? $config['offlineDays'] : 2;
        $this->sleepDays        = isset($config['sleepDays']) && is_numeric($config['sleepDays']) ? $config['sleepDays'] : 5;

    }

    /**
     * Sets the offline key
     * 
     * @param string $offlineKey The offline key passed to the method
     * @return $this
     */
    public function setOfflineKey(string $offlineKey) {
        
        $this->offlineKey = !empty($offlineKey) ? $offlineKey : '';
        return $this;
    
    }

    /**
     * Set the license key
     * 
     * @param string $licenseKey The license key passed to the method
     * @return $this
     */
    public function setLicenseKey(string $licenseKey) {

        if (empty($licenseKey)) {
            $this->setError('local', 'No license key passed');
            return false;
        }

        $this->licenseKey = $licenseKey;

        return $this;

    }

    /**
     * Check the license
     * 
     * @return array
     */
    public function checkLicense() {

        if ($this->getErrors('local')) {
            return [
                'status'    => 'error',
                'scope'     => 'local',
                'errors'    => $this->getErrors('local'),
            ];
        }

        $token      = $this->getToken();
        $checkDate  = $this->getCheckDate();
        $domain     = $this->getDomain();
        $ipAddress  = $this->getIpAddress();
        $directory  = $this->getDirectory();

        $results            = [];
        $offlineKeyValid    = false;
        
        if ($this->isAllowedOffline()) {

            if ($this->getOfflineKey()) {
                
                $decodedOfflineKey = OfflineKey::decode($this->getOfflineKey(), $this->getPassword());

                if ($decodedOfflineKey) {

                    $localExpiry        = date('Ymd', strtotime("-{$this->getSleepDays()} days"));
                    $offlineKeyResults  = json_decode($decodedOfflineKey, true);
                    $originalCheckDate  = $offlineKeyResults['checkDate'];
                
                    if ($originalCheckDate > $localExpiry) {

                        $offlineKeyValid    = true;
                        $results            = $offlineKeyResults;
                        $allowedDomains     = explode(",", $offlineKeyResults['licenseData']['allowedDomains']);
                        
                        if ($offlineKeyResults['licenseData']['isTrial']) {
                            $trialExpiry    = Carbon::createFromFormat('d-m-Y', $offlineKeyResults['licenseData']['trialExpiry']);
                            $todaysDate     = Carbon::now();
                
                            if ($todaysDate->gt($trialExpiry)) {
                                $offlineKeyValid                = false;
                                $offlineKeyResults['status']    = 'invalid';
                                $results                        = [];
                            }
                        }
                        
                        if (!in_array($domain, $allowedDomains)) {
                            $offlineKeyValid                = false;
                            $offlineKeyResults['status']    = 'invalid';
                            $results                        = [];
                        }

                        if ($ipAddress != $offlineKeyResults['licenseData']['allowedIPAddress']) {
                            $offlineKeyValid                = false;
                            $offlineKeyResults['status']    = 'invalid';
                            $results                        = [];
                        }

                        if ($directory != $offlineKeyResults['licenseData']['allowedDirectory']) {
                            $offlineKeyValid                = false;
                            $offlineKeyResults['status']    = 'invalid';
                            $results                        = [];
                        }

                    }

                }

            }

            if (!$offlineKeyValid) {

                $responseCode   = 0;
                $postFields     = [
                    'licenseCheck'      => true, 
                    'validationHash'    => hash('sha256', $this->getApplicationKey() . $token),
                    'licenseKey'        => $this->getLicenseKey(),
                    'domain'            => $domain,
                    'ipAddress'         => $ipAddress,
                    'directory'         => $directory,
                ];

                if ($token) {
                    $postFields['token'] = $token;
                }

                $check = $this->doRemoteCheck($postFields);
                
                $responseCode   = $check['responseCode'];

                if ($responseCode != 200) {

                    $localExpiry = date('Ymd', strtotime('-' . ($this->getSleepDays() + $this->getOfflineDays()) . ' days'));

                    if ($originalCheckDate > $localExpiry) {
                        $results = $offlineKeyResults;
                    } else {
                        $results            = [];
                        $results['status']  = 'Invalid';
                        $results['message'] = 'Unable to contact licensing server. Please contact support';
                        return $results;
                    }

                } else {

                    $results        = $check['data'];
                    $licenseData    = $results['licenseData'];

                }

                if (!is_array($results)) {
                    $this->setError('remote', 'Invalid license server response');
                    return $this->getErrors('remote');
                }

                if (isset($licenseData['hash'])) {
                    if ($licenseData['hash'] != hash('sha256', $this->getApplicationKey() . $token)) {
                        $results['status']  = 'Invalid';
                        $results['message'] = 'Checksum verification failed';
                        return $results;
                    }
                }

                if ($results['status'] == 'active') {
                    $results['checkDate'] = $checkDate;

                    $dataEncoded = json_encode($results);
                
                    $offlineKey = OfflineKey::generate($dataEncoded, $this->getPassword());

                    $results['offlineKey'] = $offlineKey;
                }

                $results['remoteCheck'] = true;

            }

        } else {

            $responseCode   = 0;
            $postFields     = [
                'licenseCheck'      => true, 
                'validationHash'    => hash('sha256', $this->getApplicationKey() . $token),
                'licenseKey'        => $this->getLicenseKey(),
                'domain'            => $domain,
                'ipAddress'         => $ipAddress,
                'directory'         => $directory,
            ];

            if ($token) {
                $postFields['token'] = $token;
            }

            $check = $this->doRemoteCheck($postFields);
            
            $responseCode   = $check['responseCode'];

            if ($responseCode != 200) {
                $results            = [];
                $results['status']  = 'Invalid';
                $results['message'] = 'Unable to contact licensing server. Please contact support';
                return $results;
            } else {
                
                $results        = $check['data'];
                $licenseData    = $results['licenseData'];
            }

            if (!is_array($results)) {
                $this->setError('remote', 'Invalid license server response');
                return $this->getErrors('remote');
            }

            if (isset($licenseData['hash'])) {
                if ($licenseData['hash'] != hash('sha256', $this->getApplicationKey() . $token)) {
                    $results['status']  = 'Invalid';
                    $results['message'] = 'Checksum verification failed';
                    return $results;
                }
            }

            $results['remoteCheck'] = true;

        }

        return $results;

    }

    /**
     * Get the stored offline key
     * 
     * @return string
     */
    public function getOfflineKey() {
        return $this->offlineKey;
    }

    /**
     * Get the stored license key
     * 
     * @return string
     */
    public function getLicenseKey() {
        return $this->licenseKey;
    }

    /**
     * Get the stored application key
     * 
     * @return string
     */
    public function getApplicationKey() {
        return $this->applicationKey;
    }

    /**
     * Get the stored offline days value
     * 
     * @return int
     */
    public function getOfflineDays() {
        return $this->offlineDays;
    }

    /**
     * Get a randomly generated security token based on the license key to validate with the server
     * 
     * @return string
     */
    private function getToken() {
        return time() . hash('sha256', mt_rand(100000000, mt_getrandmax()) . $this->getLicenseKey());
    }

    /**
     * Get todays date (also known as the check date)
     * 
     * @return date
     */
    private function getCheckDate() {
        return date("Ymd");
    }

    /**
     * Get the current domain name
     * 
     * @return string
     */
    private function getDomain() {
        return $_SERVER['SERVER_NAME'];
    }

    /**
     * Get the current IP address
     * 
     * @return string
     */
    private function getIpAddress() {
        return isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : $_SERVER['LOCAL_ADDR'];
    }

    /**
     * Get the current directory (where the script is installed. May need to change this if the script is likely to be installed in a subdirectory)
     * 
     * @return string
     */
    private function getDirectory() {
        return $_SERVER['DOCUMENT_ROOT'];
    }

    /**
     * Get the remote licensing server
     *
     * @return string
     */
    private function getRemoteUrl() {
        return $this->remoteUrl;
    }

    /**
     * Get the generated password key for the offline key encryption based off the domain, directory, IP address and application key
     * Useful as if any of the above change, the current offline key will become invalidated and a remote check will be performed
     *
     * @return string
     */
    private function getPassword() {
        return sha1($this->getDomain().$this->getDirectory().$this->getIpAddress().$this->getApplicationKey());
    }

    /**
     * Get stored errors based on the scope given (local scope is used if no scope is passed)
     *
     * @param string $scope
     * @return array|null
     */
    private function getErrors($scope = 'local') {
        return isset($this->errors[$scope]) && !empty($this->errors[$scope]) ? $this->errors[$scope] : null;
    }

    /**
     * Set an error for a given scope
     *
     * @param string $scope
     * @param string $message
     * @return $this
     */
    private function setError($scope, $message) {
        $this->errors[$scope][] = $message;
        
        return $this;
    }

    /**
     * Check if offline keys are allowed
     *
     * @return boolean
     */
    private function isAllowedOffline() {
        return $this->allowOffline;
    }

    /**
     * Get the stored sleep days value
     *
     * @return int
     */
    private function getSleepDays() {
        return $this->sleepDays;
    }

    /**
     * Perform remote licensing check
     *
     * @param array $postFields
     * @return array
     */
    private function doRemoteCheck($postFields = []) {

        if (empty($postFields)) {
            $this->error = 'Invalid post fields for remote check';
            return false;
        }

        $res            = [];
        $queryString    = '';

        foreach ($postFields as $k => $v) {
            $queryString .= $k . '=' . urlencode($v) . '&';
        }

        if (function_exists('curl_exec')) {

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->getRemoteUrl());
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $queryString);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

            $res = [
                'data'          => json_decode(curl_exec($ch), true),
                'responseCode'  => curl_getinfo($ch, CURLINFO_HTTP_CODE),
            ];

            curl_close($ch);

        } else {

            $responseCodePattern = '/^HTTP\/\d+\.\d+\s+(\d+)/';

            $fp = @fsockopen($this->getRemoteUrl(), 80, $errno, $errstr, 5);

            if ($fp) {

                $newlinefeed = "\r\n";
                
                $header     = "POST " . $this->getRemoteUrl() . " HTTP/1.0" . $newlinefeed;
                $header    .= "Host: " . $this->getRemoteUrl() . $newlinefeed;
                $header    .= "Content-type: application/x-www-form-urlencoded" . $newlinefeed;
                $header    .= "Content-length: " . @strlen($queryString) . $newlinefeed;
                $header    .= "Connection: close" . $newlinefeed . $newlinefeed;
                $header    .= $queryString;
                $data       = $line = '';
                
                @stream_set_timeout($fp, 20);
                @fputs($fp, $header);

                $status = @socket_get_status($fp);

                while (!@feof($fp) && $status) {
                    
                    $line           = @fgets($fp, 1024);
                    $patternMatches = [];
                    
                    if (!$responseCode && preg_match($responseCodePattern, trim($line), $patternMatches)) {
                        $responseCode = (empty($patternMatches[1])) ? 0 : $patternMatches[1];
                    }
                    
                    $data  .= $line;
                    $status = @socket_get_status($fp);
                }

                @fclose($fp);

            }

            $res = [
                'data'          => json_decode($data, true),
                'responseCode'  => $responseCode,
            ];

        }

        return $res;

    }

}
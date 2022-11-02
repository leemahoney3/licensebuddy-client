<?php

namespace LicenseBuddy\Client;

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
 * LicenseBuddy OfflineKey Class
 */
class OfflineKey {
    
    /**
     * Encryption method used
     *
     * @var string
     */
    private static $method = 'aes-256-cbc';

    /**
     * Generate the offline key
     *
     * @param string $licenseData
     * @param string $encryptionKey
     * @return string|false
     */
    public static function generate($licenseData, $encryptionKey) {
        
        if (empty($licenseData) || empty($encryptionKey)) {
            return false;
        }
        
        $iv                 = substr(sha1(mt_rand()), 0, 16);
        $salt               = sha1(mt_rand());
        $encryptionKey      = sha1($encryptionKey);
        
        $saltedEncryptionKey = hash('sha256', $encryptionKey.$salt);
    
        if($enc = openssl_encrypt($licenseData, self::$method, $saltedEncryptionKey, null, $iv)) {
            return base64_encode("$iv:$salt:$enc");
        }

        return false;

    }
    
    /**
     * Decode an offline key
     *
     * @param string $offlineKey
     * @param string $encryptionKey
     * @return string|false
     */
    public static function decode($offlineKey, $encryptionKey){
        
        $encryptionKey  = sha1($encryptionKey);
        $offlineKey     = base64_decode($offlineKey);
        $components     = explode( ':', $offlineKey);
        $iv             = $components[0];
        $salt           = hash('sha256', $encryptionKey.$components[1]);
        $payload        = $components[2];
    
        if($res = openssl_decrypt($payload, self::$method, $salt, null, $iv)) {
            return $res;
        }

        return false;
    
    }

}
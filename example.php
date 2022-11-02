<?php

use LicenseBuddy\Client\Validator;

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


// Require autoloader
require_once __DIR__ . '/vendor/autoload.php';

// Set configuration options
$configOptions = [
    'remoteUrl'         => 'https://your.whmcs.url/',
    'applicationKey'    => 'your-application-key',
    'allowOffline'      => true,
    'sleepDays'         => 5,
    'offlineDays'       => 2,
];

// Instantiate a new validator
$validator = new Validator($configOptions);

// Set the license key
$validator->setLicenseKey('TEST-YOURLICENSEKEY');

// Optionally set the offline license key if provided (validation is performed on the key)
//$validator->setOfflineKey('');

// Grab the results of the license check with the remote server
$results = $validator->checkLicense();

// Results are outputted as an array.
// if ($results['status'] == 'invalid') {
//     die('License Invalid');
// } else if ($results['status'] == 'active') {
//     die("License Active");
// }

// Show all results for debugging purposes
die("<textarea cols='160' rows='20'>" . print_r($results, true) . "</textarea>");
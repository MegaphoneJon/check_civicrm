#!/usr/bin/php
<?php

/**
 * Copyright 2014-2015 AGH Strategies, LLC
 * Released under the Affero GNU Public License version 3
 * but with NO WARRANTY: neither the implied warranty of merchantability
 * nor fitness for a particular purpose
 *
 * Place in /usr/lib/nagios/plugins
 *
 * Call with the command:
 * /usr/bin/php /usr/lib/nagios/plugins/check_civicrm.php
 *
 * Required arguments:
 * --hostname <hostname>
 * --protocol <http|https>
 * --site-key <your site key>
 * --api-key <an API key> must have system.check permission.  Use a key that has "Administer CiviCRM" permission, or better yet install https://github.com/MegaphoneJon/com.megaphonetech.monitoring
 *
 * Optional arguments:
 * --cms <Drupal|Wordpress|Joomla|Backdrop|Drupal8>
 * --rest-path <path to REST endpoint> NOTE: either --cms OR --path is required
 * --warning-threshold <integer> Checks that report back this severity_id or higher are considered Nagios/Icinga warnings.
 * --critical-threshold <integer> Checks that report back this severity_id or higher are considered Nagios/Icinga errors.
 * --show-hidden <0|1> If set to "0", checks that are hidden in the CiviCRM Status Console will be hidden from Nagios/Icinga.
 * --exclude <comma-separated list of checks, no spaces> Any checks listed here will be excluded.  E.g. --exclude checkPhpVersion,checkLastCron will suppress the PHP version check and the cron check
 */
$shortopts = '';
$longopts = ['exclude:', 'api-key:', 'site-key:', 'protocol:', 'cms:', 'rest-path:', 'show-hidden:', 'hostname:', 'warning-threshold:', 'critical-threshold:'];
$options = getopt($shortopts, $longopts);
checkRequired($options);

$prot = $options['protocol'];
$api_key = $options['api-key'];
$site_key = $options['site-key'];
$host_address = $options['hostname'];
// $show_hidden will evaluate to true unless it's a zero.
$show_hidden = $options['show-hidden'] ?? TRUE;
$warning_threshold = $options['warning-threshold'] ?? 2;
$critical_threshold = $options['critical-threshold'] ?? 4;
$path = $options['path'] ?? NULL;
$cms = $options['cms'] ?? NULL;
$exclude = explode(',', $options['exclude'] ?? NULL);


switch (strtolower($cms)) {
  case 'wordpress':
    $path = 'wp-json/civicrm/v3/rest';
    break;

  case 'joomla':
  case 'backdrop':
  case 'drupal':
  case 'drupal8':
    $path = 'civicrm/ajax/rest';
    break;
}
if (!$path) {
  echo "You must specify either a valid CMS or a REST endpoint path.";
  exit(3);
}
systemCheck($prot, $host_address, $path, $site_key, $api_key, $show_hidden, $warning_threshold, $critical_threshold, $exclude);

/**
 * Given an array of command-line options, do some sanity checks, bail if missing required fields etc.
 * @param array $options
 */
function checkRequired($options) {
  $requiredArguments = ['hostname', 'protocol', 'site-key', 'api-key'];
  $arguments = array_keys($options);
  $missing = NULL;
  foreach ($requiredArguments as $required) {
    if (!in_array($required, $arguments)) {
      $missing .= " $required";
    }
  }
  if (isset($missing)) {
    echo "You are missing the following required arguments:$missing";
    exit(3);
  }
  if (!in_array($options['protocol'], ['http', 'https'])) {
    echo '"protocol" argument must be "http" or "https"' .
    exit(3);
  }
}

function systemCheck($prot, $host_address, $path, $site_key, $api_key, $show_hidden, $warning_threshold, $critical_threshold, $exclude = []) {
  $options = [
    'http' => [
      'header'  => "Content-type: application/x-www-form-urlencoded\r\nUser-Agent: CiviMonitor\r\nX-Requested-With: XMLHttpRequest\r\n",
      //'method'  => 'POST',
      //'content' => http_build_query($request),
    ],
  ];
  $context  = stream_context_create($options);
  $result = file_get_contents("$prot://$host_address/$path?entity=system&action=check&key=$site_key&api_key=$api_key&json=1&version=3", FALSE, $context);

  $a = json_decode($result, TRUE);
  $isError = $a["is_error"] ?? FALSE;

  if ($isError) {
    echo $a['error_message'] ?? '';
    exit(2);
  }
  if (!isset($a['values'])) {
    echo 'Unknown error - no values returned from CiviCRM';
    exit(3);
  }

  $message = [];
  $max_severity = 0;
  foreach ($a["values"] as $attrib) {

    // Remove excluded checks.
    if (in_array($attrib['name'], $exclude)) {
      continue;
    }

    // first check for missing info
    $neededKeys = [
      'title' => TRUE,
      'message' => TRUE,
      'name' => TRUE,
    ];
    if (array_intersect_key($neededKeys, $attrib) != $neededKeys) {
      $message[] = 'Missing keys: ' . implode(', ', array_diff($neededKeys, array_intersect_key($neededKeys, $attrib))) . '.';
      $max_severity = 3;
      continue;
    }
    // Skip this item if it's hidden and we're hiding hidden items
    if ($attrib['is_visible'] == 0 && !$show_hidden) {
      continue;
    }
    // Skip this item if it doesn't meet the warning threshold
    if ($attrib['severity_id'] < $warning_threshold) {
      continue;
    }
    $message[] = htmlspecialchars($attrib['title']) . ': ' . htmlspecialchars($attrib['message']);

    if ($attrib['severity_id'] >= $warning_threshold) {
      $max_severity = max(1, $max_severity);
    };
    if ($attrib['severity_id'] >= $critical_threshold) {
      $max_severity = max(2, $max_severity);
    };

  }
  echo implode(' / ', $message);
  exit($max_severity);
}

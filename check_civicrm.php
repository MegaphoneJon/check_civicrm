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
 * Required arguments (if protcol is http or https):
 * --hostname <hostname>
 * --protocol <http|https|cv>
 * --site-key <your site key>
 * --api-key <an API key> must have system.check permission.  Use a key that has "Administer CiviCRM" permission, or better yet install https://github.com/MegaphoneJon/com.megaphonetech.monitoring
 *
 * Required arguments (if protocol is cv):
 * --webroot <path to webroot>
 *
 * Optional arguments:
 * --cms <Drupal|Wordpress|Joomla|Backdrop|Drupal8>
 * --rest-path <path to REST endpoint> NOTE: either --cms OR --path is required
 * --warning-threshold <integer> Checks that report back this severity_id or higher are considered Nagios/Icinga warnings.
 * --critical-threshold <integer> Checks that report back this severity_id or higher are considered Nagios/Icinga errors.
 * --show-hidden <0|1> If set to "0", checks that are hidden in the CiviCRM Status Console will be hidden from Nagios/Icinga.
 * --exclude <comma-separated list of checks, no spaces> Any checks listed here will be excluded.  E.g. --exclude checkPhpVersion,checkLastCron will suppress the PHP version check and the cron check
 * --only-these-checks <comma-separated list of checks, no spaces> If specified, only these checks will be run.  Unlike "--exclude", which simply hides results, this prevents other checks from running.
 * --include-disabled <0|1> If set to 1, it will run status checks that have been marked inactive in the CiviCRM database.
 * --cvpath <path to cv> Only needed if protocol is "cv" and cv is not in the default location of /usr/local/bin/cv
 */
$shortopts = '';
$longopts = ['exclude:', 'api-key:', 'site-key:', 'protocol:', 'cms:', 'rest-path:', 'show-hidden:', 'hostname:', 'warning-threshold:', 'critical-threshold:', 'include-disabled:', 'only-these-checks:', 'webroot:', 'cvpath:'];
$options = getopt($shortopts, $longopts);
checkRequired($options);
main($options);

function main(array $options) {
  $prot = $options['protocol'];
  $show_hidden = $options['show-hidden'] ?? TRUE;
  $warning_threshold = $options['warning-threshold'] ?? 2;
  $critical_threshold = $options['critical-threshold'] ?? 4;
  $exclude = $options['exclude'] ?? FALSE ? explode(',', $options['exclude']) : [];
  $onlyTheseChecks = $options['only-these-checks'] ?? FALSE ? explode(',', $options['only-these-checks']) : [];
  $include_disabled = $options['include-disabled'] ?? FALSE;

  if ($prot == 'cv') {
    $webroot = $options['webroot'];
    $cvPath = $options['cvpath'] ?? '/usr/local/bin/cv';
    $a = getStatusLocal($webroot, $cvPath);
  }
  else {
    $api_key = $options['api-key'];
    $site_key = $options['site-key'];
    $host_address = $options['hostname'];
    $cms = $options['cms'] ?? NULL;
    $path = $options['path'] ?? getPath($cms);
    $a = getStatusRemote($prot, $host_address, $path, $site_key, $api_key, $onlyTheseChecks, $include_disabled);
  }

  systemCheck($a, $show_hidden, $warning_threshold, $critical_threshold, $exclude);
}

function getPath(?string $cms) {
  $path = NULL;
  switch (strtolower($cms)) {
    case 'joomla':
      $path = 'administrator/components/com_civicrm/civicrm/extern/rest.php';

    // This assumes WP has Clean URLs enabled.
    case 'wordpress':
    case 'backdrop':
    case 'drupal':
    case 'drupal8':
      $path = 'civicrm/ajax/api4';
      break;
  }
  if (!$path) {
    echo "You must specify either a valid CMS or a REST endpoint path.";
    exit(3);
  }
  return $path;
}

/**
 * Given an array of command-line options, do some sanity checks, bail if missing required fields etc.
 * @param array $options
 */
function checkRequired($options) {
  if ($options['protocol'] == 'cv') {
    $requiredArguments = ['webroot', 'protocol'];
  }
  else {
    $requiredArguments = ['hostname', 'protocol', 'site-key', 'api-key'];
  }
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
  if (!in_array($options['protocol'], ['http', 'https', 'cv'])) {
    echo '"protocol" argument must be "http", "https", or "cv"' .
    exit(3);
  }
}

function getStatusRemote(string $prot, string $host_address, string $path, string $site_key, string $api_key, array $onlyTheseChecks, bool $include_disabled = FALSE): array {
  // $url = "$prot://$host_address/$path/System/check?XDEBUG_SESSION=VSCODE";
  $url = "$prot://$host_address/$path/System/check";
  $params['includeDisabled'] = $include_disabled;
  if ($onlyTheseChecks) {
    $params['where'] = [['name', 'IN', $onlyTheseChecks]];
  };

  $context = stream_context_create([
    'http' => [
      'method' => 'POST',
      'header' => [
        'Content-Type: application/x-www-form-urlencoded',
        "X-Civi-Auth: Bearer $api_key",
        "X-Civi-Key: $site_key",
        "X-Requested-With: XMLHttpRequest",
        "User-Agent: CiviMonitor",
      ],
    ],
  ]);
  $result = file_get_contents($url, FALSE, $context);
  return json_decode($result, TRUE);
}

function getStatusLocal(string $webroot, string $cvPath): array {
  $result = [];
  exec(escapeshellarg($cvPath) . ' --out=json-strict --cwd=' . escapeshellarg($webroot) . ' api4 System.check', $raw);
  $result['values'] = json_decode(implode("\n", $raw), TRUE);
  return $result;
}

function systemCheck(array $a, bool $show_hidden, int $warning_threshold, int $critical_threshold, array $exclude) {
  $isError = $a['is_error'] ?? $a['error_code'] ?? FALSE;

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
    $allowed_tags = ['<p>', '<br>', '<table>', '<th>', '<thead>', '<tr>', '<td>'];
    $message[] = strip_tags($attrib['title'], $allowed_tags) . ': ' . strip_tags($attrib['message'], $allowed_tags);

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

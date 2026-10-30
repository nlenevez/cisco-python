#!/usr/bin/env php
<?php
/*
 * export_custom_templates.php - export, in one import file, every template on
 * this Cacti that another Cacti doesn't have.
 *
 * Run on the OLD (source) Cacti, from its cli/ directory:
 *
 *   php export_custom_templates.php --stock=new-hashes.txt [--output=FILE] [--list]
 *
 * --stock   One template hash per line, taken from the NEW (target) Cacti. See
 *           contrib/README-templates.md for the query. Anything on this box
 *           whose hash isn't in the list is exported.
 * --output  Where to write the XML (default: custom_templates.xml).
 * --list    Only list what would be exported, and the script/XML files the
 *           custom data input methods and data queries need.
 *
 * Dependencies the target already has (same hash) are left out of the file and
 * resolved by hash when it is imported, so the import never overwrites the
 * target's own copies of stock templates.
 */

require(__DIR__ . '/../include/cli_check.php');
require_once($config['base_path'] . '/lib/export.php');

/* export type => table holding its hash */
$types = array(
	'host_template'       => 'host_template',
	'data_query'          => 'snmp_query',
	'graph_template'      => 'graph_templates',
	'data_template'       => 'data_template',
	'data_input_method'   => 'data_input',
	'cdef'                => 'cdef',
	'vdef'                => 'vdef',
	'gprint_preset'       => 'graph_templates_gprint',
	'data_source_profile' => 'data_source_profiles',
);

$stock_file = '';
$output     = 'custom_templates.xml';
$list_only  = false;

foreach (array_slice($_SERVER['argv'], 1) as $arg) {
	if (strpos($arg, '--stock=') === 0) {
		$stock_file = substr($arg, 8);
	} elseif (strpos($arg, '--output=') === 0) {
		$output = substr($arg, 9);
	} elseif ($arg == '--list') {
		$list_only = true;
	} else {
		print "usage: php export_custom_templates.php --stock=new-hashes.txt [--output=FILE] [--list]\n";
		exit(1);
	}
}

if ($stock_file == '' || !is_readable($stock_file)) {
	print "ERROR: --stock=FILE is required and must be readable\n";
	exit(1);
}

$stock = array();
foreach (file($stock_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
	$line = strtolower(trim($line));
	if (preg_match('/^[0-9a-f]{32}$/', $line)) {
		$stock[$line] = true;
	}
}

if (!cacti_sizeof($stock)) {
	print "ERROR: no hashes found in $stock_file\n";
	exit(1);
}

print 'Target has ' . cacti_sizeof($stock) . " template hashes.\n\n";

/* find every template this box has and the target doesn't */
$custom = array();
$deps   = array();

foreach ($types as $type => $table) {
	$rows = db_fetch_assoc("SELECT id, name, hash FROM `$table` ORDER BY name");

	foreach ($rows as $row) {
		if ($row['hash'] == '') {
			print "WARNING: $type '{$row['name']}' (id {$row['id']}) has no hash, skipped\n";
			continue;
		}

		if (!isset($stock[strtolower($row['hash'])])) {
			$custom[$type][$row['id']] = $row['name'];

			if (!$list_only) {
				$deps = resolve_dependencies($type, $row['id'], $deps);
			}
		}
	}
}

if (!cacti_sizeof($custom)) {
	print "Nothing to export: the target has every template this box has.\n";
	exit(0);
}

foreach ($custom as $type => $items) {
	print "$type (" . cacti_sizeof($items) . "):\n";
	foreach ($items as $id => $name) {
		print "  $name\n";
	}
}

/* files the custom items need on disk */
$files = array();
if (isset($custom['data_input_method'])) {
	foreach (array_keys($custom['data_input_method']) as $id) {
		$s = db_fetch_cell_prepared('SELECT input_string FROM data_input WHERE id = ?', array($id));
		if (preg_match_all('#<path_cacti>/\S+#', $s, $m)) {
			$files = array_merge($files, $m[0]);
		}
	}
}
if (isset($custom['data_query'])) {
	foreach (array_keys($custom['data_query']) as $id) {
		$files[] = db_fetch_cell_prepared('SELECT xml_path FROM snmp_query WHERE id = ?', array($id));
	}
}
if (cacti_sizeof($files)) {
	print "\nFiles to copy to the target as well (<path_cacti> = /var/www/cacti):\n";
	foreach (array_unique($files) as $f) {
		print "  $f\n";
	}
	print "  ...plus any scripts those data query XMLs call (their <script_path>).\n";
}

if ($list_only) {
	exit(0);
}

/* drop dependencies the target already has; the import finds them by hash */
$skipped = 0;
foreach ($deps as $type => $ids) {
	if (!isset($types[$type])) {
		continue;
	}

	foreach ($ids as $id) {
		$hash = db_fetch_cell_prepared("SELECT hash FROM `{$types[$type]}` WHERE id = ?", array($id));
		if (isset($stock[strtolower($hash)])) {
			unset($deps[$type][$id]);
			$skipped++;
		}
	}
}

/* same rendering as get_item_xml() in lib/export.php, over the merged set */
$xml_text = '';
foreach ($deps as $type => $ids) {
	foreach ($ids as $id) {
		switch ($type) {
		case 'graph_template':      $xml_text .= "\n" . graph_template_to_xml($id);      break;
		case 'data_template':       $xml_text .= "\n" . data_template_to_xml($id);       break;
		case 'host_template':       $xml_text .= "\n" . host_template_to_xml($id);       break;
		case 'data_input_method':   $xml_text .= "\n" . data_input_method_to_xml($id);   break;
		case 'data_query':          $xml_text .= "\n" . data_query_to_xml($id);          break;
		case 'gprint_preset':       $xml_text .= "\n" . gprint_preset_to_xml($id);       break;
		case 'cdef':                $xml_text .= "\n" . cdef_to_xml($id);                break;
		case 'vdef':                $xml_text .= "\n" . vdef_to_xml($id);                break;
		case 'data_source_profile': $xml_text .= "\n" . data_source_profile_to_xml($id); break;
		}
	}
}

$xml_indent = '';
foreach (explode("\n", $xml_text) as $line) {
	$xml_indent .= "\t" . $line . "\n";
}

if (file_put_contents($output, '<cacti>' . $xml_indent . '</cacti>') === false) {
	print "ERROR: could not write $output\n";
	exit(1);
}

$count = 0;
foreach ($deps as $ids) {
	$count += cacti_sizeof($ids);
}

print "\nWrote $output: $count items ($skipped dependencies left out because the target has them).\n";

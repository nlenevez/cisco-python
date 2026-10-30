# Copying custom templates to another Cacti

Cacti's Export Templates page exports one template at a time.
`export_custom_templates.php` exports every template the target Cacti doesn't
have (device templates, data queries, graph and data templates, data input
methods, CDEFs, VDEFs, GPRINTs, data source profiles) into one import file.

"Custom" means: its hash isn't on the target. A box upgraded from 0.8.x also
carries stock templates whose hashes differ from a fresh install's; those are
exported too, and import as separate templates rather than replacing the
target's. Dependencies the target already has are left out of the file and
found by hash on import, so the import never changes the target's own templates.

Tested with Cacti 1.2.31 on MariaDB: the export from a box with two extra
template packages imported cleanly into a fresh one, every source hash existed
on the target afterwards, and none of the target's templates changed.

No network is needed between the two boxes: everything moves as files (USB
stick or similar). The stick goes new → old with the hash list, then old → new
with the export and a tar of the scripts.

## 1. New box: list its template hashes → USB

```sh
mysql -N cacti -e "SELECT hash FROM graph_templates UNION SELECT hash FROM data_template
  UNION SELECT hash FROM host_template UNION SELECT hash FROM data_input
  UNION SELECT hash FROM snmp_query UNION SELECT hash FROM graph_templates_gprint
  UNION SELECT hash FROM cdef UNION SELECT hash FROM vdef
  UNION SELECT hash FROM data_source_profiles" > /media/usb/new-hashes.txt
```

## 2. Old box: export templates and files → USB

```sh
cp export_custom_templates.php /var/www/cacti/cli/
cd /var/www/cacti/cli
cp /media/usb/new-hashes.txt /tmp/ && chmod 644 /tmp/new-hashes.txt    # USB mounts are often root-only
sudo -u nginx php export_custom_templates.php --stock=/tmp/new-hashes.txt --list     # review first
sudo -u nginx php export_custom_templates.php --stock=/tmp/new-hashes.txt --output=/tmp/custom_templates.xml
cp /tmp/custom_templates.xml /media/usb/

# Templates reference scripts and data query XMLs by path; the import doesn't
# carry them. Take scripts/ and resource/ whole.
tar -C /var/www/cacti -czf /media/usb/cacti-scripts-resource.tgz scripts resource
(cd /media/usb && sha256sum custom_templates.xml cacti-scripts-resource.tgz > SHA256SUMS)
```

`--list` prints each template that will go across, and the files they need.

## 3. New box: add the missing files

```sh
(cd /media/usb && sha256sum -c SHA256SUMS)
cp /media/usb/custom_templates.xml /tmp/ && chmod 644 /tmp/custom_templates.xml
tar -C /var/www/cacti --skip-old-files -xzf /media/usb/cacti-scripts-resource.tgz
chown -R nginx:nginx /var/www/cacti/{scripts,resource}
restorecon -Rv /var/www/cacti/{scripts,resource}
fapolicyd-cli --file update /var/www/cacti/ && fapolicyd-cli --update
```

`--skip-old-files` only adds files the new box doesn't have, so its own 1.2.31
copies stay.

## 4. New box: import

```sh
sudo -u nginx php /var/www/cacti/cli/import_template.php --filename=/tmp/custom_templates.xml --with-profile --preview
sudo -u nginx php /var/www/cacti/cli/import_template.php --filename=/tmp/custom_templates.xml --with-profile
```

`--preview` shows what would be created without changing anything. Every line
should say `[new]`. Or use Console → Import/Export → Import Templates with the
same file.

To check, run step 1 again and take the new list back to the old box: step 2
with `--list` should report "Nothing to export".

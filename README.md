# Galaxy Dataset Exporter

This tool will transfer datasets to a network share or local disk. Allowed locations can be specified in the 
`config.yaml` and predefined locations including the user help text can be set in `predefined_export_paths.xml`.

## DANGERS

- We take no responsibility if you lose data (that should be obvious..)
- Have backups
- Test this tool thoroughly yourself before given your users access to this. 
- While testing, maybe uncomment the `#if $is_admin:` check in the `dataset-exporter.xml` to see what happens or log in
as a regular user.
- File paths are not sanitized in the xml, but should be in python code, then again, critical processes are launched 
with `shell=True` 😬
- Feel free to modify to your liking and/or submit issues or PRs

## Description

Allow users to export one or more datasets/collections to a given path. These can be predefined(`predefined_export_paths.xml`)
or custom paths but limited to those described in `config.yaml`.

Resulting file names can be based on various datasets attributes as can be seen in the tool help.

## Permission checks and resolving usernames and groups

For some permission checking and constructing file names, we resolve the username using `resolve_username.sh` and
the users primary group through `id -gn`. If you need something else, just modify this.


## Example

Example log snippet of exporting a `Collection` named `TrimGalore Reports` with two report files with:
``/scratch/{username}/galaxy_transfer/atac-test/qc/trimGalore/{collection}_{name}`` as custom file pattern.

```
(..)
INFO: Resolved new path: '/scratch/scholtal/galaxy_transfer/atac-test/qc/trimGalore/TrimGalore_Reports_atac_test2.txt'
INFO: Copied: '/g/funcgen/galaxy-production/database/files/063/dataset_63965.dat' (atac_test2.txt) -> '/scratch/scholtal/galaxy_transfer/atac-test/qc/trimGalore/TrimGalore_Reports_atac_test2.txt'.
``` 

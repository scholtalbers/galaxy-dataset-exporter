# -*- coding: utf-8 -*-
import argparse
import copy
import json
import logging
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path

import yaml
from yaml.scanner import ScannerError

logger = logging.getLogger()

# Command to that takes a username and email address as arguments and returns the unix username.

script_path = Path(sys.argv[0]).parent
username_resolver_location = script_path / "resolve_username.sh"
USERNAME_COMMAND = ["bash", str(username_resolver_location), "{username}", "{email}"]
# Command that takes a username as a single argument and returns all groups the user belongs to.
GROUPS_COMMAND = ["id", "-Gn", "{username}"]
GROUP_IDS_COMMAND = ["id", "-G", "{username}"]
# Command that takes a username as a single argument and returns the primary group"
PRIMARY_GROUP_COMMAND = ["id", "-gn", "{username}"]
UMASK = 0o002
CHMOD = 0o664

with open(script_path / "config.yaml") as c:
    try:
        config = yaml.load(c, Loader=yaml.FullLoader)
    except ScannerError:
        logger.exception("Config yaml file incorrect.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Input/Output")
    parser.add_argument("--dry_run", action="store_true", default=False)
    parser.add_argument("--email")
    parser.add_argument("--username")

    parser.add_argument("--dataset", action="append")
    parser.add_argument("--dataset_name", action="append")
    parser.add_argument("--dataset_extension", action="append")
    parser.add_argument("--dataset_extra_files", action="append")
    parser.add_argument("--collection_name", action="append")
    parser.add_argument("--dataset_tags", action="append")
    parser.add_argument("--history_id", action="append")
    parser.add_argument("--history_name", action="append")

    # output
    parser.add_argument("--file_pattern")
    parser.add_argument("--copy_extra_files", action="store_true", default=False)
    parser.add_argument("--export_metadata", action="store_true", default=False)
    parser.add_argument("--loglevel", default="DEBUG")
    parser.add_argument("--log", default=None)

    # permission related settings
    parser.add_argument("--group_readonly", action="store_true", default=False,
                        help="chmod 640 on exported files.")
    parser.add_argument("--skip_user_permission_check", action="store_true",
                        default=False, help="Check that the user has read&write permissions to the provided directory.")
    parser.add_argument("--run_with_primary_group", action="store_true",
                        default=False,
                        help="Try to create directories and files with the user's primary group set using"
                             "sg - primary_group -c '[cmd]'. This can only work if this script is"
                             "executed by a (system) user with this group membership.")

    args = parser.parse_args()

    loglevel = getattr(logging, args.loglevel.upper())
    logging.basicConfig(level=loglevel,
                        format="%(levelname)s: %(message)s")

    if args.log:
        ch = logging.FileHandler(filename=args.log)
        ch.setLevel(loglevel)
        formatter = logging.Formatter("%(levelname)s: %(message)s")
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    if args.dry_run:
        logger.info("Dry run activated - not copying any files!")

    try:
        username = resolve_username(args.username, args.email)
        logger.debug(f"Found username: '{username}'")
        primary_group, groups, group_ids = resolve_groups(username)
        group_id_str = ", ".join(map(str, group_ids))
        logger.debug(f"Found primary group: '{primary_group}', group names: '{', '.join(groups)}' and ids: "
                     f"'{group_id_str}'")
    except KeyError as e:
        logger.exception(e)
        logger.critical(f"Cannot find unix username by '{args.email}'. Please contact your Galaxy administrator.")
        sys.exit(1)

    global UMASK
    global CHMOD
    if args.group_readonly:
        UMASK = 0o027
        CHMOD = 0o640
    elif not args.run_with_primary_group:
        # ignore umask - we want 0o777
        UMASK = 0
        CHMOD = 0o666  # only affects the metadata file
        os.umask(UMASK)

    copy_datasets(args, username, primary_group, groups, group_ids)


def parse_tags(tag_string):
    all_tags = []
    simple_tags = []
    named_tags = {}
    for tag in tag_string.split(","):
        if tag:
            all_tags.append(tag)
            if ":" in tag:
                name, value = tag.split(":", 1)
                named_tags[name] = value
            else:
                simple_tags.append(tag)
    return all_tags, simple_tags, named_tags


def copy_datasets(args, username, primary_group, groups, group_ids):
    for i, dataset in enumerate(args.dataset):
        all_tags, simple_tags, named_tags = parse_tags(args.dataset_tags[i])
        file_pattern_map = {
            "username": username,
            "group": primary_group,
            "email": args.email,
            "name": args.dataset_name[i],
            "ext": args.dataset_extension[i],
            "history": args.history_name[i],
            "hid": args.history_id[i],
            "tags": "_".join(all_tags),
            "collection": args.collection_name[i]
        }
        metadata = generate_metadata(file_pattern_map, simple_tags, named_tags)
        logger.debug(f"Got following metadata:\n{json.dumps(metadata)}")
        new_path, pattern_found = resolve_path(args, file_pattern_map, groups, named_tags)
        if os.path.exists(new_path):
            logger.critical(f"Path '{new_path}' already existing, we will not overwrite this file. "
                            f"Change the destination or (re)move the existing file.")
            sys.exit(1)

        if create_path(args, new_path, pattern_found, username, primary_group, group_ids):
            metadata_path = f"{new_path}.info"
            if args.dry_run:
                logger.debug(f"Would have copied: '{dataset}' ({file_pattern_map['name']}) -> '{new_path}'.")
                if args.export_metadata:
                    logger.debug(f"Would have exported the metadata to {metadata_path}")
            else:
                copy_dataset(args, dataset, args.dataset_extra_files[i], file_pattern_map, metadata, metadata_path,
                             new_path, primary_group)
        else:
            logger.critical("You do not have permission or the directory does not exists yet.")
            sys.exit(1)


def copy_dataset(args, dataset, dataset_extra_files, file_pattern_map, metadata, metadata_path, new_path,
                 primary_group):
    try:
        # do the actual copy
        run_command(["cp", "--no-preserve", "mode", dataset, new_path], {}, "Copying dataset with '%s'",
                    raise_exception=True, sg_group=primary_group, args=args)
        logger.info(f"Copied: '{dataset}' ({file_pattern_map['name']}) -> '{new_path}'.")
        if args.copy_extra_files and os.path.exists(dataset_extra_files):
            new_extra_path = f"{new_path}_files"
            logger.info(f"Will try to copy extra files to '{new_extra_path}'")
            run_command(["cp", "-r", "--no-preserve", "mode", dataset_extra_files, new_extra_path],
                        {}, "Copying extra datasets with '%s'", raise_exception=True,
                        sg_group=primary_group, args=args)
    except OSError as e:
        handle_oserror(args, e, new_path)
    except Exception as e:
        logger.exception(f"Cannot copy file '{dataset}' -> '{new_path}'.")
        sys.exit(1)

    if args.export_metadata:
        logger.debug(f"Exporting metadata with chmod: {CHMOD}")
        os.umask(0)
        # stat.S_IRWXU | stat.S_IRWXO
        with open(os.open(metadata_path, os.O_CREAT | os.O_WRONLY, CHMOD), "w") as info:
            json.dump(metadata, info, indent=2)
        logger.info(f"Exported the metadata to {metadata_path}")


def handle_oserror(args, e, new_path):
    if e.errno == 13:
        msg = "Galaxy cannot copy the file to the destination path. Please make sure the galaxy user has write " \
              "permission on the given path. "
        dirname = os.path.dirname(new_path)
        if args.run_with_primary_group:
            msg += f"`chmod g+w {dirname}` might just do the trick."
        else:
            msg += f"`chmod og+w {dirname}` might be needed!"
        logger.critical(msg)
    else:
        logger.critical(e)
    sys.exit(1)


def resolve_username(username, email):
    return run_command(USERNAME_COMMAND, {"email": email, "username": username}, "Getting username with: '%s'")


def subprocess_umask():
    os.setpgrp()
    os.umask(UMASK)


def run_command(command_list, format_dict, msg, raise_exception=False, sg_group=None, args=None):
    cmd = []
    for cmd_part in command_list:
        cmd.append(cmd_part.format(**format_dict))
    logger.debug(msg, cmd)
    subprocess_kwargs = {"preexec_fn": subprocess_umask, "encoding": "utf-8"}
    if sg_group and args and args.run_with_primary_group:
        # sg - group -c 'cmd'
        subprocess_kwargs["shell"] = True
        cmd = "sg - {} -c '{}'".format(sg_group, " ".join(cmd))
    try:
        return subprocess.check_output(cmd, **subprocess_kwargs).strip()
    except subprocess.CalledProcessError as e:
        if raise_exception:
            raise e
        logger.critical(e)
        sys.exit(1)


def generate_metadata(file_pattern_map, tags, named_tags):
    metadata = copy.deepcopy(file_pattern_map)
    metadata["tags"] = named_tags
    for tag in tags:
        metadata["tags"][tag] = None
    return metadata


def resolve_groups(username):
    primary_group = run_command(PRIMARY_GROUP_COMMAND, {"username": username}, "Getting primary_group with: '%s'")
    groups_out = run_command(GROUPS_COMMAND, {"username": username}, "Getting groups with: '%s'")
    groups = groups_out.split(" ")
    group_ids_out = run_command(GROUP_IDS_COMMAND, {"username": username}, "Getting group ids with '%s'")
    group_ids = map(int, group_ids_out.split(" "))
    return primary_group, groups, group_ids


def user_can_write_dir(directory, username, group_ids):
    pwd_user = pwd.getpwnam(username)
    stat_info = os.stat(directory)
    logger.debug(f"Directory '{directory}' permissions: '{oct(stat_info.st_mode)}' ({stat_info.st_mode})")
    logger.debug(f"Directory owned by user id: {stat_info.st_uid}")
    logger.debug(f"Directory owned by group: {stat_info.st_gid}")
    logger.debug(f"Directory group id in user group ids: {stat_info.st_gid in group_ids}")
    logger.debug(f"Directory writable by owner: {stat_info.st_mode & stat.S_IWUSR}")
    logger.debug(f"Directory writable by group: {stat_info.st_mode & stat.S_IWGRP}")
    logger.debug(f"Directory writable by others: {stat_info.st_mode & stat.S_IWOTH}")
    return (stat_info.st_uid == pwd_user.pw_uid and stat_info.st_mode & stat.S_IWUSR) or \
           (stat_info.st_gid in group_ids and stat_info.st_mode & stat.S_IWGRP) or \
           (stat_info.st_mode & stat.S_IWOTH)


def check_permission(path, pattern_found, username, group_ids):
    """

    The config['required_path_patterns'] specify the directory that the user needs to have at least write
    permission for. `pattern_found` holds the required pattern that was found when resolving the path.
    If the rest of the path is not existing, this will be allowed.
    If the path is already existing we check those permissions.

    e.g. for /g/furlong/scholtal/newdirectory/1.fa ->
    /g/furlong/scholtal is existing and user needs to have write permission on this directory.
    newdirectory will be created.
    If /g/furlong/scholtal is also not existing, the user needs to have write permissions on /g/furlong
    as that is the value of `pattern_found`
    """
    logger.info(f"Checking directory: {path}")
    if os.path.exists(path):
        user_can_write_dir_out = user_can_write_dir(path, username, group_ids)
        logger.info(f"Permission check out: {user_can_write_dir_out}")
        if user_can_write_dir_out:
            logger.info("Directory is writable by the user.")
            return True
        else:
            logger.info("Directory is not writable by the user.")
            return False
    elif os.path.normpath(path) == os.path.normpath(pattern_found):
        # the root directory - i.e. the required pattern does not exist yet, we will not create this
        logger.debug("Maximum parent reached, will not traverse further.")
        return False
    logger.debug(f"Path not yet existing: '{path}'")
    # if not yet existing, then check the parent directory till we find an existing one
    parent_directory = os.path.dirname(path)
    return check_permission(parent_directory, pattern_found, username, group_ids)


def create_path(args, path, pattern_found, username, primary_group, group_ids, create_as_directory=False):
    """
    Create path and check permissions
    """
    directory_path = path
    if not create_as_directory:
        directory_path = os.path.dirname(path)
    dir_exists = os.path.exists(directory_path)
    if args.skip_user_permission_check:
        can_write = True
    else:
        can_write = check_permission(directory_path, pattern_found, username, group_ids)
    if can_write and not dir_exists:
        if args.dry_run:
            logger.info("Would have created directory: '{directory_path}'")
        else:
            try:
                logger.info("Creating directory: '{directory_path}'")
                run_command(["mkdir", "-p", directory_path], {}, "Creating directory: '%s'", raise_exception=True,
                            sg_group=primary_group, args=args)
            except subprocess.CalledProcessError as e:
                msg = "Galaxy cannot create the directory path. Please make sure the galaxy user has write permission" \
                      " on the given path. "
                if args.run_with_primary_group:
                    msg += f"`chmod g+w {directory_path}` might just do the trick."
                else:
                    msg += f"`chmod og+w {directory_path}` might be needed!"

                sys.exit(1)
    return can_write


def get_valid_filepath(path):
    directory = get_valid_directory(os.path.dirname(path))
    filename = get_valid_filename(os.path.basename(path))
    return os.path.join(directory, filename)


def get_valid_directory(directory):
    directory = str(directory).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w./]', '', directory)


def get_valid_filename(filename):
    """
    From https://github.com/django/django/blob/master/django/utils/text.py#L219
    """
    filename = str(filename).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', filename)


def string_replace_named_tags(file_pattern, named_tags):
    """
    e.g. a dataset  `SeqX_from_PMID_{tag:PMID}.fa` with the tag `#PMID:23002` becomes `SeqX_from_PMID_23002.fa`
    """
    for match in re.finditer(r"({tag:(?P<key>.+?)})", file_pattern):
        # every key has to be present in the named tags or we fail
        tag_name = match.group("key")
        try:
            file_pattern = re.sub(match.group(0), named_tags[tag_name], file_pattern)
        except KeyError:
            logger.critical(f"Could not find named tag '{tag_name}' mentioned in pattern on dataset, "
                            f"dataset only has the following tags:\n{', '.join(named_tags.keys())}")
            sys.exit(1)
    return file_pattern


def resolve_path(args, file_pattern_map, groups, named_tags):
    file_pattern = args.file_pattern
    logger.info(f"Got file pattern: {file_pattern}")
    pattern_found = None
    if not args.skip_user_permission_check:
        # for each group a different pattern map
        file_pattern_maps = []
        for group in groups:
            alt_file_pattern_map = copy.deepcopy(file_pattern_map)
            alt_file_pattern_map["group"] = group
            file_pattern_maps.append(alt_file_pattern_map)
        for pattern in config["required_path_patterns"]:
            if file_pattern.startswith(pattern):
                pattern_found = pattern
            else:
                for _pattern_map in file_pattern_maps:
                    if file_pattern.startswith(pattern.format(**_pattern_map)):
                        pattern_found = pattern
                        break
        if not pattern_found:
            logger.critical(f"Given file pattern does not match the required path prefix e.g.\n"
                            f"{', '.join(config['required_path_patterns'])}.")
            sys.exit(1)
    else:
        pattern_found = file_pattern

    # first string replace any named tags
    file_pattern = string_replace_named_tags(file_pattern, named_tags)

    # then any other keys will be matched
    try:
        new_path_mapped = file_pattern.format(**file_pattern_map)
    except KeyError as e:
        logger.critical(f"Given file pattern cannot be resolved. Cannot match '{e.args[0]}'")
        sys.exit(1)
    except ValueError as e:
        logger.critical("Given file pattern cannot be resolved. '{e}'")
        sys.exit(1)

    pattern_found = string_replace_named_tags(pattern_found, named_tags)
    pattern_found = pattern_found.format(**file_pattern_map)

    logger.debug(f"Make given file path '{new_path_mapped}' valid")
    new_path_mapped = get_valid_filepath(new_path_mapped)

    logger.debug("Constructed new path: '{new_path_mapped}'")
    new_path = os.path.realpath(new_path_mapped)
    logger.info("Resolved new path: '{new_path_mapped}'")
    return new_path, pattern_found


if __name__ == "__main__":
    main()

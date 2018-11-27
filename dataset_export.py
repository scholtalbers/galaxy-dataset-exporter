# -*- coding: utf-8 -*-
import argparse
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import yaml
import pwd

from yaml.scanner import ScannerError

logger = logging.getLogger()


# Command to that takes a username and email address as arguments and returns the unix username.
script_path = os.path.dirname(os.path.realpath(sys.argv[0]))
username_resolver_location = os.path.join(script_path, "resolve_username.sh")
groups_resolver_location = os.path.join(script_path, "resolve_groups.sh")
USERNAME_COMMAND=["bash", username_resolver_location, "{username}", "{email}"]
# Command that takes a username as a single argument and returns all groups the user belongs to.
GROUPS_COMMAND=["id", "-Gn", "{username}"]
GROUP_IDS_COMMAND=["id", "-G", "{username}"]
# Command that takes a username as a single argument and returns the primary group"
PRIMARY_GROUP_COMMAND=["id", "-gn", "{username}"]

with open(os.path.join(script_path, "config.yaml")) as c:
    try:
        config = yaml.load(c)
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
    parser.add_argument("--collection_name", action="append")
    parser.add_argument("--dataset_tags", action="append")
    parser.add_argument("--history_id", action="append")
    parser.add_argument("--history_name", action="append")

    # output
    parser.add_argument("--file_pattern")
    parser.add_argument("--loglevel", default="DEBUG")
    parser.add_argument("--log", default=None)

    # permission related settings
    parser.add_argument("--skip_user_permission_check", action="store_true",
                        default=False, help="Check that the user has read&write permissions to the provided directory.")
    parser.add_argument("--run_with_primary_group", action="store_true",
                        default=False, help="Try to create directories and files with the user's primary group set using"
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
        logger.debug("Found username: '%s'", username)
        primary_group, groups, group_ids = resolve_groups(username)
        logger.debug("Found primary group: '%s', group names: '%s' and ids: '%s'",
                     primary_group, ", ".join(groups), ", ".join(map(str, group_ids)))
    except KeyError as e:
        logger.exception(e)
        logger.critical("Cannot find unix username by '%s'. Please contact your Galaxy administrator.", args.email)
        sys.exit(1)

    # ignore umask - we want 0o777
    os.umask(0)
    copy_datasets(args, username, primary_group, groups, group_ids)


def copy_datasets(args, username, primary_group, groups, group_ids):
    for i, dataset in enumerate(args.dataset):
        tags = []
        if args.dataset_tags[i]:
            for tag in args.dataset_tags[i].split(","):
                if tag and tag != "None":
                    tags.append(tag)
        file_pattern_map = {
            "username": username,
            "group": primary_group,
            "email": args.email,
            "name": args.dataset_name[i],
            "ext": args.dataset_extension[i],
            "history": args.history_name[i],
            "hid": args.history_id[i],
            "tags": "_".join(args.dataset_tags),
            "collection": args.collection_name[i]
        }
        new_path, pattern_found = resolve_path(args, file_pattern_map)
        if os.path.exists(new_path):
            logger.critical("Path '%s' already existing, we will not overwrite this file. Change the destination or "
                            "(re)move the existing file.", new_path)
            sys.exit(1)

        if create_path(args, new_path, pattern_found, username, primary_group, group_ids):
            if args.dry_run:
                logger.debug("Would have copied: '%s' (%s) -> '%s'.", dataset, file_pattern_map["name"], new_path)
            else:
                try:
                    # do the actual copy
                    shutil.copyfile(dataset, new_path)
                    logger.info("Copied: '%s' (%s) -> '%s'.", dataset, file_pattern_map["name"], new_path)
                except OSError as e:
                    if e.errno == 13:
                        logger.critical("Galaxy cannot copy the file to the destination path. Please make sure the galaxy "
                                        "user has write permission on the given path. "
                                        "`chmod g+w %s` might just do the trick.", os.path.dirname(new_path))
                    else:
                        logger.critical(e)
                    sys.exit(1)
                except Exception as e:
                    logger.exception(e)
                    logger.critical("Cannot copy file '%s' -> '%s'.", dataset, new_path)
                    sys.exit(1)

        else:
            logger.critical("You do not have permission or the directory does not exists yet.")
            sys.exit(1)


def resolve_username(username, email):
    return run_command(USERNAME_COMMAND, {"email": email, "username": username}, "Getting username with: '%s'")


def run_command(command_list, format_dict, msg, raise_exception=False, sg_group=None, args=None):
    cmd = []
    for cmd_part in command_list:
        cmd.append(cmd_part.format(**format_dict))
    logger.debug(msg, cmd)

    if sg_group and args and args.run_with_primary_group:
        # sg - group -c 'cmd'
        cmd = ["sg", "-", sg_group, "-c", "'{}'".format(" ".join(cmd))]
    try:
        return subprocess.check_output(cmd).strip()
    except subprocess.CalledProcessError as e:
        if raise_exception:
            raise
        logger.critical(e)
        sys.exit(1)


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
    logger.debug("Directory '%s' permissions: '%s' (%s)", directory, oct(stat_info.st_mode), stat_info.st_mode)
    logger.debug("Directory owned by user id: %s", stat_info.st_uid)
    logger.debug("Directory owned by group: %s", stat_info.st_gid)
    logger.debug("Directory group id in user group ids: %s", stat_info.st_gid in group_ids)
    logger.debug("Directory writable by owner: %s", stat_info.st_mode & stat.S_IWUSR)
    logger.debug("Directory writable by group: %s", stat_info.st_mode & stat.S_IWGRP)
    logger.debug("Directory writable by others: %s", stat_info.st_mode & stat.S_IWOTH)
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
    logger.info("Checking directory: %s", path)
    if os.path.exists(path):
        user_can_write_dir_out = user_can_write_dir(path, username, group_ids)
        logger.info("Permission check out: %s", user_can_write_dir_out)
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
    logger.debug("Path not yet existing: '%s'", path)
    # if not yet existing, then check the parent directory till we find an existing one
    parent_directory = os.path.dirname(path)
    return check_permission(parent_directory, pattern_found, username, group_ids)


def create_path(args, path, pattern_found, username, primary_group, group_ids):
    """
    Create path and check permissions
    """
    directory_path = os.path.dirname(path)
    dir_exists = os.path.exists(directory_path)
    if args.skip_user_permission_check:
        can_write = True
    else:
        can_write = check_permission(directory_path, pattern_found, username, group_ids)
    if can_write and not dir_exists:
        if args.dry_run:
            logger.info("Would have created directory: '%s'", directory_path)
        else:
            try:
                logger.info("Creating directory: '%s'", directory_path)
                run_command(["mkdir", "-p", directory_path], raise_exception=True, sg_group=primary_group)
            except subprocess.CalledProcessError as e:
                if "Permission denied" in e.output.decode():
                    logger.critical("Galaxy cannot create the directory path. Please make sure the galaxy user has"
                                    "write permission on the given path. `chmod g+w %s` might just do the trick.",
                                    directory_path)
                else:
                    logger.critical(e.output.decode())
                sys.exit(1)
    return can_write


def get_valid_filepath(path):
    directory = get_valid_directory(os.path.dirname(path))
    filename = get_valid_filename(os.path.basename(path))
    return os.path.join(directory, filename)


def get_valid_directory(directory):
    directory = str(directory).strip().replace(' ', '_')
    return directory


def get_valid_filename(filename):
    """
    From https://github.com/django/django/blob/master/django/utils/text.py#L219
    """
    filename = str(filename).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', filename)


def resolve_path(args, file_pattern_map):
    file_pattern = args.file_pattern
    logger.info("Got file pattern: %s", file_pattern)
    pattern_found = None
    if not args.skip_user_permission_check:
        for pattern in config["required_path_patterns"]:
            if file_pattern.startswith(pattern) or file_pattern.startswith(pattern.format(**file_pattern_map)):
                pattern_found = pattern
        if not pattern_found:
            logger.critical("Given file pattern does not match the required path prefix e.g.\n%s.",
                            ", ".join(config['required_path_patterns']))
            sys.exit(1)
    else:
        pattern_found = file_pattern
    try:
        new_path_mapped = file_pattern.format(**file_pattern_map)
    except KeyError as e:
        logger.critical("Given file pattern cannot be resolved. Cannot match '{%s}'", e.args[0])
        sys.exit(1)
    except ValueError as e:
        logger.critical("Given file pattern cannot be resolved. '%s'", e)
        sys.exit(1)

    pattern_found = pattern_found.format(**file_pattern_map)

    logger.debug("Make given file path '%s' valid", new_path_mapped)
    new_path_mapped = get_valid_filepath(new_path_mapped)

    logger.debug("Constructed new path: '%s'", new_path_mapped)
    new_path = os.path.realpath(new_path_mapped)
    logger.info("Resolved new path: '%s'", new_path_mapped)
    return new_path, pattern_found

if __name__ == "__main__":
    main()




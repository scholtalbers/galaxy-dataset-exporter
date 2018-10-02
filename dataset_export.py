# -*- coding: utf-8 -*-
import argparse
import logging
import os
import re
import shutil
import subprocess
import sys


logger = logging.getLogger(__name__)

# Command to that takes an email address as a single argument and returns the unix username.
script_path = os.path.dirname(os.path.realpath(sys.argv[0]))
resolver_location = os.path.join(script_path, "resolve_username.sh")
USERNAME_COMMAND=["bash", resolver_location]
# Command that takes a username as a single argument and returns all groups the user belongs to."
GROUPS_COMMAND=["groups"]
# Command that takes a username as a single argument and returns the primary group"
PRIMARY_GROUP_COMMAND=["id", "-gn"]

REQUIRED_PATH_PATTERN=[
    "/tmp/test/",
    "/scratch/{username}/", "/g/{group}/galaxy_transfer/", "/g/aulelha/WaveletMovieBatchG/",
]


def main():
    parser = argparse.ArgumentParser(
        description="Input/Output")

    parser.add_argument("--dataset", action="append")
    parser.add_argument("--dataset_name", action="append")
    parser.add_argument("--dataset_extension", action="append")
    parser.add_argument("--dataset_tags", action="append")
    parser.add_argument("--history_id", action="append")
    parser.add_argument("--history_name", action="append")

    # output
    parser.add_argument("--file_pattern")
    parser.add_argument("--email")
    parser.add_argument("--loglevel", default="DEBUG")

    # permission related settings
    parser.add_argument("--check-user-permissions", dest="check_user_permissions",
                        default=True, help="Check that the user has read&write permissions to the provided directory.")

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.loglevel.upper()))

    logger.info(args)

    username = None
    primary_group = None
    groups = []
    try:
        username = resolve_username(args.email)
        logger.debug("Found username: '%s'", username)
        primary_group, groups = resolve_groups(username)
        logger.debug("Found primary group: '%s' and groups: '%s'", primary_group, groups)
    except KeyError:
        logger.critical("Cannot find unix username by '%s'. Please contact your Galaxy administrator.", args.email)
        sys.exit(1)

    copy_datasets(args, username, primary_group, groups)


def copy_datasets(args, username, primary_group, groups):
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
            "name": args.dataset_names[i],
            "ext": args.dataset_extension[i],
            "history": args.history_name[i],
            "hid": args.history_id[i],
            "tags": "_".join(args.dataset_tags)
        }
        new_path = resolve_path(args.file_pattern, file_pattern_map)
        #check_path_permissions(new_path, username, groups)
        try:
            # do the actual copy
            shutil.copy2(dataset, new_path)
            logger.info("Copied: '%s' (%s) -> '%s'.", dataset, file_pattern_map["name"], new_path)
        except Exception as e:
            logger.exception(e)
            logger.critical("Cannot copy file '%s' -> '%s'.", dataset, new_path)
            sys.exit(1)


def resolve_username(email):
    cmd = USERNAME_COMMAND + [email]
    logger.critical("Getting username with: '%s'", cmd)
    return subprocess.check_output(cmd).strip()


def resolve_groups(username):
    cmd = PRIMARY_GROUP_COMMAND + [username]
    logger.critical("Getting primary_group with: '%s'", cmd)
    primary_group = subprocess.check_output(cmd).strip()
    cmd = GROUPS_COMMAND + [username]
    logger.critical("Getting groups with: '%s'", cmd)
    groups = subprocess.check_output(cmd).strip()
    return primary_group, groups

def get_valid_filename(s):
    """
    From https://github.com/django/django/blob/master/django/utils/text.py#L219
    """
    s = str(s).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)


def resolve_path(file_pattern, file_pattern_map):
    pattern_found = False
    for pattern in REQUIRED_PATH_PATTERN:
        if file_pattern.startswith(pattern):
            pattern_found = True
        elif file_pattern.startswith(pattern.format(**file_pattern_map)):
            pattern_found = True
    if not pattern_found:
        logger.critical("Given file pattern does not match the required path prefix e.g. /g/{group} or /scratch/{username}.")
        sys.exit(1)

    new_path_mapped = file_pattern.format(**file_pattern_map)
    new_path_mapped = get_valid_filename(new_path_mapped)

    logger.debug("Constructed new_path: '%s'", new_path_mapped)
    new_path = os.path.realpath(new_path_mapped)
    logger.debug("Resolved new_path: '%s'", new_path_mapped)
    return new_path

if __name__ == "__main__":
    main()




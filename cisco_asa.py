import re
import sys
from collections import defaultdict

def parse_asa_config(file_path):
    with open(file_path, 'r') as file:
        config_lines = file.readlines()

    access_lists = defaultdict(list)
    objects = defaultdict(set)

    # Regular expressions to match access-list and object definitions
    acl_pattern = re.compile(r'access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)')
    object_group_pattern = re.compile(r'object-group\s+(network|service)\s+(\S+)')
    object_pattern = re.compile(r'object\s+(network|service)\s+(\S+)')

    for line in config_lines:
        line = line.strip()

        # Match access-list entries
        acl_match = acl_pattern.match(line)
        if acl_match:
            acl_name = acl_match.group(1)
            action = acl_match.group(2)
            protocol = acl_match.group(3)
            src = acl_match.group(4)
            src_detail = acl_match.group(5)
            dst = acl_match.group(6)
            dst_detail = acl_match.group(7)

            access_lists[acl_name].append({
                'action': action,
                'protocol': protocol,
                'src': src,
                'src_detail': src_detail,
                'dst': dst,
                'dst_detail': dst_detail
            })

            # Collect referenced objects
            for item in [src, src_detail, dst, dst_detail]:
                if item.startswith('object') or item.startswith('object-group'):
                    objects[acl_name].add(item)

        # Match object-group definitions
        og_match = object_group_pattern.match(line)
        if og_match:
            pass  # Extend here if you want to store object-group definitions

        # Match object definitions
        obj_match = object_pattern.match(line)
        if obj_match:
            pass  # Extend here if you want to store object definitions

    return access_lists, objects

def print_acl_objects(access_lists, objects):
    for acl_name, entries in access_lists.items():
        print(f"\nAccess-list: {acl_name}")
        print("Entries:")
        for entry in entries:
            print(f"  {entry}")
        print("Referenced Objects:")
        for obj in objects[acl_name]:
            print(f"  {obj}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python asa_acl_object_analyzer.py <asa_config_file>")
        sys.exit(1)

    config_file_path = sys.argv[1]
    access_lists, objects = parse_asa_config(config_file_path)
    print_acl_objects(access_lists, objects)

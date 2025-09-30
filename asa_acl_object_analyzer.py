import re
import sys
from collections import defaultdict

def parse_asa_config(file_path):
    with open(file_path, 'r') as file:
        config_lines = [line.strip() for line in file.readlines()]

    access_lists = defaultdict(list)
    object_groups = defaultdict(list)
    objects = {}

    # Regular expressions
    acl_pattern = re.compile(r'access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)')
    object_group_start = re.compile(r'object-group\s+(network|service)\s+(\S+)')
    object_start = re.compile(r'object\s+(network|service)\s+(\S+)')
    host_pattern = re.compile(r'host\s+(\S+)')
    subnet_pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})')
    port_pattern = re.compile(r'(eq|range)\s+(.+)')

    current_group = None
    current_object = None
    in_group = False

    for line in config_lines:
        # Access-list parsing
        acl_match = acl_pattern.match(line)
        if acl_match:
            acl_name = acl_match.group(1)
            entry = {
                'action': acl_match.group(2),
                'protocol': acl_match.group(3),
                'src': acl_match.group(4),
                'src_detail': acl_match.group(5),
                'dst': acl_match.group(6),
                'dst_detail': acl_match.group(7)
            }
            access_lists[acl_name].append(entry)
            continue

        # Object-group parsing
        og_match = object_group_start.match(line)
        if og_match:
            current_group = og_match.group(2)
            in_group = True
            continue

        if in_group and line.startswith('object-group'):
            current_group = None
            in_group = False

        if in_group and current_group:
            object_groups[current_group].append(line)
            continue

        # Object parsing
        obj_match = object_start.match(line)
        if obj_match:
            current_object = obj_match.group(2)
            objects[current_object] = []
            continue

        if current_object:
            if line.startswith('host'):
                host_match = host_pattern.match(line)
                if host_match:
                    objects[current_object].append({'type': 'host', 'value': host_match.group(1)})
            elif subnet_pattern.match(line):
                subnet_match = subnet_pattern.match(line)
                objects[current_object].append({'type': 'subnet', 'ip': subnet_match.group(1), 'mask': subnet_match.group(2)})
            elif port_pattern.match(line):
                port_match = port_pattern.match(line)
                objects[current_object].append({'type': 'port', 'method': port_match.group(1), 'value': port_match.group(2)})

    return access_lists, object_groups, objects

def expand_object_group(group_name, object_groups, objects):
    expanded = []
    if group_name not in object_groups:
        return expanded

    for line in object_groups[group_name]:
        if line.startswith('object '):
            obj_name = line.split()[1]
            if obj_name in objects:
                expanded.extend(objects[obj_name])
        elif line.startswith('host'):
            host_match = re.match(r'host\s+(\S+)', line)
            if host_match:
                expanded.append({'type': 'host', 'value': host_match.group(1)})
        elif re.match(r'\d{1,3}(?:\.\d{1,3}){3}\s+\d{1,3}(?:\.\d{1,3}){3}', line):
            subnet_match = re.match(r'(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})', line)
            expanded.append({'type': 'subnet', 'ip': subnet_match.group(1), 'mask': subnet_match.group(2)})
        elif line.startswith('group-object'):
            nested_group = line.split()[1]
            expanded.extend(expand_object_group(nested_group, object_groups, objects))
        elif line.startswith('port-object'):
            port_match = re.match(r'port-object\s+(eq|range)\s+(.+)', line)
            if port_match:
                expanded.append({'type': 'port', 'method': port_match.group(1), 'value': port_match.group(2)})

    return expanded

def print_expanded_acls(access_lists, object_groups, objects):
    for acl_name, entries in access_lists.items():
        print(f"\nAccess-list: {acl_name}")
        for entry in entries:
            print(f"  Entry: {entry}")
            referenced = [entry['src'], entry['src_detail'], entry['dst'], entry['dst_detail']]
            for ref in referenced:
                if ref.startswith('object-group'):
                    group_name = ref.split()[-1]
                    expanded = expand_object_group(group_name, object_groups, objects)
                    print(f"    Expanded object-group '{group_name}':")
                    for item in expanded:
                        print(f"      {item}")
                elif ref.startswith('object'):
                    obj_name = ref.split()[-1]
                    if obj_name in objects:
                        print(f"    Expanded object '{obj_name}':")
                        for item in objects[obj_name]:
                            print(f"      {item}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python asa_acl_object_analyzer.py <asa_config_file>")
        sys.exit(1)

    config_file_path = sys.argv[1]
    access_lists, object_groups, objects = parse_asa_config(config_file_path)
    print_expanded_acls(access_lists, object_groups, objects)

import re
import sys

def generate_no_route_map_commands(config_text):
    # Find all route-map blocks and extract (name, action)
    route_map_blocks = re.findall(r'(route-map\s+(\S+)\s+(permit|deny)[\s\S]*?)(?=\nroute-map|\Z)', config_text)
    route_map_instances = [(match[1], match[2]) for match in route_map_blocks]

    # Build a list of all lines that might reference route-maps
    lines = config_text.splitlines()
    referenced_names = set()

    for line in lines:
        for name, _ in route_map_instances:
            # Skip actual route-map definitions
            if line.strip().startswith(f'route-map {name}'):
                continue
            # Check for common reference patterns
            if re.search(rf'\broute-map\s+{re.escape(name)}\b', line):
                referenced_names.add(name)

    # Generate 'no route-map' commands for unreferenced route-map instances
    no_commands = []
    seen = set()
    for name, action in route_map_instances:
        key = (name, action)
        if name not in referenced_names and key not in seen:
            no_commands.append(f'no route-map {name} {action}')
            seen.add(key)

    return '\n'.join(no_commands)

if __name__ == "__main__":
    config_text = sys.stdin.read()
    print(generate_no_route_map_commands(config_text))

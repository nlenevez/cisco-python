import re
import sys

def generate_no_route_map_commands(config_text):
    # Find all route-map blocks and extract (name, action or sequence)
    route_map_blocks = re.findall(
        r'(route-map\s+(\S+)\s+(permit|deny|\d+)[\s\S]*?)(?=\nroute-map|\Z)', config_text
    )
    route_map_instances = [(match[1], match[2]) for match in route_map_blocks]

    # Normalize config lines for reference scanning
    lines = config_text.splitlines()
    referenced_names = set()

    for line in lines:
        line = line.strip()

        # Skip actual route-map definitions
        if re.match(r'^route-map\s+\S+\s+(permit|deny|\d+)', line):
            continue

        # Skip template peer-policy definitions
        if re.search(r'\btemplate\s+peer-policy\b', line):
            continue

        # Check for valid reference patterns
        for name, _ in route_map_instances:
            if re.search(rf'\b(match|set|ip policy|neighbor|redistribute|route-map)\s+{re.escape(name)}\b', line):
                referenced_names.add(name)

    # Generate 'no route-map' commands for unreferenced route-map instances
    no_commands = []
    seen = set()
    for name, action in route_map_instances:
        key = (name, action)
        if name not in referenced_names and key not in seen:
            no_commands.append(f'no route-map {name}')
            seen.add(key)

    return '\n'.join(no_commands)

if __name__ == "__main__":
    config_text = sys.stdin.read()
    print(generate_no_route_map_commands(config_text))

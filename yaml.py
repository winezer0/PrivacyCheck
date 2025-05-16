import re
from typing import Any, Dict, List, Union


def parse_yaml(yaml_str: str) -> List[Dict[str, Any]]:
    lines = yaml_str.strip().splitlines()
    root = []
    stack = [(root, -1)]  # (current_context, indent_level)

    for line in lines:
        stripped_line = line.lstrip(' ')
        if not stripped_line or stripped_line.startswith('#'):
            continue

        indent = (len(line) - len(stripped_line)) // 2  # 假设缩进为2个空格
        while stack and stack[-1][1] >= indent:
            stack.pop()

        current_context, _ = stack[-1]

        list_match = re.match(r'^-\s+(.+?):\s*(.*?)\s*$', stripped_line)
        key_value_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*?):\s*(.*?)\s*$', stripped_line)
        only_list_match = re.match(r'^-\s+(.*)$', stripped_line)

        if list_match:
            key, value = list_match.groups()
            value = parse_value(value)
            new_dict = {key: value}
            if isinstance(current_context, list):
                current_context.append(new_dict)
                stack.append((new_dict, indent))
            elif isinstance(current_context, dict):
                last_key = list(current_context.keys())[-1]
                if last_key not in current_context or not isinstance(current_context[last_key], list):
                    current_context[last_key] = []
                current_context[last_key].append(new_dict)
                stack.append((new_dict, indent))
        elif key_value_match:
            key, raw_value = key_value_match.groups()
            value = parse_value(raw_value)
            if isinstance(current_context, list):
                new_dict = {key: value}
                current_context.append(new_dict)
                stack.append((new_dict, indent))
            elif isinstance(current_context, dict):
                current_context[key] = value
        elif only_list_match:
            value = parse_value(only_list_match.group(1))
            if isinstance(current_context, dict):
                last_key = list(current_context.keys())[-1]
                if last_key not in current_context or not isinstance(current_context[last_key], list):
                    current_context[last_key] = []
                current_context[last_key].append(value)
            elif isinstance(current_context, list):
                current_context.append(value)
        else:
            raise ValueError(f"Unrecognized syntax: {line}")

    return root


def parse_value(val: str) -> Union[str, int, float, bool, None]:
    val = val.strip()
    if val.lower() == 'true':
        return True
    elif val.lower() == 'false':
        return False
    elif val.lower() in ('null', '~'):
        return None
    try:
        if '.' in val:
            return float(val)
        else:
            return int(val)
    except ValueError:
        return val

def safe_load(f):
    return parse_yaml(f.read().strip())

if __name__ == '__main__':
    sample_yaml = open('config.yaml').read()
    data = parse_yaml(sample_yaml.strip())
    print(data)
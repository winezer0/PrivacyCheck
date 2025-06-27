import csv
import os
import re
import time
from collections import defaultdict
from datetime import timedelta
from typing import Tuple, List, Dict, Any
import json

try:
    import yaml
except ImportError:
    print("[Warning] Missing dependency: PyYAML is not installed. Please: pip install pyyaml or use json config.")

# 　Cache FIlE Key
CACHE_RESULT = "result"
CACHE_UPDATE = "last_update"

def init_cacha_dict():
    return {CACHE_RESULT: {}, CACHE_UPDATE: None}


def load_rules_config(config_path: str) -> Dict:
    # 根据文件扩展名决定加载方式
    if config_path.lower().endswith('.json'):
        with open(config_path, 'r', encoding='utf-8') as f:
            config_info = json.load(f)
    else:
        # 默认使用 yaml 加载
        with open(config_path, 'r', encoding='utf-8') as f:
            config_info = yaml.safe_load(f)

    # 当前输入的是原始HAE规则,需要提取rules节点信息
    if isinstance(config_info, dict) and 'rules' in config_info.keys():
        return config_info.get('rules')
    return config_info


def save_cache_if_needed(cache_file, cache_data, cache_time, last_cache_time, save_interval, force_store) -> Tuple:
    """检查是否需要保存缓存"""
    total_seconds = (cache_time - last_cache_time).total_seconds()
    if force_store or (0 < save_interval <= total_seconds):
        try:
            # 根据数据类型分别处理
            if isinstance(cache_data, (dict, list)):
                # dump_status, dump_error = dump_json(cache_file, cache_data)
                # 尝试copy看有没有缓存报错 没有用
                # cache_copy = copy.deepcopy(cache_data)  # dictionary changed size during iteration
                # 转换为json再进行写入
                json_str, dump_error = dumps_json(cache_data)  # dictionary changed size during iteration
                if dump_error:
                    raise dump_error
                if json_str:
                    dump_status, dump_error = write_string(cache_file, json_str)
                    if dump_error:
                        raise dump_error
            elif isinstance(cache_data, str):
                dump_status, dump_error = write_string(cache_file, cache_data)
                if dump_error:
                    raise dump_error
            else:
                dump_error = TypeError(f"非预期的缓存格式类型:{type(cache_data)}")
                if dump_error:
                    raise dump_error
            return True, None
        except Exception as error:
            print(f"\n保存缓存失败: {error}")
            return False, error
    else:
        return False, None


def dumps_json(data, indent=0, ensure_ascii=False, sort_keys=False, allow_nan=False) -> Tuple:
    """
    - indent (int or str): 缩进级别 输出格式化的JSON字符串 会导致性能卡顿
    - ensure_ascii (bool): 如果为False，则允许输出非ASCII字符而不进行转义。
    - sort_keys (bool): 如果为True，则字典的键将按字母顺序排序。
    - allow_nan (bool): 如果为True，则允许 `NaN`, `Infinity`, `-Infinity` 等特殊浮点数值。
    """
    try:
        json_string = json.dumps(data, indent=indent, ensure_ascii=ensure_ascii, sort_keys=sort_keys,
                                 allow_nan=allow_nan)
        return json_string, None
    except Exception as e:
        print(f"dumps json error: {e}")
        return None, e


def write_string(file_path: str, content: str, mode: str = 'w+', encoding: str = 'utf-8') -> Tuple:
    try:
        if content:
            with open(file_path, mode, encoding=encoding) as file:
                file.write(content)
        return True, None
    except IOError as e:
        print(f"写入文件时发生错误: {e}")
        return False, e


def file_is_larger(file_path, limit=1):
    """判断指定路径的文件大小是否超过1MB。 """
    # 获取文件大小，单位为字节
    file_size = os.path.getsize(file_path)
    # 1 MB 的字节数
    one_mb_in_bytes = 1024 * 1024 * limit
    # 比较文件大小是否超过1MB
    return file_size > one_mb_in_bytes


def validate_rules(rules_info: Dict) -> bool:
    print("\n开始验证规则...")
    invalid_rules = []
    valid_rules_count = 0

    if not isinstance(rules_info, dict):
        print("Error: The rules info is not of dict type!!!")
        return False

    for group_name, rule_list in rules_info.items():
        if not isinstance(rule_list, list):
            print("Error: The rules content is not of list type!!!")
            continue

        for rule in rule_list:
            if not isinstance(rule, dict):
                print("Error: The rule is not of dict type!!!")
                continue

            # 检查loaded字段(默认为True)
            if not rule.get('loaded', True):
                continue

            valid_rules_count += 1
            # 检查必要字段
            required_fields = ['name', 'f_regex']
            missing_fields = [field for field in required_fields if field not in rule]
            if missing_fields:
                invalid_rules.append({
                    'group': group_name,
                    'name': rule.get('name', 'Unknown'),
                    'error': f'缺少必要字段: {", ".join(missing_fields)}'
                })
                continue

            # 验证正则表达式
            try:
                re.compile(rule['f_regex'])
            except re.error as e:
                invalid_rules.append({
                    'group': group_name,
                    'name': rule['name'],
                    'f_regex': rule['f_regex'],
                    'error': str(e)
                })

    if invalid_rules:
        print("\n发现无效的规则:")
        for rule in invalid_rules:
            print(f"\n规则组: {rule['group']}")
            print(f"规则名: {rule['name']}")
            if 'f_regex' in rule:
                print(f"正则表达式: {rule['f_regex']}")
            print(f"错误信息: {rule['error']}")
        print("\n请修复以上规则后再运行扫描。")
        return False
    else:
        print("规则验证通过！\n")
        return True


def file_ext_in_black(filename: str, exclude_ext: List) -> bool:
    return any(filename.endswith(ext) for ext in exclude_ext)


def get_files_with_filter(target_path, exclude_ext, limit_size):
    files_to_scan = []
    for root, _, files in os.walk(target_path):
        for file in files:
            path = os.path.join(root, file)
            if not file_ext_in_black(file, exclude_ext) and not file_is_larger(path, limit_size):
                files_to_scan.append(path)
    return files_to_scan


def string_encoding(data: bytes):
    # 简单的判断文件编码类型
    # 说明：UTF兼容ISO8859-1和ASCII，GB18030兼容GBK，GBK兼容GB2312，GB2312兼容ASCII
    CODES = ['UTF-8', 'GB18030', 'BIG5']
    # UTF-8 BOM前缀字节
    UTF_8_BOM = b'\xef\xbb\xbf'

    # 遍历编码类型
    for code in CODES:
        try:
            data.decode(encoding=code)
            if 'UTF-8' == code and data.startswith(UTF_8_BOM):
                return 'UTF-8-SIG'
            return code
        except UnicodeDecodeError:
            continue
    # 什么编码都没获取到 按UTF-8处理
    return 'UTF-8'


def file_encoding(file_path: str):
    # 获取文件编码类型
    if not os.path.exists(file_path):
        return "utf-8"
    with open(file_path, 'rb') as f:
        return string_encoding(f.read())


def print_progress(completed_task, total_task, start_time):
    elapsed = time.time() - start_time
    remaining = (elapsed / completed_task) * (total_task - completed_task) if completed_task > 0 else 0
    # 将秒数转换为可读的时间格式
    elapsed_delta = timedelta(seconds=int(elapsed))
    remaining_delta = timedelta(seconds=int(remaining))
    print(f"\r当前进度: {completed_task}/{total_task} ({(completed_task / total_task * 100):.2f}%) "
          f"已用时长: {str(elapsed_delta)} 预计剩余: {str(remaining_delta)}", end='')


def read_file_safe(filepath: str) -> Tuple[str, str]:
    """
    安全地读取文件内容并自动识别编码格式。

    :param filepath: 文件路径
    :return: (解码后的文本, 实际使用的编码)
    """
    encodings = [
        'utf-8-sig',  # UTF-8 with BOM
        'utf-8',
        'gbk',
        'gb2312',
        'gb18030',
        'big5',
        'latin1',
        'ascii',
        'iso-8859-1',
        'utf-16',
        'utf-32'
    ]

    try:
        with open(filepath, 'rb') as f:
            raw_data = f.read()

        # 尝试常用编码解码
        for encoding in encodings:
            try:
                content = raw_data.decode(encoding)
                return content, encoding
            except (UnicodeDecodeError, LookupError):
                continue

        # 如果所有编码都失败，强制使用 UTF-8 忽略错误
        content = raw_data.decode('utf-8', errors='replace')
        return content, 'utf-8-forced'

    except Exception as e:
        print(f"[!] 读取文件时发生错误: {e}")
        content = raw_data.decode('utf-8', errors='ignore')
        return content, 'utf-8-ignore-forced'


def load_json(json_path: str, encoding: str = 'utf-8') -> Any:
    """加载漏洞扫描结果"""
    try:
        with open(json_path, 'r', encoding=encoding) as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(f"加载 JSON 失败: {str(e)}")


def read_in_chunks(file_object, chunk_size=1024 * 1024):
    """生成器函数，用于分块读取文件"""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


def print_rules_info(rules_info: Dict):
    print("\n本次扫描使用的规则:")
    if not isinstance(rules_info, dict):
        print("Error: The rules info is not of dict type!!!")

    for group_name, rule_list in rules_info.items():
        for rule in rule_list:
            if not isinstance(rule, dict):
                print("Error: The rule is not of dict type!!!")
                continue
            if not rule.get('loaded', True):
                continue
            name = rule.get('name', 'Unknown')
            regex = rule.get('f_regex', '')
            if len(regex) > 50:
                regex = regex[:47] + '...'

            print(f"{group_name}: {name}: {regex}")
    print("\n" + "=" * 50)


def auto_make_dir(path, is_file=False):
    # 自动创建目录  如果输入的是文件路径,就创建上一级目录
    directory = os.path.dirname(os.path.abspath(path)) if is_file else path
    # print(f"auto_make_dir:{directory}")
    if not os.path.exists(directory):
        os.makedirs(directory)
        return True
    return False


def file_is_empty(file_path):
    # 判断一个文件是否为空
    return not path_is_exist(file_path) or not os.path.getsize(file_path)

def path_is_exist(file_path):
    # 判断文件是否存在
    return os.path.exists(file_path) if file_path else False


def write_dict_to_csv(csv_file, dicts, mode="a+", encoding="utf-8", title_keys=None):
    # 写入字典格式的数据到csv文件中
    # 判断数据是否存在
    if not dicts:
        return

    # 自动创建目录
    auto_make_dir(csv_file, is_file=True)
    # 判断输入的是字典列表,还是单个字典
    dicts = [dicts] if isinstance(dicts, dict) else dicts
    # 判断是否需要写入表头
    file_empty = file_is_empty(csv_file)
    # 获取表头格式  # BUG 自定义指定表头时可能出错
    title_keys = title_keys or dicts[0].keys()
    # 在使用csv.writer()写入CSV文件时，通常建议将newline参数设置为''，以便按照系统的默认行为进行换行符的处理。
    with open(csv_file, mode=mode, encoding=encoding, newline='') as file_open:
        # DictWriter 直接写入字典格式的数据
        # fieldnames=data[0].keys() 将字典的键作为表头
        # quoting=csv.QUOTE_ALL  将每个元素都用双引号包裹
        csv_writer = csv.DictWriter(file_open, fieldnames=title_keys, quoting=csv.QUOTE_ALL)
        if file_empty or "w" in mode:
            csv_writer.writeheader()
        csv_writer.writerows(dicts)
        file_open.close()


def write_dict_to_json(file_path, data, mode="w+", encoding="utf-8"):
    try:
        auto_make_dir(file_path, is_file=True)
        with open(file_path, mode, encoding=encoding) as json_file:
            formatted_json = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
            json_file.write(formatted_json)
    except Exception as e:
        print(f"写入 JSON 文件失败: {e}")


def strip_string(val):
    if isinstance(val, str):
        val = val.strip("'\"()[]{} \n\r\t")
        val = val.replace(r"\/", "/")
        return val
    return val


def new_dicts(dicts, need_keys):
    # 提取dicts中的指定键的值
    dicts = [{k: item.get(k) for k in need_keys if k in item} for item in dicts]
    return dicts


def group_dicts_by_key(dicts, key):
    if not key:
        # 没有指定键时 将dicts放在空键中
        return {key: dicts}

    group_dict = defaultdict(list)
    for item in dicts:
        group_name = item.get(key)
        group_dict[group_name].append(item)
    return dict(group_dict)


def filter_rules(group_infos, filter_groups: List[str], filter_names: List[str], sensitive_only=False) -> Dict[str, List[Dict]]:
    """整理出要利用的规则列表，返回dict，{group: [{rule1},{rule2}...]}"""
    if filter_groups:
        filter_groups = filter_groups if isinstance(filter_groups, list) else [filter_groups]
        filter_groups = [x.strip().lower() for x in filter_groups if x.strip()]

    if filter_names:
        filter_names = filter_names if isinstance(filter_names, list) else [filter_names]
        filter_names = [x.strip().lower() for x in filter_names if x.strip()]

    loaded_rules = {}
    if not isinstance(group_infos, list):
        print("rules info is not list, incorrect rules format!!!")
        return {}

    for group_info in group_infos:
        if not isinstance(group_info, dict):
            print("rules group is not dict, incorrect rules format!!!")
            continue

        group_name = group_info.get('group', None)
        group_rules = group_info.get('rule', [])

        if not isinstance(group_rules, list):
            print("rules content is not list, incorrect rules format!!!")
            continue

        # 按照group_name进行过滤
        if filter_groups and not any(x in str(group_name).lower() for x in filter_groups):
            continue

        filtered_rules = []
        for rule in group_rules:
            # 排除空规则
            if not rule or not isinstance(rule, dict):
                continue
            # 仅敏感模式下排除非敏感信息的规则
            if sensitive_only and rule.get('sensitive', False) is False:
                continue
            # 排除没有加载的规则
            if not rule.get('loaded', True) or 'f_regex' not in rule.keys():
                continue
            # 按名称关键字过滤
            if filter_names and not any(x in str(rule.get('name')).lower() for x in filter_names):
                continue
            filtered_rules.append(rule)

        if filtered_rules:
            loaded_rules[group_name] = filtered_rules

    return loaded_rules


def rules_size(rules_info):
    """计算实际规则数量"""
    size = 0
    if isinstance(rules_info, dict):
        size += sum([len(x) for x in rules_info.values()])
    if isinstance(rules_info, list):
        size += sum([len(x.get('rule')) for x in rules_info])
    return size


def convert_yaml_to_json(input_yaml, output_json):
    """将指定的 YAML 文件转换为 JSON 格式"""
    status = True
    error = None
    try:
        # 加载 YAML 文件
        with open(input_yaml, 'r', encoding='utf-8') as f:
            yaml_data = yaml.safe_load(f)
        # 保存为 JSON 文件
        with open(output_json, 'w+', encoding='utf-8') as f:
            json.dump(yaml_data, f, ensure_ascii=False, indent=2)
        print(f"Yaml To Json convert success: {input_yaml} -> {output_json}")
    except Exception as e:
        print(f"Yaml To Json convert failed: {input_yaml} -> {e}")
        status = False
        error = str(e)
    return status, error


def check_keys_is_valid(allowed_keys, output_keys):
    """检查输出字段是否都在允许的字段范围内"""
    invalid_keys = [k for k in output_keys if k not in allowed_keys]
    if invalid_keys:
        print(f"[错误] --output-keys 存在非法字段: {invalid_keys} 仅允许以下字段: {sorted(allowed_keys)}")
        return False
    return True

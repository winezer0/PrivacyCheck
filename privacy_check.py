import argparse
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, datetime
from typing import List, Dict, Tuple, Any
import yaml

# 　Cache FIlE Key
CACHE_RESULT = "result"
CACHE_UPDATE = "last_update"


def dumps_json(data, indent=0, ensure_ascii=False, sort_keys=False, allow_nan=False) -> tuple:
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


def write_string(file_path: str, content: str, mode: str = 'w+', encoding: str = 'utf-8') -> tuple:
    try:
        if content:
            with open(file_path, mode, encoding=encoding) as file:
                file.write(content)
        return True, None
    except IOError as e:
        print(f"写入文件时发生错误: {e}")
        return False, e


def save_cache_if_needed(cache_file, cache_data, cache_time, last_cache_time, save_interval, force_store) -> tuple:
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


def file_is_larger(file_path, limit=1):
    """判断指定路径的文件大小是否超过1MB。 """
    # 获取文件大小，单位为字节
    file_size = os.path.getsize(file_path)
    # 1 MB 的字节数
    one_mb_in_bytes = 1024 * 1024 * limit
    # 比较文件大小是否超过1MB
    return file_size > one_mb_in_bytes


def validate_rules(rules, sensitive_only) -> None:
    print("\n开始验证规则...")
    invalid_rules = []
    valid_rules_count = 0

    if not isinstance(rules, list):
        print("错误: 配置文件不是列表类型")
        return

    for group in rules:
        if not isinstance(group, dict):
            continue

        group_name = group.get('group', '')
        rule_list = group.get('rule', [])

        if not isinstance(rule_list, list):
            continue

        for rule in rule_list:
            if not isinstance(rule, dict):
                continue

            # 如果启用了仅敏感规则模式，跳过非敏感规则
            if sensitive_only and not rule.get('sensitive', False):
                continue

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

            # 检查loaded字段（默认为True）
            if not rule.get('loaded', True):
                continue

            # 验证正则表达式
            try:
                re.compile(rule['f_regex'])
            except re.error as e:
                invalid_rules.append({
                    'group': group_name,
                    'name': rule['name'],
                    'regex': rule['f_regex'],
                    'error': str(e)
                })

    if invalid_rules:
        print("\n发现无效的规则:")
        for rule in invalid_rules:
            print(f"\n规则组: {rule['group']}")
            print(f"规则名: {rule['name']}")
            if 'regex' in rule:
                print(f"正则表达式: {rule['regex']}")
            print(f"错误信息: {rule['error']}")
        print("\n请修复以上规则后再运行扫描。")
        exit(1)
    else:
        print("规则验证通过！\n")


def file_ext_in_black(filename: str, exclude_ext: list) -> bool:
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
    return 'unknown'


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


def _load_config(config_path: str) -> Dict:
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def _read_whole_file(filepath: str) -> Tuple[str, str]:
    # 原有的文件读取逻辑保持不变
    try:
        with open(filepath, 'rb') as f:
            raw_data = f.read()
            detected_encoding = file_encoding(filepath)
    except Exception:
        detected_encoding = 'utf-8'

    encodings = [
        detected_encoding,
        'utf-8',
        'gbk',
        'gb2312',
        'gb18030',
        'big5',
        'iso-8859-1',
        'ascii',
        'latin1',
        'utf-16',
        'utf-32'
    ]

    for encoding in encodings:
        try:
            return raw_data.decode(encoding), encoding
        except (UnicodeDecodeError, LookupError):
            continue

    return raw_data.decode('utf-8', errors='ignore'), 'utf-8-forced'


def _read_file_safe(filepath: str, chunk_size: int = 1024 * 1024, ) -> Tuple[str, str]:
    # 获取文件大小
    file_size = os.path.getsize(filepath)

    # 如果文件小于chunk_size，直接读取
    if file_size <= chunk_size:
        return _read_whole_file(filepath)

    # 对大文件进行分块处理
    try:
        with open(filepath, 'rb') as f:
            # 先读取一小块来检测编码
            sample = f.read(4096)
            encoding = string_encoding(sample)

            # 重置文件指针
            f.seek(0)
            content = ''
            chunk = True  # 初始化chunk变量，确保进入循环
            while chunk:
                chunk = f.read(chunk_size)  # 读取文件块
                if not chunk:  # 如果没有读取到数据，则退出循环
                    break
                try:
                    content += chunk.decode(encoding, errors='ignore')  # 尝试按指定编码解码
                except UnicodeDecodeError:
                    content += chunk.decode('utf-8', errors='ignore')  # 解码失败则尝试使用'utf-8'编码
            return content, encoding
    except Exception:
        return _read_whole_file(filepath)


def init_cacha_dict():
    return {CACHE_RESULT: {}, CACHE_UPDATE: None}


def load_json(json_path: str, encoding: str = 'utf-8') -> Any:
    """加载漏洞扫描结果"""
    try:
        with open(json_path, 'r', encoding=encoding) as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(f"加载 JSON 失败: {str(e)}")


class PrivacyChecker:
    def __init__(self, project_name: str, rule_file: str, exclude_ext: List[str], sensitive_only: bool = False,
                 limit_size: int = 1):

        self.rule_file = _load_config(rule_file)
        self.exclude_ext = exclude_ext
        self.limit_size = limit_size
        self.sensitive_only = sensitive_only  # 新增属性
        validate_rules(self.rule_file, self.sensitive_only)
        self.scan_results = []

        # 缓存信息
        self.cache_file = f"{project_name}.cache"
        self.new_cache_data = init_cacha_dict()
        self.old_cache_data = self._load_scan_cache()
        self.cache_interval = 10
        self.cache_lock = threading.Lock()  # 添加线程锁
        self.last_cache_time = datetime.now()

    def _load_scan_cache(self) -> Dict:
        """加载验证缓存"""
        cache = init_cacha_dict()
        try:
            if os.path.exists(self.cache_file):
                cache = load_json(self.cache_file)
                print("加载缓存完成:"
                      f"\n已缓存结果数: {len(cache.get(CACHE_RESULT, {}).keys())}"
                      f"\n缓存更新时间: {cache.get(CACHE_UPDATE, '未知')}")
        except Exception as e:
            print(f"加载缓存失败: {e}")
        return cache

    def print_used_rules(self):
        print("\n本次扫描使用的规则:")
        config = self.rule_file
        sensitive_only = self.sensitive_only
        for group in config:
            group_name = group.get('group', '')
            rule_list = group.get('rule', [])
            for rule in rule_list:
                if not isinstance(rule, dict):
                    continue
                if sensitive_only and not rule.get('sensitive', False):
                    continue
                if not rule.get('loaded', True):
                    continue
                name = rule.get('name', 'Unknown')
                regex = rule.get('f_regex', '')
                if len(regex) > 50:
                    regex = regex[:47] + '...'

                print(f"[{group_name}] {name}: {regex}")
        print("\n" + "=" * 50)

    @classmethod
    def _prepare_rules(cls, rules, sensitive_only) -> Dict[str, List[Dict]]:
        """
        整理出要利用的规则列表，返回dict，键为组名，值为规则列表。
        """
        rules_to_apply = {}

        if not isinstance(rules, list):
            return rules_to_apply

        for group in rules:
            if not isinstance(group, dict):
                continue

            group_name = group.get('group', '')
            rule_list = group.get('rule', [])

            if not isinstance(rule_list, list):
                continue

            filtered_rules = []
            for rule in rule_list:
                # 排除空规则
                if not rule or not isinstance(rule, dict):
                    continue
                # 仅敏感模式下排除非敏感信息的规则
                if sensitive_only and rule.get('sensitive', False) is False:
                    continue
                # 排除没有加载的规则
                if rule.get('loaded', True) is False or 'f_regex' not in rule:
                    continue
                filtered_rules.append(rule)

            if filtered_rules:
                rules_to_apply[group_name] = filtered_rules

        return rules_to_apply

    @classmethod
    def _apply_rule(cls, rule: Dict, content: str, group_name: str, filepath: str) -> list[dict]:
        flags = re.MULTILINE | (re.IGNORECASE if rule.get('ignore_case', True) else 0)
        pattern = re.compile(rule['f_regex'], flags)
        matches = pattern.finditer(content)

        rule_results = []
        for match in matches:
            matched_text = match.group()
            if len(matched_text.strip()) <= 5:
                continue

            start_pos = max(0, match.start() - 50)
            end_pos = min(len(content), match.end() + 50)
            context = content[start_pos:end_pos]

            result = {
                'file': filepath,  # 应在调用时赋值
                'group': group_name,
                'rule_name': rule['name'],
                'match': matched_text,
                'context': context,
                'position': match.start(),
                'line_number': content.count('\n', 0, match.start()) + 1,
                'sensitive': rule.get('sensitive', False)
            }
            rule_results.append(result)
        return rule_results

    def scan(self, target_path: str, max_workers: int = None, save_cache=True):
        # 显示本次扫描使用的规则
        self.print_used_rules()
        # 获取需要扫描的文件
        if os.path.isfile(target_path):
            files_to_scan = [target_path]
        else:
            files_to_scan = get_files_with_filter(target_path, self.exclude_ext, self.limit_size)

        total_files = len(files_to_scan)
        print(f"开始扫描，共发现 {total_files} 个有效文件")
        print(f"使用线程数: {max_workers if max_workers else '系统CPU核心数'}")

        # 进行实际使用的规则提取
        rules_to_apply = self._prepare_rules(self.rule_file, self.sensitive_only)
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 开始提交任务
            futures = [executor.submit(self._apply_rules, file, rules_to_apply) for file in files_to_scan]
            # 进行结果接受
            for completed, future in enumerate(futures):
                filepath, check_results = future.result()
                # 保存扫描结果、提取所有 findings 内容到一个列表
                self.scan_results.extend(check_results)
                # 输出当前进度
                print_progress(completed, total_files, start_time)
                # 保存缓存数据
                if save_cache:
                    try:
                        self.new_cache_data[CACHE_RESULT][filepath] = check_results
                        # 记录缓存
                        with self.cache_lock:
                            now_cache_time = datetime.now()
                            self.new_cache_data[CACHE_UPDATE] = now_cache_time.isoformat()
                            is_completed = len(futures) == completed + 1
                            cache_status, cache_error = save_cache_if_needed(
                                cache_file=self.cache_file,
                                cache_data=self.new_cache_data,
                                cache_time=now_cache_time,
                                last_cache_time=self.last_cache_time,
                                save_interval=self.cache_interval,
                                force_store=is_completed
                            )
                            if cache_status:
                                self.last_cache_time = now_cache_time
                    except Exception as e:
                        print(f"\nFailure save scan cache by cache_save_interval:{e}")

            total_time = time.time() - start_time
            print(f"\n扫描完成！总用时: {str(timedelta(seconds=int(total_time)))} 发现漏洞: {len(self.scan_results)} 个")
            return self.scan_results

    def _apply_rules(self, filepath: str, apply_rules: dict) -> tuple[str, Any]:
        file_results = []

        # 检查缓存
        old_cache_result = self.old_cache_data[CACHE_RESULT]
        if filepath in old_cache_result:
            return filepath, old_cache_result.get(filepath)

        try:
            # 整理出要利用的规则列表
            content, _ = _read_file_safe(filepath)
            for group_name, rule_list in apply_rules.items():
                for rule in rule_list:
                    rules_result = self._apply_rule(rule, content, group_name, filepath)
                    file_results.extend(rules_result)
        except Exception as e:
            print(f"Error processing file {filepath}: {str(e)}")
        return filepath, file_results


def main():
    excludes_ext = {
        '.tmp', '.exe', '.bin', '.dll', '.elf',
        '.zip', '.rar', '.7z', '.gz', '.bz2', '.tar',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.woff', '.woff2'
    }

    parser = argparse.ArgumentParser(description='Privacy information detection tool')
    parser.add_argument('-r', '--rule-file', default='config.yaml',
                        help='Path to configuration file (default: config.yaml)')
    parser.add_argument('-t', '--target', required=True, help='Target file or directory to scan')
    parser.add_argument('-e', '--exclude-ext', nargs='+', default=[],
                        help=f'exclude file extensions (always add inner {excludes_ext})')
    parser.add_argument('-o', '--output', default=None, help='Output file path (default: output.json)')
    parser.add_argument('-w', '--workers', type=int, default=os.cpu_count(),
                        help='Number of worker threads (default: CPU count)')
    parser.add_argument('-s', '--sensitive-only', action='store_true', help='只扫描敏感文件规则')
    parser.add_argument('-l', '--limit-size', type=int, default=1, help='check file size limit x MB')
    parser.add_argument('-S', '--save-cache', action='store_true', default=False,
                        help='实时记录缓存文件, 建议大项目使用 (默认: False) 注意:会生成缓存文件!!!')
    parser.add_argument('-p', '--project', default='default_project', help='Project name for cache identification')

    args = parser.parse_args()
    # 更新用户指定的后缀类型
    excludes_ext.update(args.exclude_ext)

    checker = PrivacyChecker(
        project_name=args.project,
        rule_file=args.rule_file,
        exclude_ext=excludes_ext,
        sensitive_only=args.sensitive_only,
        limit_size=args.limit_size
    )

    check_results = checker.scan(args.target, max_workers=args.workers, save_cache=args.save_cache)

    # 保存分析结果
    if check_results:
        output_file = args.output or f"{args.project}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(check_results, f, ensure_ascii=False, indent=2)
            print(f"分析结果已保存至: {output_file}")


if __name__ == '__main__':
    main()

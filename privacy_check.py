import argparse
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, datetime
from typing import List, Dict, Tuple, Any

from utils import validate_rules, get_files_with_filter, file_encoding, print_progress, \
    load_rules_config, read_file_safe, load_json, read_in_chunks, print_rules_info, init_cacha_dict, CACHE_RESULT, \
    CACHE_UPDATE, save_cache_if_needed, write_dict_to_csv, write_dict_to_json, strip_string, new_dicts, \
    group_dicts_by_key, filter_rules, rules_size


class PrivacyChecker:
    def __init__(self, project_name: str, rules_info: Dict, exclude_ext: List[str], sensitive_only: bool = False,
                 limit_size: int = 1):
        self.exclude_ext = exclude_ext
        self.limit_size = limit_size
        self.scan_results = []
        self.rules_info = rules_info

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

    @classmethod
    def _apply_rule(cls, rule: Dict, content: str, group_name: str, filepath: str) -> List[Dict]:
        rule_results = []

        rule_name = rule.get('name', None)
        rule_regex = rule.get('f_regex', None)
        rule_ignore_case = rule.get('ignore_case', True)
        if not rule_regex:
            print(f"Error rule. The key [f_regex] content is empty... -> {rule}")
            return rule_results

        # 根据是否为敏感信息设置默认上下文长度 非敏感信息获取的情况下不需要扩充上下文 敏感信息的情况下扩充上下文长度
        rule_is_sensitive = rule.get('sensitive', False)
        context_default = 50 if rule_is_sensitive else 0
        rule_context_left = rule.get('context_left', context_default)
        rule_context_right = rule.get('context_right', context_default)

        flags = re.MULTILINE | (re.IGNORECASE if rule_ignore_case else 0)
        pattern = re.compile(rule_regex, flags)
        matches = pattern.finditer(content)

        for match in matches:
            matched_text = match.group()
            if len(matched_text.strip()) <= 5:
                continue
            start_pos = max(0, match.start() - rule_context_left)
            end_pos = min(len(content), match.end() + rule_context_right)
            context = content[start_pos:end_pos]

            result = {
                'file': filepath,  # 应在调用时赋值
                'group': group_name,
                'rule_name': rule_name,
                'match': matched_text,
                'context': context,
                'position': match.start(),
                'line_number': content.count('\n', 0, match.start()) + 1,
                'sensitive': rule_is_sensitive
            }
            rule_results.append(result)
        return rule_results

    def scan(self, target_path: str, max_workers: int = None, save_cache=True, chunk_mode=False):

        # 获取需要扫描的文件
        if os.path.isfile(target_path):
            files_to_scan = [target_path]
        else:
            files_to_scan = get_files_with_filter(target_path, self.exclude_ext, self.limit_size)

        total_files = len(files_to_scan)
        print(f"开始扫描，共发现 {total_files} 个有效文件")
        print(f"使用线程数: {max_workers if max_workers else '系统CPU核心数'}")

        start_time = time.time()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 开始提交任务
            futures = [executor.submit(self._apply_rules, file, self.rules_info, chunk_mode) for file in files_to_scan]
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

    def _apply_rules(self, filepath: str, apply_rules: Dict, chunk_mode: bool) -> Tuple[str, Any]:
        file_results = []

        # 检查缓存
        old_cache_result = self.old_cache_data[CACHE_RESULT]
        if filepath in old_cache_result:
            return filepath, old_cache_result.get(filepath)
        try:
            if chunk_mode:
                chunk_size = 1024 * 1024  # 每次读取1MB的数据
                with open(filepath, 'r', encoding=file_encoding(filepath), errors="ignore") as file:
                    for chunk in read_in_chunks(file, chunk_size):
                        # 应用所有规则到当前数据块
                        for group_name, rule_list in apply_rules.items():
                            for rule in rule_list:
                                rules_result = self._apply_rule(rule, chunk, group_name, filepath)
                                file_results.extend(rules_result)
            else:
                content, _ = read_file_safe(filepath)
                # 应用规则到文件内容
                for group_name, rule_list in apply_rules.items():
                    for rule in rule_list:
                        rules_result = self._apply_rule(rule, content, group_name, filepath)
                        file_results.extend(rules_result)
        except Exception as e:
            print(f"Error processing file {filepath}: {str(e)}")
        return filepath, file_results


def args_parser(excludes_ext, allowed_keys):
    parser = argparse.ArgumentParser(description='Privacy information detection tool')
    parser.add_argument('-r', '--rules', dest='rules_file', default='privacy_check.yaml',
                        help='规则文件的路径(默认值：privacy_check.yaml)')
    parser.add_argument('-t', '--target', dest='target', required=True,
                        help='待扫描的项目目标文件或目录')
    parser.add_argument('-p', '--project-name', dest='project_name', default='default_project',
                        help='项目名称, 影响默认输出文件名和缓存文件名')
    # 性能配置
    parser.add_argument('-w', '--workers', dest='workers', type=int, default=os.cpu_count(),
                        help='工作线程数量(默认值：CPU 核心数)')
    parser.add_argument('-l', '--limit-size', dest='limit_size', type=int, default=5,
                        help='检查文件大小限制 不超过 limit_size M')
    parser.add_argument('-s', '--save-cache', dest='save_cache', action='store_true', default=False,
                        help='定时缓存扫描结果, 建议大项目使用 (默认: False) 注意:会生成缓存文件!!!')
    parser.add_argument('-k', '--chunk-mode', dest='chunk_mode', action='store_true', default=False,
                        help='使用chunk模式读取文件,运行时间延长,内存占用减小 (默认: False) ')
    # 过滤配置
    parser.add_argument('-e', '--exclude-ext', dest='exclude_ext', nargs='+', default=[],
                        help=f'排除文件扩展名(始终添加内置扩展名: {excludes_ext})')
    # 筛选规则
    parser.add_argument('-S', '--sensitive-only', dest='sensitive_only', action='store_true',
                        help='只启用敏感信息规则 (sensitive: true) 默认False')
    parser.add_argument('-N', '--filter-names', dest='filter_names', nargs='+', type=str, default=[],
                        help='仅启用name中包含指定关键字的规则, 多个关键字用空格分隔')
    parser.add_argument('-G', '--filter-groups', dest='filter_groups', nargs='+', type=str, default=[],
                        help='仅启用group中包含指定关键字的规则, 多个关键字用空格分隔')
    # 输出配置
    parser.add_argument('-o', '--output-file', dest='output_file', default=None,
                        help='指定输出文件路径 (默认：{project_name}.json)')

    parser.add_argument('-g', '--output-group', dest='output_group', action='store_true', default=False,
                        help='为规则组单独输出结果 (默认：False')

    parser.add_argument('-O', '--output-keys', dest='output_keys', nargs='+', default=[],
                        help=f'仅输出结果中指定键的值，多个键使用空格分隔, 允许的键: {allowed_keys}')

    parser.add_argument('-f','--output-format', dest='output_format', type=str, default='json', choices=['json', 'csv'],
                        help='指定输出文件格式: json 或 csv, 默认: json')

    parser.add_argument('-F', '--format-results', dest='format_results', action='store_false', default=True,
                        help='对输出结果的每个值进行格式化，去除引号、空格等符号, 默认: True')

    parser.add_argument('-b','--block-matches', dest='block_matches', type=str, default=None, nargs='+',
                        help='对匹配结果中的match键值进行黑名单关键字列表匹配剔除, 建议在匹配较大项目时搭配缓存功能使用.')

    args = parser.parse_args()
    return args

def main():
    excludes_ext = {
        '.tmp', '.exe', '.bin', '.dll', '.elf',
        '.zip', '.rar', '.7z', '.gz', '.bz2', '.tar',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.woff', '.woff2'
    }

    allowed_keys = {"file", "group", "rule_name", "match", "context", "position", "line_number", "sensitive"}

    args = args_parser(excludes_ext, allowed_keys)
    output_format = args.output_format
    output_file = args.output_file
    project_name = args.project_name
    # 更新用户指定的后缀类型
    excludes_ext.update(args.exclude_ext)

    # 校验 output_keys 合法性
    output_keys = args.output_keys or []
    if output_keys:
        invalid_keys = [k for k in output_keys if k not in allowed_keys]
        if invalid_keys:
            print(f"[错误] --output-keys 存在非法字段: {invalid_keys} 仅允许以下字段: {sorted(allowed_keys)}")
            sys.exit(1)

    # 进行实际使用的规则提取
    load_rules = load_rules_config(args.rules_file)
    print(f"loaded rules group:{len(load_rules)} -> Rule Size:{rules_size(load_rules)} -> Type:{type(load_rules)}")
    rules_info = filter_rules(load_rules, args.filter_groups, args.filter_names, args.sensitive_only)
    print(f"filter rules group:{len(rules_info)} -> Rule Size:{rules_size(rules_info)} -> Type:{type(rules_info)}")
    if not validate_rules(rules_info):
        sys.exit(1)
    print_rules_info(rules_info)

    checker = PrivacyChecker(project_name=project_name,
                             rules_info=rules_info,
                             exclude_ext=excludes_ext,
                             limit_size=args.limit_size)

    check_results = checker.scan(args.target,
                                 max_workers=args.workers,
                                 save_cache=args.save_cache,
                                 chunk_mode=args.chunk_mode)

    # 保存分析结果
    if check_results:
        # 格式化结果值
        if args.format_results:
            check_results = [{k: strip_string(v) for k, v in row.items()} for row in check_results]

        # 排除带有黑名单关键字的结果
        if args.block_matches:
            check_results = [dic for dic in check_results if not any(b in dic.get('match') for b in args.block_matches) ]

        # 按照group分别输出结果类型
        if args.output_group:
            group_results = group_dicts_by_key(check_results, key='group')
        else:
            group_results = group_dicts_by_key(check_results, key='')

        # 仅输出结果中的指定键
        if output_keys:
            group_results = {group_name: new_dicts(group, output_keys) for group_name, group in group_results.items()}

        # 输出csv或者json格式
        for group_name, group_results in group_results.items():
            base_output = output_file or project_name
            output_name = f"{base_output}.{group_name}" if group_name else base_output
            output_file = f"{output_name}.{output_format}"
            if 'csv' in output_format:
                write_dict_to_csv(output_file, group_results, mode="a+", encoding="utf-8")
            else:
                write_dict_to_json(output_file, group_results, mode="a+", encoding="utf-8")
            print(f"分析结果 [group:{group_name}|format:{output_format})] 已保存至: {output_file}")


if __name__ == '__main__':
    main()


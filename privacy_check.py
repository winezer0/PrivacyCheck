import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, datetime
from typing import List, Dict, Tuple, Any

from utils import validate_rules, get_files_with_filter, file_encoding, print_progress, \
    _load_rules_config, read_file_safe, load_json, read_in_chunks, print_rules_info, init_cacha_dict, CACHE_RESULT, \
    CACHE_UPDATE, save_cache_if_needed


class PrivacyChecker:
    def __init__(self, project_name: str, rule_file: str, exclude_ext: List[str], allow_names: List[str] = None,
                 sensitive_only: bool = False, limit_size: int = 1):
        self.exclude_ext = exclude_ext
        self.limit_size = limit_size
        self.sensitive_only = sensitive_only  # 新增属性
        self.scan_results = []
        self.allow_names = allow_names

        # 进行实际使用的规则提取
        load_rules = _load_rules_config(rule_file)
        self.rules_info = self._filter_rules(load_rules, self.allow_names, self.sensitive_only)
        if not validate_rules(self.rules_info):
            sys.exit(1)
        print_rules_info(self.rules_info)

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
    def _filter_rules(cls, rules_info, allow_names: List[str], sensitive_only=False) -> Dict[str, List[Dict]]:
        """整理出要利用的规则列表，返回dict，{group: [{rule1},{rule2}...]}"""
        allow_names = [x.strip() for x in allow_names if x.strip()] if allow_names else []

        loaded_rules = {}
        if not isinstance(rules_info, list):
            print("rules info is not list, incorrect rules format!!!")
            return {}

        for group in rules_info:
            if not isinstance(group, dict):
                print("rules group is not dict, incorrect rules format!!!")
                continue

            group_name = group.get('group', None)
            rule_list = group.get('rule', [])

            if not isinstance(rule_list, list):
                print("rules content is not list, incorrect rules format!!!")
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
                if not rule.get('loaded', True) or 'f_regex' not in rule.keys():
                    continue
                # 按名称关键字过滤
                if allow_names and not any(x in str(rule.get('name')).lower() for x in allow_names):
                    continue
                filtered_rules.append(rule)

            if filtered_rules:
                loaded_rules[group_name] = filtered_rules

        return loaded_rules

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


def main():
    excludes_ext = {
        '.tmp', '.exe', '.bin', '.dll', '.elf',
        '.zip', '.rar', '.7z', '.gz', '.bz2', '.tar',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.woff', '.woff2'
    }

    allowed_keys = {"file", "group", "rule_name", "match", "context", "position", "line_number", "sensitive"}


    parser = argparse.ArgumentParser(description='Privacy information detection tool')
    parser.add_argument('-r', '--rules', dest='rule_file', default='privacy_check.yaml',
                        help='规则文件的路径(默认值：privacy_check.yaml)')
    parser.add_argument('-t', '--target', dest='target', required=True,
                        help='待扫描的项目目标文件或目录')
    parser.add_argument('-p', '--project', dest='project', default='default_project',
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
    # 筛选配置
    parser.add_argument('-S', '--sensitive', dest='sensitive_only', action='store_true',
                        help='只启用敏感信息规则 (sensitive: true) 默认False')
    # 新增规则名称过滤参数
    parser.add_argument('-a','--allow-names', dest='allow_names', type=str, default=[],
                        help='仅启用指定名称关键字的规则, 多个规则名用空格分隔')
    # 新增输出键参数
    parser.add_argument('-o', '--output', dest='output', default=None,
                        help='输出文件路径(默认：{project_name}.json)')
    parser.add_argument('-O','--output-keys', dest='output_keys', nargs='+', default=[],
                        help=f'指定输出结果的键，直接以空格分隔多个键，如 -O file match, 允许的键:{allowed_keys}')

    args = parser.parse_args()
    # 更新用户指定的后缀类型
    excludes_ext.update(args.exclude_ext)

    # 校验 output_keys 合法性
    output_keys = args.output_keys or []
    if output_keys:
        invalid_keys = [k for k in output_keys if k not in allowed_keys]
        if invalid_keys:
            print(f"[错误] --output-keys 存在非法字段: {invalid_keys} 仅允许以下字段: {sorted(allowed_keys)}")
            sys.exit(1)

    checker = PrivacyChecker(project_name=args.project,
                             rule_file=args.rule_file,
                             exclude_ext=excludes_ext,
                             allow_names=args.allow_names,
                             sensitive_only=args.sensitive_only,
                             limit_size=args.limit_size)

    check_results = checker.scan(args.target,
                                 max_workers=args.workers,
                                 save_cache=args.save_cache,
                                 chunk_mode=args.chunk_mode)

    # 保存分析结果
    if check_results:
        output_file = args.output or f"{args.project}.json"
        if output_keys:
            check_results = [{k: item.get(k) for k in output_keys if k in item} for item in check_results]

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(check_results, f, ensure_ascii=False, indent=2)
            print(f"分析结果已保存至: {output_file}")


if __name__ == '__main__':
    main()


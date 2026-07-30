# -*- coding: utf-8 -*-
"""
    pom_parser
    ~~~~~~~~~~
    解析 pom.xml 提取 Maven 依赖信息 + 语义化版本比较
"""
import os
import re
import xml.etree.ElementTree as ET
from utils.log import logger


def _get_parent_version(root, prefix):
    """从 parent 标签中获取版本号"""
    parent = root.find(f'{prefix}parent')
    if parent is None:
        parent = root.find('{http://maven.apache.org/POM/4.0.0}parent')
    if parent is not None:
        for pfx in ['{http://maven.apache.org/POM/4.0.0}', '']:
            ver = parent.findtext(f'{pfx}version', '')
            if ver:
                return ver
    return None


def parse_pom_dependencies(pom_path):
    """
    解析 pom.xml 提取所有依赖
    返回 [{"group_id": "...", "artifact_id": "...", "version": "..."}, ...]
    """
    deps = []
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
        
        # Maven POM namespace
        ns = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
        
        # 尝试带 namespace 和不带 namespace 两种方式
        for prefix in ['{http://maven.apache.org/POM/4.0.0}', '']:
            dependencies = root.findall(f'.//{prefix}dependency')
            if dependencies:
                parent_version = _get_parent_version(root, prefix)
                for dep in dependencies:
                    gid = dep.findtext(f'{prefix}groupId', '')
                    aid = dep.findtext(f'{prefix}artifactId', '')
                    ver = dep.findtext(f'{prefix}version', '')
                    if gid and aid:
                        # 处理 ${property} 引用
                        ver = _resolve_version(ver, root, prefix)
                        # 如果版本为空，不使用 parent 版本替代——
                        # parent 版本是项目自身的版本，不是依赖的版本。
                        # 依赖版本通常在父 POM 的 dependencyManagement 中定义，
                        # 这里无法解析到那个值，所以保持 "unknown"。
                        # version_in_range 会对 unknown 返回 False，避免 FP。
                        deps.append({
                            "group_id": gid,
                            "artifact_id": aid,
                            "version": ver or "unknown"
                        })
                break
    except Exception as e:
        logger.debug(f'[POM] parse error: {e}')
    
    return deps


def _resolve_version(version_str, root, prefix):
    """解析 ${property} 引用，如 ${shiro.version}"""
    if not version_str:
        return version_str
    
    m = re.match(r'\$\{(.+?)\}', version_str)
    if m:
        prop_name = m.group(1)
        # 在 properties 中查找
        for pfx in ['{http://maven.apache.org/POM/4.0.0}', '']:
            props = root.find(f'.//{pfx}properties')
            if props is not None:
                val = props.findtext(f'{pfx}{prop_name}')
                if val:
                    return val
    return version_str


def find_pom_files(target_directory):
    """递归查找所有 pom.xml 文件，同时向上搜索父目录（最多3层）"""
    pom_files = set()
    
    # 1. 递归搜索目标目录及其子目录
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in ('.git', 'target', 'node_modules', 'vendor')]
        for f in files:
            if f == 'pom.xml':
                pom_files.add(os.path.join(root, f))
    
    # 2. 向上搜索父目录（扫描 src/ 时 pom.xml 通常在项目根目录）
    current = os.path.abspath(target_directory)
    for _ in range(3):
        parent = os.path.dirname(current)
        if parent == current:
            break
        pom_path = os.path.join(parent, 'pom.xml')
        if os.path.isfile(pom_path):
            pom_files.add(pom_path)
        current = parent
    
    return list(pom_files)


def version_compare(v1, op, v2):
    """
    语义化版本比较
    v1 op v2 → True/False
    op: "<=", "<", ">=", ">", "==", "!=", "=<", "=>"
    支持简单的 x.y.z 格式
    """
    def parse_ver(v):
        # 提取数字部分
        parts = re.findall(r'\d+', str(v))
        return [int(p) for p in parts] if parts else [0]
    
    pv1 = parse_ver(v1)
    pv2 = parse_ver(v2)
    
    # 补齐长度
    maxlen = max(len(pv1), len(pv2))
    pv1 += [0] * (maxlen - len(pv1))
    pv2 += [0] * (maxlen - len(pv2))
    
    if op in ('<=', '=<'):
        return pv1 <= pv2
    elif op in ('>=', '=>'):
        return pv1 >= pv2
    elif op == '<':
        return pv1 < pv2
    elif op == '>':
        return pv1 > pv2
    elif op in ('==', '='):
        return pv1 == pv2
    elif op == '!=':
        return pv1 != pv2
    else:
        return False


def version_in_range(version, version_range):
    """
    检查版本是否在指定范围内
    version_range 格式: "<=1.2.4" 或 ">=1.0.0,<=1.4.2" 或 "<2.5.30"
    返回 True/False
    """
    if not version or version == "unknown":
        return False
    # 跳过未解析的占位符（如 ${revision}、${project.version}）
    if '${' in version:
        return False
    
    conditions = [c.strip() for c in version_range.split(',')]
    
    for cond in conditions:
        m = re.match(r'(<=|>=|=<|=>|<|>|==|=|!=)\s*(.+)', cond.strip())
        if m:
            op, target = m.group(1), m.group(2).strip()
            if not version_compare(version, op, target):
                return False
        else:
            # 没有操作符，视为 ==
            if not version_compare(version, '==', cond.strip()):
                return False
    
    return True


def check_framework_dependency(target_directory, dep_config):
    """
    检查目标目录是否使用了受影响版本的框架依赖
    
    dep_config 格式:
    {
        "group_id": "org.apache.shiro",
        "artifact_id": "shiro-spring", 
        "version_range": "<=1.2.4",
        "cve": "CVE-2016-4437",
        "description": "Shiro rememberMe 反序列化"
    }
    
    返回: [{"pom": "/path/to/pom.xml", "version": "1.2.4", ...}, ...] 或 []
    """
    pom_files = find_pom_files(target_directory)
    if not pom_files:
        return []
    
    results = []
    gid = dep_config.get("group_id", "")
    aid = dep_config.get("artifact_id", "")
    vrange = dep_config.get("version_range", "")
    cve = dep_config.get("cve", "")
    desc = dep_config.get("description", "")
    
    for pom_path in pom_files:
        deps = parse_pom_dependencies(pom_path)
        for dep in deps:
            if dep["group_id"] == gid and dep["artifact_id"] == aid:
                ver = dep["version"]
                if version_in_range(ver, vrange):
                    results.append({
                        "pom": pom_path,
                        "group_id": gid,
                        "artifact_id": aid,
                        "version": ver,
                        "cve": cve,
                        "description": desc,
                    })
    
    return results


def search_code_patterns(target_directory, patterns, file_extensions=None):
    """
    在源码中搜索配置特征（用于二次确认）
    patterns: ["CookieRememberMeManager", ...]
    返回: 匹配到的文件列表
    """
    if file_extensions is None:
        file_extensions = ['.java']
    
    matched_files = set()
    
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in ('.git', 'target', 'node_modules', 'vendor')]
        for fname in files:
            if any(fname.endswith(ext) for ext in file_extensions):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    for pattern in patterns:
                        if pattern in content:
                            matched_files.add(fpath)
                except:
                    pass
    
    return list(matched_files)

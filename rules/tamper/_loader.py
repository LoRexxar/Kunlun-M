# -*- coding: utf-8 -*-
"""
Tamper framework config loader.

Two-step framework detection:
1. Dependency file matching (composer.json, package.json, go.mod, etc.)
2. Fingerprint file detection (detect() function in each framework module)
"""

import os
import json
import logging

logger = logging.getLogger(__name__)

# Language -> tamper sub-package mapping
LANG_MODULES = {
    'php': 'rules.tamper.php',
    'python': 'rules.tamper.python',
    'javascript': 'rules.tamper.javascript',
    'java': 'rules.tamper.java',
    'go': 'rules.tamper.go',
    'c': 'rules.tamper.c',
}


def _parse_composer(dep_path):
    """Parse composer.json, return dict like {'composer': ['laravel/framework', ...]}."""
    try:
        with open(dep_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        result = {}
        for section in ('require', 'require-dev'):
            pkgs = data.get(section, {})
            if pkgs:
                result[section] = list(pkgs.keys())
        return result
    except Exception as e:
        logger.debug("[TAMPER] Failed to parse composer.json: {}".format(e))
        return {}


def _parse_requirements(dep_path):
    """Parse requirements.txt, return dict like {'requirements': ['flask', 'django', ...]}."""
    try:
        with open(dep_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        pkgs = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            # Extract package name (before version specifier)
            for sep in ['>=', '<=', '==', '!=', '~=', '>', '<', '[', ';']:
                if sep in line:
                    line = line.split(sep)[0].strip()
                    break
            if line:
                pkgs.append(line.strip())
        return {'requirements': pkgs} if pkgs else {}
    except Exception as e:
        logger.debug("[TAMPER] Failed to parse requirements.txt: {}".format(e))
        return {}


def _parse_pyproject(dep_path):
    """Parse pyproject.toml dependencies, return dict like {'pyproject': ['flask', ...]}."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return {}
    try:
        with open(dep_path, 'rb') as f:
            data = tomllib.load(f)
        pkgs = []
        deps = data.get('project', {}).get('dependencies', [])
        for dep in deps:
            # Extract name (before version specifier)
            for sep in ['>=', '<=', '==', '!=', '~=', '>', '<', '[', ';', ' ']:
                idx = dep.find(sep)
                if idx > 0:
                    pkgs.append(dep[:idx].strip())
                    break
            else:
                pkgs.append(dep.strip())
        return {'pyproject': pkgs} if pkgs else {}
    except Exception as e:
        logger.debug("[TAMPER] Failed to parse pyproject.toml: {}".format(e))
        return {}


def _parse_package_json(dep_path):
    """Parse package.json, return dict like {'package': ['express', ...]}."""
    try:
        with open(dep_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        result = {}
        for section in ('dependencies', 'devDependencies'):
            pkgs = data.get(section, {})
            if pkgs:
                result[section] = list(pkgs.keys())
        return result
    except Exception as e:
        logger.debug("[TAMPER] Failed to parse package.json: {}".format(e))
        return {}


def _parse_gomod(dep_path):
    """Parse go.mod, return dict like {'gomod': ['github.com/gin-gonic/gin', ...]}."""
    try:
        with open(dep_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        pkgs = []
        in_require = False
        for line in content.split('\n'):
            line = line.strip()
            if line == 'require (':
                in_require = True
                continue
            elif line == ')':
                in_require = False
                continue
            elif in_require and line:
                # Remove comments and trailing whitespace
                pkg = line.split()[0] if line.split() else ''
                if pkg and not pkg.startswith('//'):
                    pkgs.append(pkg)
            elif line.startswith('require '):
                # Single require statement
                parts = line.split()
                if len(parts) >= 2:
                    pkgs.append(parts[1])
        return {'gomod': pkgs} if pkgs else {}
    except Exception as e:
        logger.debug("[TAMPER] Failed to parse go.mod: {}".format(e))
        return {}


def _parse_pom(dep_path):
    """Parse pom.xml <dependencies>, return dict like {'pom': ['spring-boot-starter-web', ...]}."""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(dep_path)
        root = tree.getroot()
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        pkgs = []
        # Try with namespace
        deps = root.findall('.//m:dependency', ns)
        if not deps:
            # Try without namespace
            deps = root.findall('.//dependency')
        for dep in deps:
            artifact = dep.find('m:artifactId', ns)
            if artifact is None:
                artifact = dep.find('artifactId')
            if artifact is not None and artifact.text:
                pkgs.append(artifact.text)
        return {'pom': pkgs} if pkgs else {}
    except Exception as e:
        logger.debug("[TAMPER] Failed to parse pom.xml: {}".format(e))
        return {}


# Language -> [(dep_filename, parser_fn)]
DEP_PARSERS = {
    'php': [('composer.json', _parse_composer)],
    'python': [('requirements.txt', _parse_requirements), ('pyproject.toml', _parse_pyproject)],
    'javascript': [('package.json', _parse_package_json)],
    'go': [('go.mod', _parse_gomod)],
    'java': [('pom.xml', _parse_pom)],
    'c': [],
}


def _match_deps(installed_deps, framework_deps):
    """Check if any framework dependency matches installed packages.

    installed_deps keys are language-specific file types ('composer',
    'requirements', 'package', etc.), unified by _parse_* functions.
    framework_deps (DEPENDENCIES in each tamper module) use the same keys.
    However, _parse_composer currently returns section names ('require',
    'require-dev') rather than 'composer'. We handle both: try the exact
    key, and also scan all installed_deps sections as a fallback.
    """
    for dep_type, packages in framework_deps.items():
        # Exact key match (e.g. 'composer' → 'composer')
        installed = installed_deps.get(dep_type, [])
        for pkg in packages:
            pkg_lower = pkg.lower()
            for inst in installed:
                if pkg_lower in inst.lower():
                    return True
            # Fallback: scan ALL installed_deps sections. This handles the
            # _parse_composer key mismatch (require/require-dev vs composer)
            # and makes dependency matching robust to parser output format.
            if not installed:
                for section_pkgs in installed_deps.values():
                    for inst in section_pkgs:
                        if pkg_lower in inst.lower():
                            return True
    return False


def detect_frameworks(language, project_dir):
    """
    Detect frameworks for a given language and project directory.
    Uses two-step detection: dependency file matching -> fingerprint detection.

    :param language: language identifier (php, python, javascript, java, go, c)
    :param project_dir: project root directory path
    :return: list of matched framework module objects
    """
    if language not in LANG_MODULES:
        return []

    # Discover framework modules in the language subdirectory
    import importlib
    lang_pkg_name = LANG_MODULES[language]
    try:
        lang_pkg = importlib.import_module(lang_pkg_name)
    except ImportError:
        logger.debug("[TAMPER] No tamper sub-package for language: {}".format(language))
        return []

    pkg_path = os.path.dirname(lang_pkg.__file__)
    if not os.path.isdir(pkg_path):
        return []

    # Parse all dependency files for this language
    installed_deps = {}
    if language in DEP_PARSERS:
        for dep_file, parser_fn in DEP_PARSERS[language]:
            dep_path = os.path.join(project_dir, dep_file)
            if os.path.exists(dep_path):
                parsed = parser_fn(dep_path)
                installed_deps.update(parsed)

    # Iterate framework modules
    matched = []
    for fname in sorted(os.listdir(pkg_path)):
        if fname.startswith('_') or fname == '__init__.py' or not fname.endswith('.py'):
            continue
        mod_name = fname[:-3]
        try:
            mod = importlib.import_module('{}.{}'.format(lang_pkg_name, mod_name))
        except ImportError as e:
            logger.debug("[TAMPER] Failed to import framework {}: {}".format(mod_name, e))
            continue

        # Must have FRAMEWORK_NAME (excludes _base.py which has IS_REPAIR)
        if not hasattr(mod, 'FRAMEWORK_NAME'):
            continue

        fw_matched = False

        # Step 1: dependency file matching
        deps = getattr(mod, 'DEPENDENCIES', None)
        if deps and installed_deps:
            fw_matched = _match_deps(installed_deps, deps)

        # Step 2: fingerprint detection
        if not fw_matched:
            detect_fn = getattr(mod, 'detect', None)
            if detect_fn and callable(detect_fn):
                try:
                    fw_matched = detect_fn(project_dir, language)
                except Exception as e:
                    logger.debug("[TAMPER] detect() error in {}: {}".format(mod_name, e))

        if fw_matched:
            logger.info("[TAMPER] Framework detected: {} (language: {})".format(
                getattr(mod, 'FRAMEWORK_NAME', mod_name), language))
            matched.append(mod)

    # 兼容：扫描根目录旧版 tamper 文件（无 DEPENDENCIES/detect，只通过 -tp 手动指定）
    from rules.tamper._compat import scan_legacy_tampers, wrap_legacy_module
    try:
        tamper_root = os.path.dirname(__file__)
        legacy_list = scan_legacy_tampers(tamper_root)
        for mod, ltc_name, ltc_lang, ltc_path in legacy_list:
            if ltc_lang != language:
                continue
            wrapped = wrap_legacy_module(mod, ltc_name, ltc_lang, ltc_path)
            # 旧版没有自动检测，但如果有同名语言目录下不存在同名模块，
            # 将 wrapped 加入 matched 以便 -tp 参数能正确找到
            # （detect_frameworks 的结果也用于缓存，这里注册确保可用）
            logger.info("[TAMPER-COMPAT] Legacy framework registered: {} (language: {})".format(
                ltc_name, language))
            matched.append(wrapped)
    except Exception as e:
        logger.debug("[TAMPER-COMPAT] Legacy scan error: {}".format(e))

    return matched


def load_base_config(language):
    """
    Load base config (IS_REPAIR, IS_CONTROLLED) for a language.

    :param language: language identifier
    :return: (repair_dict, controlled_list) tuple
    """
    import importlib
    lang_pkg_name = LANG_MODULES.get(language)
    if not lang_pkg_name:
        return {}, []

    try:
        mod = importlib.import_module('{}.{}'.format(lang_pkg_name, '_base'))
        repair = getattr(mod, 'IS_REPAIR', {})
        controlled = getattr(mod, 'IS_CONTROLLED', [])
        return repair.copy() if isinstance(repair, dict) else {}, list(controlled) if isinstance(controlled, list) else []
    except ImportError:
        logger.debug("[TAMPER] No _base.py for language: {}".format(language))
        return {}, []


def merge_framework_config(repair_dict, controlled_list, framework_module):
    """
    Merge a framework module's config into repair_dict and controlled_list.

    :param repair_dict: existing repair dict (modified in-place)
    :param controlled_list: existing controlled list (modified in-place)
    :param framework_module: framework module with FILTER_FUNCTIONS, CONTROLLED_SOURCES, EXTRA_SINKS
    :return: dict of {pattern_str: set_of_svids} for EXTRA_SINKS
    """
    # Merge FILTER_FUNCTIONS into repair_dict
    fw_repair = getattr(framework_module, 'FILTER_FUNCTIONS', {})
    if fw_repair:
        for func_name, svids in fw_repair.items():
            # 兼容两种格式：{func: [svid]} 和 {func: {"safe_for": [svid]}}
            if isinstance(svids, dict):
                svid_list = svids.get('safe_for', [])
            elif isinstance(svids, list):
                svid_list = svids
            else:
                svid_list = []
            if func_name in repair_dict:
                existing = repair_dict[func_name]
                if isinstance(existing, list) and isinstance(svid_list, list):
                    merged = list(set(existing + svid_list))
                    repair_dict[func_name] = merged
                else:
                    repair_dict[func_name] = svid_list
            else:
                repair_dict[func_name] = svid_list if isinstance(svid_list, list) else []

    # Merge CONTROLLED_SOURCES into controlled_list
    fw_controlled = getattr(framework_module, 'CONTROLLED_SOURCES', [])
    if fw_controlled:
        existing_set = set(controlled_list)
        for src in fw_controlled:
            if src not in existing_set:
                controlled_list.append(src)

    # 收集 EXTRA_SINKS
    extra_sinks = {}
    fw_extra_sinks = getattr(framework_module, 'EXTRA_SINKS', [])
    if fw_extra_sinks:
        for sink_item in fw_extra_sinks:
            if isinstance(sink_item, (list, tuple)) and len(sink_item) >= 2:
                pattern = sink_item[0]
                svids = sink_item[1]
                if isinstance(svids, list):
                    if pattern not in extra_sinks:
                        extra_sinks[pattern] = set()
                    extra_sinks[pattern] |= set(svids)

    return extra_sinks

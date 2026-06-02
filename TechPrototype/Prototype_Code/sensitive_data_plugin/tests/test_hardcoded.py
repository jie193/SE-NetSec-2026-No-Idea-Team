import pytest
import bandit
from bandit.core import manager
from bandit.core import config as bandit_config


def test_hardcoded_password_assign():
    """测试 SC100: 变量赋值硬编码检测"""
    conf = bandit_config.BanditConfig(config_file=None)
    b_manager = manager.BanditManager(
        config=conf,
        agg_type='vuln',
        debug=False,
        verbose=True,
        quiet=False,
        profile=None,
        ignore_nosec=False,
    )

    import sys, os
    plugin_path = os.path.join(os.path.dirname(__file__), "..")
    sys.path.insert(0, plugin_path)

    test_file = os.path.join(os.path.dirname(__file__), "samples", "hardcoded_vuln.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    sc100_issues = [i for i in issues if i.test_id == "SC100"]
    assert len(sc100_issues) > 0

    # 安全文件不应产生告警
    safe_file = os.path.join(os.path.dirname(__file__), "samples", "hardcoded_clean.py")
    conf2 = bandit_config.BanditConfig(config_file=None)
    b_manager2 = manager.BanditManager(
        config=conf2,
        agg_type='vuln',
        debug=False,
        verbose=True,
        quiet=False,
        profile=None,
        ignore_nosec=False,
    )
    b_manager2.discover_files([safe_file])
    b_manager2.run_tests()
    safe_issues = [i for i in b_manager2.get_issue_list() if i.test_id == "SC100"]
    assert len(safe_issues) == 0


def test_dict_sensitive_info():
    """测试 SC101: 字典键值对检测"""
    conf = bandit_config.BanditConfig(config_file=None)
    b_manager = manager.BanditManager(
        config=conf,
        agg_type='vuln',
        debug=False,
        verbose=True,
        quiet=False,
        profile=None,
        ignore_nosec=False,
    )

    import sys, os
    plugin_path = os.path.join(os.path.dirname(__file__), "..")
    sys.path.insert(0, plugin_path)

    test_file = os.path.join(os.path.dirname(__file__), "samples", "hardcoded_vuln.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    sc101_issues = [i for i in issues if i.test_id == "SC101"]
    assert len(sc101_issues) > 0


def test_funcarg_sensitive_info():
    """测试 SC102: 函数参数检测"""
    conf = bandit_config.BanditConfig(config_file=None)
    b_manager = manager.BanditManager(
        config=conf,
        agg_type='vuln',
        debug=False,
        verbose=True,
        quiet=False,
        profile=None,
        ignore_nosec=False,
    )

    import sys, os
    plugin_path = os.path.join(os.path.dirname(__file__), "..")
    sys.path.insert(0, plugin_path)

    test_file = os.path.join(os.path.dirname(__file__), "samples", "hardcoded_vuln.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    sc102_issues = [i for i in issues if i.test_id == "SC102"]
    assert len(sc102_issues) > 0
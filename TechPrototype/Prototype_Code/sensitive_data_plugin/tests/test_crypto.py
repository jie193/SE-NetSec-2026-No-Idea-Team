import pytest
import bandit
from bandit.core import manager
from bandit.core import config as bandit_config


def test_weak_hash_algorithm():
    """测试 SC200: 弱哈希算法检测"""
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

    test_file = os.path.join(os.path.dirname(__file__), "samples", "crypto_vuln.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    sc200_issues = [i for i in issues if i.test_id == "SC200"]
    assert len(sc200_issues) > 0

    # 安全文件不应产生告警
    safe_file = os.path.join(os.path.dirname(__file__), "samples", "crypto_clean.py")
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
    safe_issues = [i for i in b_manager2.get_issue_list() if i.test_id == "SC200"]
    assert len(safe_issues) == 0


def test_weak_cipher_algorithm():
    """测试 SC201: 弱加密算法检测"""
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

    test_file = os.path.join(os.path.dirname(__file__), "samples", "crypto_vuln.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    sc201_issues = [i for i in issues if i.test_id == "SC201"]
    assert len(sc201_issues) > 0


def test_unsafe_encryption_mode():
    """测试 SC202: 不安全加密模式检测"""
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

    test_file = os.path.join(os.path.dirname(__file__), "samples", "crypto_vuln.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    sc202_issues = [i for i in issues if i.test_id == "SC202"]
    assert len(sc202_issues) > 0


def test_weak_cryptographic_key():
    """测试 SC203: 弱密钥长度检测"""
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

    test_file = os.path.join(os.path.dirname(__file__), "samples", "crypto_vuln.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    sc203_issues = [i for i in issues if i.test_id == "SC203"]
    assert len(sc203_issues) > 0
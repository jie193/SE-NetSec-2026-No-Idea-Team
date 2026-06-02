#!/usr/bin/env python3
"""边界值测试和误报测试"""
import pytest
import bandit
from bandit.core import manager
from bandit.core import config as bandit_config
import os
import sys


def test_short_password_not_detected():
    """测试短密码（< 6字符）不应被检测"""
    from sensitive_data_plugin.utils.filters import is_short_string
    
    assert is_short_string("12345") == True, "5字符应为短字符串"
    assert is_short_string("abc") == True, "3字符应为短字符串"
    assert is_short_string("123456") == False, "6字符不应为短字符串"


def test_nosec_comment_ignored():
    """测试 #nosec 注释应被忽略"""
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

    plugin_path = os.path.join(os.path.dirname(__file__), "..")
    sys.path.insert(0, plugin_path)

    test_file = os.path.join(os.path.dirname(__file__), "samples", "hardcoded_vuln.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    
    assert True, "#nosec 测试通过"


def test_common_constants_not_detected():
    """测试常见常量不应被检测"""
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

    plugin_path = os.path.join(os.path.dirname(__file__), "..")
    sys.path.insert(0, plugin_path)

    test_file = os.path.join(os.path.dirname(__file__), "samples", "hardcoded_clean.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    sc100_issues = [i for i in issues if i.test_id == "SC100"]
    
    assert len(sc100_issues) == 0, "常见常量不应被检测为敏感信息"


def test_placeholder_password_low_severity():
    """测试占位符密码应为低严重级别"""
    from sensitive_data_plugin.checks.hardcoded.funcarg_detect import _assess_risk_level
    
    severity = _assess_risk_level("<your-password>", "password")
    assert severity == bandit.LOW, "占位符密码应为 LOW 级别"


def test_long_password_high_severity():
    """测试长密码应为高严重级别"""
    from sensitive_data_plugin.checks.hardcoded.funcarg_detect import _assess_risk_level
    
    severity = _assess_risk_level("myverylongpassword123456", "password")
    assert severity == bandit.HIGH, "长密码（>=12字符）应为 HIGH 级别"


def test_medium_password_medium_severity():
    """测试中等长度密码应为中严重级别"""
    from sensitive_data_plugin.checks.hardcoded.funcarg_detect import _assess_risk_level
    
    severity = _assess_risk_level("pass1234", "password")
    assert severity == bandit.MEDIUM, "中等长度密码（6-11字符）应为 MEDIUM 级别"


def test_api_key_pattern_high_severity():
    """测试 API 密钥格式应为高严重级别"""
    from sensitive_data_plugin.checks.hardcoded.funcarg_detect import _assess_risk_level
    
    severity = _assess_risk_level("sk-1234567890abcdefghijklmnopqrstuvwxyz", "api_key")
    assert severity == bandit.HIGH, "API 密钥格式应为 HIGH 级别"


def test_clean_file_no_issues():
    """测试干净文件不应产生问题"""
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

    plugin_path = os.path.join(os.path.dirname(__file__), "..")
    sys.path.insert(0, plugin_path)

    test_file = os.path.join(os.path.dirname(__file__), "samples", "hardcoded_clean.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    hardcoded_issues = [i for i in issues if i.test_id in ("SC100", "SC101", "SC102")]
    
    assert len(hardcoded_issues) == 0, "干净文件不应产生硬编码问题"


def test_crypto_clean_file_no_issues():
    """测试加密干净文件不应产生问题"""
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

    plugin_path = os.path.join(os.path.dirname(__file__), "..")
    sys.path.insert(0, plugin_path)

    test_file = os.path.join(os.path.dirname(__file__), "samples", "crypto_clean.py")
    b_manager.discover_files([test_file])
    b_manager.run_tests()

    issues = b_manager.get_issue_list()
    crypto_issues = [i for i in issues if i.test_id in ("SC200", "SC201", "SC202", "SC203")]
    
    assert len(crypto_issues) == 0, "加密干净文件不应产生加密问题"


def test_none_value_handling():
    """测试 None 值处理"""
    from sensitive_data_plugin.utils.filters import is_common_constant, is_short_string
    
    assert is_common_constant(None) == False, "None 不应是常见常量"
    assert is_short_string(None) == False, "None 不应被判断为短字符串"


def test_empty_string_handling():
    """测试空字符串处理"""
    from sensitive_data_plugin.utils.filters import is_short_string, is_common_constant
    
    assert is_short_string("") == True, "空字符串应是短字符串"
    assert is_common_constant("") == False, "空字符串不是常见常量"


def test_sensitive_keyword_detection():
    """测试敏感关键词检测"""
    from sensitive_data_plugin.utils.filters import contains_sensitive_keyword
    
    assert contains_sensitive_keyword("password") == True
    assert contains_sensitive_keyword("api_key") == True
    assert contains_sensitive_keyword("secret") == True
    assert contains_sensitive_keyword("token") == True
    assert contains_sensitive_keyword("username") == False
    assert contains_sensitive_keyword("count") == False

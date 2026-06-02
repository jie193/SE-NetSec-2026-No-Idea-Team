#!/usr/bin/env python3
"""性能测试脚本"""
import time
import subprocess
import os

def run_benchmark():
    """运行性能基准测试"""
    test_dir = "sensitive_data_plugin/tests/samples/"
    
    print("=" * 60)
    print("性能测试开始")
    print("=" * 60)
    
    # 测试1: 扫描小项目(2个文件)
    print("\n测试1: 扫描测试样例目录")
    start = time.time()
    result = subprocess.run(
        ["bandit", "-r", test_dir, "--tests", "SC100,SC101,SC102,SC200,SC201,SC202,SC203"],
        capture_output=True,
        text=True
    )
    elapsed = time.time() - start
    
    print(f"  扫描时间: {elapsed:.3f} 秒")
    
    # 计算代码行数
    total_lines = 0
    for root, dirs, files in os.walk(test_dir):
        for file in files:
            if file.endswith('.py'):
                with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                    total_lines += len(f.readlines())
    
    print(f"  扫描行数: {total_lines} 行")
    print(f"  吞吐量: {total_lines/elapsed:.1f} 行/秒")
    
    return elapsed, total_lines

if __name__ == "__main__":
    run_benchmark()

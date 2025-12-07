# 测试框架说明

## 📋 概述

本目录包含 PrivateTunnel 项目的完整测试框架，包括单元测试、集成测试和功能测试。

## 🚀 快速开始

### 1. 安装测试依赖

```bash
pip install -r requirements.txt
```

### 2. 运行所有测试

```bash
python scripts/run_tests.py
```

### 3. 运行特定类型的测试

```bash
# 只运行单元测试
python scripts/run_tests.py --unit

# 只运行集成测试
python scripts/run_tests.py --integration

# 生成覆盖率报告
python scripts/run_tests.py --coverage

# 详细输出
python scripts/run_tests.py --verbose
```

### 4. 使用 pytest 直接运行

```bash
# 运行所有测试
pytest tests/

# 运行特定测试文件
pytest tests/test_multi_node_manager.py

# 运行特定测试类
pytest tests/test_multi_node_manager.py::TestMultiNodeManager

# 运行特定测试方法
pytest tests/test_multi_node_manager.py::TestMultiNodeManager::test_add_node

# 生成覆盖率报告
pytest --cov=core --cov-report=html tests/
```

## 📁 测试文件结构

```
tests/
├── __init__.py                 # 测试包初始化
├── conftest.py                 # pytest 配置和共享 fixtures
├── test_multi_node_manager.py  # 多节点管理器测试
├── test_node_health_checker.py # 健康检查器测试
├── test_smart_routing.py       # 智能选路测试
├── test_connection_monitor.py  # 连接监控测试
├── test_adaptive_params.py     # 自适应参数测试
├── test_chatgpt_optimizer.py   # ChatGPT 优化器测试
├── test_integration.py         # 集成测试
└── test_utils.py               # 测试工具
```

## 🧪 测试覆盖范围

### 单元测试

- **多节点管理器** (`test_multi_node_manager.py`)
  - 节点添加、更新、删除
  - 节点状态管理
  - 最佳节点查找
  - 故障转移

- **健康检查器** (`test_node_health_checker.py`)
  - TCP 连接检查
  - HTTPS 连接检查
  - DNS 解析检查
  - 完整节点健康检查

- **智能选路** (`test_smart_routing.py`)
  - 节点评分计算
  - 不同选路策略
  - 最佳节点选择

- **连接监控** (`test_connection_monitor.py`)
  - 监控器初始化
  - 监控启动/停止
  - 报告生成

- **自适应参数** (`test_adaptive_params.py`)
  - 参数调整建议
  - 参数序列化

- **ChatGPT 优化器** (`test_chatgpt_optimizer.py`)
  - 域名解析
  - 连接性测试

### 集成测试

- **完整工作流程** (`test_integration.py`)
  - 多节点管理 → 健康检查 → 智能选路 → 连接监控
  - 节点故障转移流程

## 📊 测试覆盖率

目标覆盖率：
- 整体覆盖率 > 70%
- 核心模块覆盖率 > 90%

生成覆盖率报告：
```bash
pytest --cov=core --cov-report=html --cov-report=term tests/
```

报告将生成在 `htmlcov/index.html`。

## ⚙️ 配置

测试配置在 `pytest.ini` 中：

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v
    --strict-markers
    --tb=short
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow tests
```

## 🔧 Fixtures

共享的 fixtures 定义在 `conftest.py` 中：

- `temp_dir`: 临时目录
- `sample_node`: 示例节点
- `sample_nodes`: 示例节点列表
- `multi_node_manager`: 多节点管理器实例
- `node_health_checker`: 健康检查器实例
- `sample_metrics`: 示例连接指标
- `sample_session`: 示例连接会话

## 📝 编写新测试

1. 在 `tests/` 目录下创建新的测试文件，命名格式：`test_*.py`
2. 创建测试类，命名格式：`Test*`
3. 创建测试方法，命名格式：`test_*`
4. 使用 fixtures 来设置测试数据

示例：

```python
"""新模块测试。New module tests."""

from __future__ import annotations

import pytest

from core.tools.new_module import NewModule


class TestNewModule:
    """新模块测试类。New module test class."""

    def test_basic_functionality(self):
        """测试基本功能。Test basic functionality."""
        module = NewModule()
        result = module.do_something()
        assert result is not None
```

## ⚠️ 注意事项

1. **测试隔离**：每个测试应该独立，不依赖其他测试
2. **模拟数据**：使用 fixture 和 mock 避免依赖外部服务
3. **测试速度**：集成测试可能较慢，标记为 `@pytest.mark.slow`
4. **网络依赖**：某些测试需要网络连接，可能在某些环境下失败

## 🔗 相关文档

- [pytest 文档](https://docs.pytest.org/)
- [pytest-cov 文档](https://pytest-cov.readthedocs.io/)



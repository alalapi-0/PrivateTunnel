# 项目功能概览

自动生成时间：2025-12-08 22:54:03

## core\port_config.py
- 函数 `_parse_port`：无文档
- 函数 `resolve_listen_port`：Return the listen port and the environment variable that defined it.
- 函数 `get_default_wg_port`：Return the WireGuard listen port derived from environment variables.

## core\project_overview.py
- 类 `MethodSummary`：表示类方法的概览信息。
- 类 `DefinitionSummary`：表示 Python 源文件中的定义信息。
- 函数 `_iter_python_files`：遍历 ``root`` 目录下的 Python 源文件。
- 函数 `_extract_doc`：提取 ``node`` 的文档字符串首行。
- 函数 `_summarize_class`：收集类及其方法的概要信息。
- 函数 `_summarize_module`：解析 ``path`` 并返回该模块中的定义信息。
- 函数 `generate_project_overview`：生成项目功能概览文档。

## core\proxy_utils.py
- 函数 `_normalize_proxy_url`：规范化代理 URL。
- 函数 `_get_env_var_case_insensitive`：从环境变量中读取值（大小写不敏感）。
- 函数 `_check_port_listening`：检查指定主机和端口是否在监听。
- 函数 `_test_http_proxy`：测试 HTTP 代理是否可用。
- 函数 `get_proxy_config`：从环境变量读取代理配置并返回标准格式。
- 函数 `get_proxy_for_urllib`：为 urllib 库提供代理配置。
- 函数 `is_proxy_configured`：检查是否配置了代理（至少有一个代理环境变量）。
- 函数 `detect_local_proxy`：自动检测本地代理服务。
- 函数 `auto_configure_proxy`：自动检测并配置代理。
- 函数 `log_proxy_status`：记录代理配置状态。
- 函数 `validate_proxy_config`：验证代理配置是否可用。
- 函数 `get_proxy_config_with_fallback`：获取代理配置，支持验证和降级。
- 函数 `verify_proxy_on_startup`：在程序启动时验证代理配置（可选调用）。

## core\ssh_utils.py
- 类 `SSHKeyLoadError`：Raised when a private key cannot be parsed.
- 类 `SmartSSHError`：Raised when both Paramiko and ``ssh.exe`` backends fail.
  - 方法 `__init__`：无文档
- 类 `SSHAttempt`：Metadata about one backend attempt.
- 类 `SSHResult`：Return value for :func:`smart_ssh`.
- 类 `SSHProbeResult`：Outcome for :func:`probe_publickey_auth`.
- 函数 `_default_home`：无文档
- 函数 `_default_ssh_executable`：无文档
- 函数 `nuke_known_host`：Remove stale host-key fingerprints for ``ip`` from ``known_hosts``.
- 函数 `pick_default_key`：Return the preferred default private key path for Windows prompts.
- 函数 `ask_key_path`：Prompt for a private key path with validation suitable for Windows.
- 函数 `wait_port_open`：Poll ``host:port`` until it accepts TCP connections or ``timeout`` expires.
- 函数 `probe_publickey_auth`：Probe SSH public-key authentication until ``command`` succeeds.
- 函数 `_candidate_keys`：Yield supported Paramiko key classes in preferred order.
- 函数 `load_private_key`：Load a private key from ``path``.
- 函数 `run_ssh_script_via_stdin`：Send a multi-line shell script to the remote host via ``ssh`` stdin.
- 函数 `run_ssh_paramiko_script_via_stdin`：Send ``script_text`` via Paramiko, returning ``None`` if fallback is needed.
- 函数 `smart_push_script`：Push ``script_text`` via Paramiko first and fall back to ``ssh`` stdin.
- 函数 `run_ssh_paramiko`：Try executing ``command`` via Paramiko.
- 函数 `run_ssh_exe`：Execute ``command`` using the system ``ssh`` binary.
- 函数 `smart_ssh`：Execute ``command`` on ``host`` using either Paramiko or ``ssh.exe``.

## core\tools\adaptive_params.py
- 类 `ParameterSet`：参数集合。Parameter set.
  - 方法 `__post_init__`：无文档
  - 方法 `to_dict`：转换为字典。Convert to dictionary.
  - 方法 `from_dict`：从字典创建。Create from dictionary.
- 类 `ParameterAdjustment`：参数调整记录。Parameter adjustment record.
  - 方法 `to_dict`：转换为字典。Convert to dictionary.
  - 方法 `from_dict`：从字典创建。Create from dictionary.
- 类 `AdaptiveParameterTuner`：自适应参数调整器。Adaptive parameter tuner.
  - 方法 `__init__`：初始化调整器。Initialize tuner.
  - 方法 `_load_history`：加载调整历史。Load adjustment history.
  - 方法 `_save_history`：保存调整历史。Save adjustment history.
  - 方法 `analyze_and_suggest`：分析连接质量并建议参数调整。Analyze quality and suggest parameter adjustment.
  - 方法 `_suggest_keepalive`：建议 Keepalive 值。Suggest keepalive value.
  - 方法 `_suggest_mtu`：建议 MTU 值。Suggest MTU value.
  - 方法 `apply_adjustment`：应用参数调整。Apply parameter adjustment.
  - 方法 `evaluate_adjustment`：评估参数调整效果。Evaluate adjustment effectiveness.
  - 方法 `rollback_last_adjustment`：回滚最后一次调整。Rollback last adjustment.
  - 方法 `get_recommendations`：获取参数调整建议。Get parameter adjustment recommendations.

## core\tools\chatgpt_domains.py
- 函数 `get_chatgpt_domains`：获取 ChatGPT 域名列表。Get ChatGPT domain list.
- 函数 `is_chatgpt_domain`：判断是否为 ChatGPT 域名。Check if domain is ChatGPT-related.

## core\tools\chatgpt_optimizer.py
- 类 `ChatGPTOptimizer`：ChatGPT 专用优化器。ChatGPT-specific optimizer.
  - 方法 `__init__`：初始化优化器。Initialize optimizer.
  - 方法 `resolve_chatgpt_domains`：解析 ChatGPT 域名到 IP。Resolve ChatGPT domains to IPs.
  - 方法 `test_chatgpt_connectivity`：测试 ChatGPT 连接性。Test ChatGPT connectivity.
  - 方法 `optimize_for_chatgpt`：为 ChatGPT 优化参数。Optimize parameters for ChatGPT.
  - 方法 `generate_split_config`：生成分流配置文件。Generate split routing configuration.

## core\tools\connection_monitor.py
- 类 `ConnectionMonitor`：连接质量监控器。Connection quality monitor.
  - 方法 `__init__`：初始化监控器。Initialize monitor.
  - 方法 `start_monitoring`：开始监控。Start monitoring.
  - 方法 `stop_monitoring`：停止监控。Stop monitoring.
  - 方法 `_monitor_loop`：监控循环。Monitor loop.
  - 方法 `_collect_metrics`：收集指标。Collect metrics.
  - 方法 `_check_quality_degraded`：检查质量是否下降。Check if quality degraded.
  - 方法 `_save_session`：保存会话数据。Save session data.
  - 方法 `get_current_stats`：获取当前统计。Get current statistics.
  - 方法 `generate_report`：生成连接质量报告。Generate connection quality report.
  - 方法 `_calculate_quality_score`：计算质量评分。Calculate quality score (0-100).
  - 方法 `_evaluate_and_adjust_params`：评估并调整参数。Evaluate and adjust parameters.

## core\tools\connection_stats.py
- 类 `ConnectionMetrics`：连接指标。Connection metrics.
  - 方法 `__post_init__`：无文档
  - 方法 `to_dict`：转换为字典。Convert to dictionary.
  - 方法 `from_dict`：从字典创建。Create from dictionary.
- 类 `ConnectionSession`：连接会话。Connection session.
  - 方法 `__post_init__`：无文档
  - 方法 `add_metrics`：添加指标。Add metrics.
  - 方法 `get_duration`：获取会话持续时间。Get session duration.
  - 方法 `to_dict`：转换为字典。Convert to dictionary.
  - 方法 `from_dict`：从字典创建。Create from dictionary.

## core\tools\diagnose_socks_proxy.py
- 函数 `print_success`：打印成功消息。Print success message.
- 函数 `print_error`：打印错误消息。Print error message.
- 函数 `print_warning`：打印警告消息。Print warning message.
- 函数 `print_info`：打印信息消息。Print info message.
- 函数 `check_ssh_installed`：检查SSH是否已安装。Check if SSH is installed.
- 函数 `check_port_listening`：检查端口是否在监听。Check if port is listening.
- 函数 `check_socks_proxy`：测试SOCKS代理是否工作。Test if SOCKS proxy is working.
- 函数 `check_ssh_process`：检查是否有SSH隧道进程在运行。Check if SSH tunnel process is running.
- 函数 `test_vps_connection`：测试VPS SSH连接。Test VPS SSH connection.
- 函数 `check_local_port`：检查本地端口是否被占用。Check if local port is in use.
- 函数 `get_vps_instances`：从Vultr API获取VPS实例列表。Get VPS instances from Vultr API.
- 函数 `select_vps_instance`：选择VPS实例。Select VPS instance.
- 函数 `generate_ssh_command`：生成SSH隧道命令。Generate SSH tunnel command.
- 函数 `main`：主函数。Main function.

## core\tools\generate_wg_conf.py
- 函数 `parse_args`：Parse command-line arguments.
- 函数 `ensure_output_path`：Abort if *path* exists and overwriting is not allowed.
- 函数 `render_interface_section`：Render the ``[Interface]`` section based on client parameters.
- 函数 `render_peer_section`：Render the ``[Peer]`` section using endpoint and routing details.
- 函数 `render_configuration`：Convert the validated configuration dictionary into WireGuard text.
- 函数 `render_configuration_from_files`：Load and validate JSON files before rendering a WireGuard configuration.
- 函数 `main`：无文档

## core\tools\generate_wg_conf_gui.py
- 类 `WireGuardGeneratorUI`：A lightweight GUI for invoking the configuration generator.
  - 方法 `__init__`：无文档
  - 方法 `_build_form`：无文档
  - 方法 `_browse_schema`：无文档
  - 方法 `_browse_input`：无文档
  - 方法 `_browse_output`：无文档
  - 方法 `_generate_configuration`：无文档
  - 方法 `_resolve_path`：无文档
  - 方法 `_append_log`：无文档
- 函数 `main`：无文档

## core\tools\multi_node_manager.py
- 类 `NodeStatus`：节点状态枚举。Node status enumeration.
- 类 `NodeMetadata`：节点元数据。Node metadata.
- 类 `Node`：节点信息。Node information.
  - 方法 `to_dict`：转换为字典。Convert to dictionary.
  - 方法 `from_dict`：从字典创建。Create from dictionary.
- 类 `MultiNodeConfig`：多节点配置。Multi-node configuration.
  - 方法 `__post_init__`：无文档
  - 方法 `to_dict`：转换为字典。Convert to dictionary.
  - 方法 `from_dict`：从字典创建。Create from dictionary.
  - 方法 `get_node`：根据 ID 获取节点。Get node by ID.
  - 方法 `get_default_node`：获取默认节点。Get default node.
  - 方法 `add_node`：添加节点。Add node.
  - 方法 `remove_node`：删除节点。Remove node.
  - 方法 `set_default_node`：设置默认节点。Set default node.
- 类 `MultiNodeManager`：多节点管理器。Multi-node manager.
  - 方法 `__init__`：初始化管理器。Initialize manager.
  - 方法 `_load`：加载配置。Load configuration.
  - 方法 `save`：保存配置。Save configuration.
  - 方法 `add_node_from_instance`：从实例信息创建节点。Create node from instance info.
  - 方法 `update_node_info`：更新节点信息。Update node information.
  - 方法 `update_node_status`：更新节点状态。Update node status.
  - 方法 `get_all_nodes`：获取所有节点。Get all nodes.
  - 方法 `get_active_nodes`：获取所有活跃节点。Get all active nodes.
  - 方法 `get_default_node`：获取默认节点。Get default node.
  - 方法 `check_node_health`：检查节点健康状态。Check node health status.
  - 方法 `check_all_nodes`：检查所有节点健康状态。Check all nodes health.
  - 方法 `find_best_node`：查找最佳可用节点（支持智能选路）。Find best available node with smart routing.
  - 方法 `switch_to_backup_node`：切换到备用节点。Switch to backup node.
  - 方法 `switch_to_backup_node_with_retry`：切换到备用节点（带重试）。Switch to backup node with retry.

## core\tools\node_health_checker.py
- 类 `HealthCheckResult`：健康检查结果。Health check result.
- 类 `HealthCheckMetrics`：健康检查指标。Health check metrics.
  - 方法 `__post_init__`：无文档
- 类 `NodeHealthChecker`：节点健康检查器。Node health checker.
  - 方法 `__init__`：初始化健康检查器。Initialize health checker.
  - 方法 `check_icmp`：检查 ICMP 连通性。Check ICMP connectivity.
  - 方法 `_extract_latency_from_ping`：从 ping 输出中提取延迟。Extract latency from ping output.
  - 方法 `check_tcp`：检查 TCP 连接。Check TCP connection.
  - 方法 `check_https`：检查 HTTPS 可达性。Check HTTPS reachability.
  - 方法 `check_dns`：检查 DNS 解析。Check DNS resolution.
  - 方法 `check_wireguard_handshake`：检查 WireGuard 握手（通过 UDP 端口检测）。
  - 方法 `check_node`：执行完整的节点健康检查。Perform complete node health check.
- 类 `ExponentialBackoff`：指数退避重试。Exponential backoff retry.
  - 方法 `__init__`：初始化指数退避。Initialize exponential backoff.
  - 方法 `next_delay`：获取下一次延迟。Get next delay.
  - 方法 `reset`：重置计数器。Reset counter.

## core\tools\render_from_env.py
- 函数 `parse_args`：无文档
- 函数 `substitute_env`：Substitute ${VAR} placeholders using the process environment.
- 函数 `ensure_no_placeholders`：Abort if *text* still contains ${VAR} markers.
- 函数 `render`：无文档
- 函数 `main`：无文档

## core\tools\smart_routing.py
- 类 `RoutingStrategy`：选路策略。Routing strategy.
- 类 `NodeScore`：节点评分。Node score.
  - 方法 `calculate_overall`：计算综合评分。Calculate overall score.
- 类 `SmartRouter`：智能选路器。Smart router.
  - 方法 `__init__`：初始化智能选路器。Initialize smart router.
  - 方法 `probe_latency`：探测节点延迟（多轮测试）。Probe node latency with multiple rounds.
  - 方法 `test_bandwidth`：测试节点带宽（可选功能）。Test node bandwidth (optional).
  - 方法 `calculate_node_score`：计算节点评分。Calculate node score.
  - 方法 `select_best_node`：选择最佳节点。Select best node.
  - 方法 `select_best_node_for_chatgpt`：为 ChatGPT 选择最佳节点。Select best node for ChatGPT.

## core\tools\v2ray_client_config.py
- 函数 `generate_v2ray_client_config`：生成 V2Ray 客户端配置。
- 函数 `generate_vmess_url`：生成 VMess URL。
- 函数 `save_v2ray_config`：保存 V2Ray 配置到文件。

## core\tools\v2ray_config.py
- 函数 `generate_v2ray_uuid`：生成 V2Ray UUID。Generate a V2Ray UUID.
- 函数 `generate_v2ray_server_config`：生成 V2Ray 服务器端配置。
- 函数 `generate_v2ray_config_json`：将 V2Ray 配置转换为 JSON 字符串。

## core\tools\validate_config.py
- 函数 `_require_jsonschema`：Import :mod:`jsonschema` and provide a helpful error if missing.
- 函数 `load_json_file`：Read a JSON file using UTF-8 encoding.
- 函数 `mask_sensitive`：Return a copy of *data* with secrets such as private keys masked.
- 函数 `validate_json`：Validate *document* against *schema* and exit with contextual errors.
- 函数 `parse_args`：Configure and parse command-line arguments.
- 函数 `main`：无文档

## core\tools\vultr_manager.py
- 类 `VultrError`：Custom exception for Vultr API operations.
- 类 `IPv4HTTPAdapter`：无文档
  - 方法 `init_poolmanager`：无文档
  - 方法 `get_connection`：无文档
  - 方法 `_get_conn`：无文档
  - 方法 `proxy_manager_for`：无文档
  - 方法 `_prepare_conn`：无文档
- 函数 `_hdr`：Build request headers for Vultr API calls.
- 函数 `_session`：无文档
- 函数 `_friendly_error_message`：无文档
- 函数 `list_ssh_keys`：Return all SSH keys associated with the account.
- 函数 `list_instances`：Return all VPS instances associated with the account.
- 函数 `list_snapshots`：Return all snapshots associated with the account.
- 函数 `create_ssh_key`：Create a new SSH key in Vultr.
- 函数 `create_instance`：Create a Vultr instance and return the raw instance payload.
- 函数 `wait_instance_active`：Poll instance status until it becomes active and returns its IP.
- 函数 `destroy_instance`：Destroy a Vultr instance.
- 函数 `reinstall_with_ssh_keys`：Trigger ``Reinstall SSH Keys`` for an instance.

## core\tools\wireguard_installer.py
- 类 `_CommandResult`：无文档
- 类 `WireGuardProvisionError`：Raised when provisioning fails.
- 函数 `_load_private_key`：无文档
- 函数 `_run`：无文档
- 函数 `_run_checked`：无文档
- 函数 `provision`：Provision WireGuard on a remote instance via SSH.

## core\vultr_api.py
- 类 `VultrAPIError`：Raised when the Vultr API returns an unexpected response.
- 函数 `_headers`：无文档
- 函数 `_format_http_error`：无文档
- 函数 `_request`：无文档
- 函数 `_paginate`：无文档
- 函数 `ensure_ssh_key`：Ensure ``pubkey_text`` exists on Vultr and return its id.
- 函数 `_get_snapshot_info`：无文档
- 函数 `pick_snapshot`：Pick a snapshot ID based on ``snapshot_id_env`` or fall back to latest.
- 函数 `_get_plan_info`：无文档
- 函数 `_get_disk_size`：无文档
- 函数 `_check_snapshot_size`：无文档
- 函数 `create_instance`：Create an instance with optional snapshot and SSH keys.
- 函数 `reinstall_instance`：Trigger ``Reinstall SSH Keys`` for an instance.
- 函数 `wait_instance_ready`：Poll the Vultr API until the instance becomes active and running.
- 函数 `auto_create`：High-level helper that performs the whole creation flow.

## legacy\server\split\resolve_domains.py
- 类 `ConfigError`：Raised when the YAML configuration cannot be parsed.
- 类 `DomainResult`：无文档
  - 方法 `merge`：无文档
- 函数 `parse_scalar`：无文档
- 函数 `determine_container`：无文档
- 函数 `simple_yaml_load`：无文档
- 函数 `load_config`：无文档
- 函数 `resolve_with_dig`：无文档
- 函数 `resolve_with_socket`：无文档
- 函数 `resolve_domain`：无文档
- 函数 `ensure_state_dir`：无文档
- 函数 `collapse_ipv4`：无文档
- 函数 `build_arg_parser`：无文档
- 函数 `extract_domains`：无文档
- 函数 `main`：无文档

## legacy\server\toy-gateway\toy_tun_gateway.py
- 函数 `load_env`：无文档
- 函数 `parse_listen`：无文档
- 函数 `encode_frame`：无文档
- 函数 `parse_frame`：无文档
- 类 `ToyTunGateway`：无文档
  - 方法 `__init__`：无文档
  - 方法 `log`：无文档
  - 方法 `log_debug`：无文档
  - 方法 `start`：无文档
  - 方法 `stop`：无文档
  - 方法 `signal_stop`：无文档
  - 方法 `setup_udp_socket`：无文档
  - 方法 `setup_tun_device`：无文档
  - 方法 `on_udp_readable`：无文档
  - 方法 `on_tun_readable`：无文档
  - 方法 `handle_data_from_udp`：无文档
  - 方法 `forward_packet_to_clients`：无文档
  - 方法 `send_udp_frame`：无文档
  - 方法 `print_stats`：无文档
- 函数 `build_arg_parser`：无文档
- 函数 `resolve_options`：无文档
- 函数 `configure_logging`：无文档
- 函数 `main`：无文档

## main.py
- 类 `SSHResult`：远程 SSH 命令执行的结果容器。Result of a remote SSH command execution.
- 类 `SSHContext`：封装远程 SSH 执行所需的连接参数。Connection parameters for remote SSH execution.
- 类 `DeploymentError`：在自动化部署 WireGuard 失败时抛出的异常。Raised when the automated WireGuard deployment fails.
- 类 `MenuAction`：定义交互式菜单选项。Define an interactive menu option for the CLI.
- 函数 `_colorize`：用 ANSI 颜色编码包装文本。Return ``message`` wrapped in ANSI color codes.
- 函数 `_log_to_file`：如启用则把日志写入文件。Append ``message`` to the deploy log if enabled.
- 函数 `logwrite`：打印信息（可选颜色）并写入日志。Print ``message`` (optionally colorized) and persist to the log file.
- 函数 `log_info`：以蓝色输出一般信息。Print an informational message in blue.
- 函数 `log_success`：以绿色输出成功提示。Print a success message in green.
- 函数 `log_warning`：以黄色输出警告信息。Print a warning message in yellow.
- 函数 `log_error`：以红色输出错误信息。Print an error message in red.
- 函数 `log_section`：打印分隔线用于标记流程步骤。Print a visual separator for a workflow step.
- 函数 `_stream_command_output`：Stream ``stdout``/``stderr`` until completion and return the exit code.
- 函数 `_run_remote_script`：Execute ``script`` on ``client`` using ``bash`` and report errors.
- 函数 `_run_remote_command`：Run a single command via Paramiko with unified error handling.
- 函数 `_init_deploy_log`：Create a timestamped deployment log inside ``artifacts``.
- 函数 `_set_ssh_context`：Record the SSH connection context for subsequent helper calls.
- 函数 `_require_ssh_context`：Return the active SSH context or raise an internal error.
- 函数 `_close_paramiko_client`：Close and reset the cached Paramiko client if it exists.
- 函数 `_load_paramiko_pkey`：Load an SSH private key compatible with Paramiko.
- 函数 `_ensure_paramiko_client`：Return a connected Paramiko SSH client, creating one if necessary.
- 函数 `_log_remote_output`：Log remote stdout/stderr content line-by-line.
- 函数 `_clean_known_host`：Remove stale host key fingerprints for ``ip`` prior to SSH attempts.
- 函数 `_monitor_deployment_progress`：在后台监控部署进度，定期检查远程脚本状态并显示进度信息
- 函数 `_ssh_run`：Execute ``command`` on the remote host via OpenSSH with Paramiko fallback.
- 函数 `_download_with_scp`：Download ``remote_path`` via ``scp`` if available.
- 函数 `_download_with_paramiko`：Download ``remote_path`` using Paramiko SFTP.
- 函数 `_download_artifact`：Download ``remote_path`` to ``local_path`` with scp fallback to SFTP.
- 函数 `_ensure_remote_artifact`：Ensure ``remote_path`` exists and is non-empty on the server.
- 函数 `deploy_wireguard_remote_script`：Return the shell script that configures WireGuard end-to-end on the server.
- 函数 `_wait_for_port_22`：Probe TCP/22 on ``ip`` every ``interval`` seconds until success or ``timeout`` seconds elapsed.
- 函数 `_wait_for_passwordless_ssh`：Attempt ``ssh root@ip true`` until passwordless login succeeds or timeout.
- 函数 `_print_manual_ssh_hint`：Display manual troubleshooting guidance for SSH key injection issues.
- 函数 `create_vps`：Create a Vultr VPS using environment-driven defaults.
- 函数 `inspect_vps_inventory`：Inspect existing Vultr instances and optionally destroy them.
- 函数 `_log_selected_platform`：无文档
- 函数 `_update_server_info`：更新服务器信息，支持多节点。Update server info, supporting multi-node.
- 函数 `_wireguard_windows_candidate_paths`：Return likely installation paths for WireGuard for Windows.
- 函数 `_locate_wireguard_windows_executable`：Locate the WireGuard for Windows executable if it exists.
- 函数 `_install_wireguard_windows_via_powershell`：Attempt to install WireGuard for Windows using PowerShell.
- 函数 `_ensure_wireguard_for_windows`：Ensure WireGuard for Windows is installed on the local machine.
- 函数 `_desktop_usage_tip`：无文档
- 函数 `manage_nodes`：管理多节点配置。Manage multi-node configuration.
- 函数 `check_nodes_health`：检查所有节点健康状态。Check all nodes health.
- 函数 `smart_node_selection`：智能节点选择。Smart node selection.
- 函数 `launch_gui`：打开可视化界面以操作各项功能。
- 函数 `_load_instance_for_diagnostics`：Return the Vultr instance IP recorded on disk, if any.
- 函数 `_diagnostic_ping`：Run a single ping against ``ip`` and report the outcome.
- 函数 `_diagnostic_port_22`：Attempt to establish a TCP connection to ``ip:22`` once.
- 函数 `_resolve_diagnostic_key_path`：Return a reasonable private-key path for diagnostic SSH probes.
- 函数 `_diagnostic_passwordless_ssh`：Attempt a single passwordless SSH probe with ``key_path``.
- 函数 `_run_network_diagnostics`：Run connectivity diagnostics against the recorded Vultr instance.
- 函数 `_check_vultr_instances`：检查Vultr账户中是否有实例，如果没有则提示创建。
- 函数 `run_environment_check`：无文档
- 函数 `wait_instance_ping`：Ping ``ip`` every ``interval`` seconds until reachable or timeout.
- 函数 `_resolve_env_default`：Return the first non-empty environment override and its key.
- 函数 `_default_private_key_prompt`：Return the default SSH private key path prompt for Step 3.
- 函数 `view_connection_report`：查看连接质量报告。View connection quality report.
- 函数 `view_parameter_recommendations`：查看参数调整建议。View parameter recommendations.
- 函数 `test_chatgpt_connection`：测试 ChatGPT 连接。Test ChatGPT connection.
- 函数 `_check_and_auto_configure_instances`：检查账户中的实例，返回已配置和未配置的实例列表。
- 函数 `_deploy_wireguard_to_instance`：为单个实例部署 WireGuard。
- 函数 `prepare_wireguard_access`：Configure WireGuard end-to-end, including client provisioning.
- 函数 `_print_main_menu`：Render the interactive menu in a consistent order.
- 函数 `main`：无文档

## portable_bundle\__main__.py
- 函数 `run`：Dispatch to :func:`portable_bundle.main.main`.

## portable_bundle\core\port_config.py
- 函数 `_parse_port`：无文档
- 函数 `resolve_listen_port`：Return the listen port and the environment variable that defined it.
- 函数 `get_default_wg_port`：Return the WireGuard listen port derived from environment variables.

## portable_bundle\core\project_overview.py
- 类 `MethodSummary`：表示类方法的概览信息。
- 类 `DefinitionSummary`：表示 Python 源文件中的定义信息。
- 函数 `_iter_python_files`：遍历 ``root`` 目录下的 Python 源文件。
- 函数 `_extract_doc`：提取 ``node`` 的文档字符串首行。
- 函数 `_summarize_class`：收集类及其方法的概要信息。
- 函数 `_summarize_module`：解析 ``path`` 并返回该模块中的定义信息。
- 函数 `generate_project_overview`：生成项目功能概览文档。

## portable_bundle\core\ssh_utils.py
- 类 `SSHKeyLoadError`：Raised when a private key cannot be parsed.
- 类 `SmartSSHError`：Raised when both Paramiko and ``ssh.exe`` backends fail.
  - 方法 `__init__`：无文档
- 类 `SSHAttempt`：Metadata about one backend attempt.
- 类 `SSHResult`：Return value for :func:`smart_ssh`.
- 类 `SSHProbeResult`：Outcome for :func:`probe_publickey_auth`.
- 函数 `_default_home`：无文档
- 函数 `_default_ssh_executable`：无文档
- 函数 `nuke_known_host`：Remove stale host-key fingerprints for ``ip`` from ``known_hosts``.
- 函数 `pick_default_key`：Return the preferred default private key path for Windows prompts.
- 函数 `ask_key_path`：Prompt for a private key path with validation suitable for Windows.
- 函数 `wait_port_open`：Poll ``host:port`` until it accepts TCP connections or ``timeout`` expires.
- 函数 `probe_publickey_auth`：Probe SSH public-key authentication until ``command`` succeeds.
- 函数 `_candidate_keys`：Yield supported Paramiko key classes in preferred order.
- 函数 `load_private_key`：Load a private key from ``path``.
- 函数 `run_ssh_script_via_stdin`：Send a multi-line shell script to the remote host via ``ssh`` stdin.
- 函数 `run_ssh_paramiko_script_via_stdin`：Send ``script_text`` via Paramiko, returning ``None`` if fallback is needed.
- 函数 `smart_push_script`：Push ``script_text`` via Paramiko first and fall back to ``ssh`` stdin.
- 函数 `run_ssh_paramiko`：Try executing ``command`` via Paramiko.
- 函数 `run_ssh_exe`：Execute ``command`` using the system ``ssh`` binary.
- 函数 `smart_ssh`：Execute ``command`` on ``host`` using either Paramiko or ``ssh.exe``.

## portable_bundle\core\tools\generate_wg_conf.py
- 函数 `parse_args`：Parse command-line arguments.
- 函数 `ensure_output_path`：Abort if *path* exists and overwriting is not allowed.
- 函数 `render_interface_section`：Render the ``[Interface]`` section based on client parameters.
- 函数 `render_peer_section`：Render the ``[Peer]`` section using endpoint and routing details.
- 函数 `render_configuration`：Convert the validated configuration dictionary into WireGuard text.
- 函数 `render_configuration_from_files`：Load and validate JSON files before rendering a WireGuard configuration.
- 函数 `main`：无文档

## portable_bundle\core\tools\generate_wg_conf_gui.py
- 类 `WireGuardGeneratorUI`：A lightweight GUI for invoking the configuration generator.
  - 方法 `__init__`：无文档
  - 方法 `_build_form`：无文档
  - 方法 `_browse_schema`：无文档
  - 方法 `_browse_input`：无文档
  - 方法 `_browse_output`：无文档
  - 方法 `_generate_configuration`：无文档
  - 方法 `_resolve_path`：无文档
  - 方法 `_append_log`：无文档
- 函数 `main`：无文档

## portable_bundle\core\tools\render_from_env.py
- 函数 `parse_args`：无文档
- 函数 `substitute_env`：Substitute ${VAR} placeholders using the process environment.
- 函数 `ensure_no_placeholders`：Abort if *text* still contains ${VAR} markers.
- 函数 `render`：无文档
- 函数 `main`：无文档

## portable_bundle\core\tools\validate_config.py
- 函数 `_require_jsonschema`：Import :mod:`jsonschema` and provide a helpful error if missing.
- 函数 `load_json_file`：Read a JSON file using UTF-8 encoding.
- 函数 `mask_sensitive`：Return a copy of *data* with secrets such as private keys masked.
- 函数 `validate_json`：Validate *document* against *schema* and exit with contextual errors.
- 函数 `parse_args`：Configure and parse command-line arguments.
- 函数 `main`：无文档

## portable_bundle\core\tools\vultr_manager.py
- 类 `VultrError`：Custom exception for Vultr API operations.
- 类 `IPv4HTTPAdapter`：无文档
  - 方法 `init_poolmanager`：无文档
  - 方法 `get_connection`：无文档
  - 方法 `_get_conn`：无文档
  - 方法 `proxy_manager_for`：无文档
  - 方法 `_prepare_conn`：无文档
- 函数 `_hdr`：Build request headers for Vultr API calls.
- 函数 `_session`：无文档
- 函数 `_friendly_error_message`：无文档
- 函数 `list_ssh_keys`：Return all SSH keys associated with the account.
- 函数 `list_instances`：Return all VPS instances associated with the account.
- 函数 `create_ssh_key`：Create a new SSH key in Vultr.
- 函数 `create_instance`：Create a Vultr instance and return the raw instance payload.
- 函数 `wait_instance_active`：Poll instance status until it becomes active and returns its IP.
- 函数 `destroy_instance`：Destroy a Vultr instance.
- 函数 `reinstall_with_ssh_keys`：Trigger ``Reinstall SSH Keys`` for an instance.

## portable_bundle\core\tools\wireguard_installer.py
- 类 `_CommandResult`：无文档
- 类 `WireGuardProvisionError`：Raised when provisioning fails.
- 函数 `_load_private_key`：无文档
- 函数 `_run`：无文档
- 函数 `_run_checked`：无文档
- 函数 `provision`：Provision WireGuard on a remote instance via SSH.

## portable_bundle\core\vultr_api.py
- 类 `VultrAPIError`：Raised when the Vultr API returns an unexpected response.
- 函数 `_headers`：无文档
- 函数 `_format_http_error`：无文档
- 函数 `_request`：无文档
- 函数 `_paginate`：无文档
- 函数 `ensure_ssh_key`：Ensure ``pubkey_text`` exists on Vultr and return its id.
- 函数 `_get_snapshot_info`：无文档
- 函数 `pick_snapshot`：Pick a snapshot ID based on ``snapshot_id_env`` or fall back to latest.
- 函数 `_get_plan_info`：无文档
- 函数 `_get_disk_size`：无文档
- 函数 `_check_snapshot_size`：无文档
- 函数 `create_instance`：Create an instance with optional snapshot and SSH keys.
- 函数 `reinstall_instance`：Trigger ``Reinstall SSH Keys`` for an instance.
- 函数 `wait_instance_ready`：Poll the Vultr API until the instance becomes active and running.
- 函数 `auto_create`：High-level helper that performs the whole creation flow.

## portable_bundle\legacy\server\split\resolve_domains.py
- 类 `ConfigError`：Raised when the YAML configuration cannot be parsed.
- 类 `DomainResult`：无文档
  - 方法 `merge`：无文档
- 函数 `parse_scalar`：无文档
- 函数 `determine_container`：无文档
- 函数 `simple_yaml_load`：无文档
- 函数 `load_config`：无文档
- 函数 `resolve_with_dig`：无文档
- 函数 `resolve_with_socket`：无文档
- 函数 `resolve_domain`：无文档
- 函数 `ensure_state_dir`：无文档
- 函数 `collapse_ipv4`：无文档
- 函数 `build_arg_parser`：无文档
- 函数 `extract_domains`：无文档
- 函数 `main`：无文档

## portable_bundle\legacy\server\toy-gateway\toy_tun_gateway.py
- 函数 `load_env`：无文档
- 函数 `parse_listen`：无文档
- 函数 `encode_frame`：无文档
- 函数 `parse_frame`：无文档
- 类 `ToyTunGateway`：无文档
  - 方法 `__init__`：无文档
  - 方法 `log`：无文档
  - 方法 `log_debug`：无文档
  - 方法 `start`：无文档
  - 方法 `stop`：无文档
  - 方法 `signal_stop`：无文档
  - 方法 `setup_udp_socket`：无文档
  - 方法 `setup_tun_device`：无文档
  - 方法 `on_udp_readable`：无文档
  - 方法 `on_tun_readable`：无文档
  - 方法 `handle_data_from_udp`：无文档
  - 方法 `forward_packet_to_clients`：无文档
  - 方法 `send_udp_frame`：无文档
  - 方法 `print_stats`：无文档
- 函数 `build_arg_parser`：无文档
- 函数 `resolve_options`：无文档
- 函数 `configure_logging`：无文档
- 函数 `main`：无文档

## portable_bundle\scripts\check_links.py
- 函数 `iter_markdown_files`：无文档
- 函数 `is_relative`：无文档
- 函数 `validate_file`：无文档
- 函数 `main`：无文档

## portable_bundle\scripts\project_doctor.py
- 类 `CheckResult`：无文档
- 函数 `check_python_version`：无文档
- 函数 `check_pip`：无文档
- 函数 `check_packages`：无文档
- 函数 `check_vultr_api_key`：无文档
- 函数 `ensure_artifacts_dir`：无文档
- 函数 `build_report`：无文档
- 函数 `parse_args`：无文档
- 函数 `check_selected_platform`：无文档
- 函数 `main`：无文档

## portable_bundle\scripts\prune_non_windows_only.py
- 函数 `iter_paths`：无文档
- 函数 `safe_move`：无文档
- 函数 `safe_delete`：无文档
- 函数 `rewrite_workflow_for_windows_only`：无文档
- 函数 `collect_archived_records`：无文档
- 函数 `main`：无文档

## portable_bundle\scripts\vultr_provision.py
- 类 `VultrAPIError`：Raised when Vultr's API returns an error response.
  - 方法 `__init__`：无文档
- 函数 `_api_request`：Perform a Vultr API call.
- 函数 `create_instance`：无文档
- 函数 `wait_for_instance_active`：Poll the instance until it becomes ``active`` or ``timeout`` expires.
- 函数 `wait_for_ssh`：Block until an SSH connection can be established.
- 函数 `sync_provision_directory`：Use ``rsync`` over SSH to copy ``server/provision`` to the instance.
- 函数 `parse_args`：无文档
- 函数 `main`：无文档

## portable_bundle\scripts\windows_oneclick.py
- 函数 `_prompt`：无文档
- 函数 `_read_pubkey`：无文档
- 函数 `_default_pubkey_path`：无文档
- 函数 `_prompt_private_key`：无文档
- 函数 `_artifacts_dir`：无文档
- 函数 `_known_hosts_path`：无文档
- 函数 `_reset_host_key`：无文档
- 函数 `_scp_download`：无文档
- 函数 `_ensure_local_qrcode`：无文档
- 函数 `_write_instance_artifact`：无文档
- 函数 `_record_server_info`：无文档
- 函数 `create_vps_flow`：无文档
- 函数 `_contains_permission_denied`：无文档
- 函数 `_diagnose_attempts`：无文档
- 函数 `_manual_console_instructions`：无文档
- 函数 `post_boot_verify_ssh`：无文档
- 函数 `deploy_wireguard`：无文档
- 函数 `main`：无文档

## scripts\check_links.py
- 函数 `iter_markdown_files`：无文档
- 函数 `is_relative`：无文档
- 函数 `validate_file`：无文档
- 函数 `main`：无文档

## scripts\node_health_monitor.py
- 函数 `main`：主函数。Main function.

## scripts\project_doctor.py
- 类 `CheckResult`：无文档
- 函数 `check_python_version`：无文档
- 函数 `check_pip`：无文档
- 函数 `check_packages`：无文档
- 函数 `check_vultr_api_key`：无文档
- 函数 `ensure_artifacts_dir`：无文档
- 函数 `build_report`：无文档
- 函数 `parse_args`：无文档
- 函数 `check_selected_platform`：无文档
- 函数 `main`：无文档

## scripts\prune_non_windows_only.py
- 函数 `iter_paths`：无文档
- 函数 `safe_move`：无文档
- 函数 `safe_delete`：无文档
- 函数 `rewrite_workflow_for_windows_only`：无文档
- 函数 `collect_archived_records`：无文档
- 函数 `main`：无文档

## scripts\run_tests.py
- 函数 `main`：主函数。Main function.

## scripts\vultr_provision.py
- 类 `VultrAPIError`：Raised when Vultr's API returns an error response.
  - 方法 `__init__`：无文档
- 函数 `_api_request`：Perform a Vultr API call.
- 函数 `create_instance`：无文档
- 函数 `wait_for_instance_active`：Poll the instance until it becomes ``active`` or ``timeout`` expires.
- 函数 `wait_for_ssh`：Block until an SSH connection can be established.
- 函数 `sync_provision_directory`：Use ``rsync`` over SSH to copy ``server/provision`` to the instance.
- 函数 `parse_args`：无文档
- 函数 `main`：无文档

## scripts\windows_oneclick.py
- 函数 `_prompt`：无文档
- 函数 `_read_pubkey`：无文档
- 函数 `_default_pubkey_path`：无文档
- 函数 `_prompt_private_key`：无文档
- 函数 `_artifacts_dir`：无文档
- 函数 `_known_hosts_path`：无文档
- 函数 `_reset_host_key`：无文档
- 函数 `_scp_download`：无文档
- 函数 `_ensure_local_qrcode`：无文档
- 函数 `_write_instance_artifact`：无文档
- 函数 `_record_server_info`：无文档
- 函数 `create_vps_flow`：无文档
- 函数 `_contains_permission_denied`：无文档
- 函数 `_diagnose_attempts`：无文档
- 函数 `_manual_console_instructions`：无文档
- 函数 `post_boot_verify_ssh`：无文档
- 函数 `deploy_wireguard`：无文档
- 函数 `main`：无文档

## tests\conftest.py
- 函数 `temp_dir`：临时目录 fixture。Temporary directory fixture.
- 函数 `sample_node`：示例节点 fixture。Sample node fixture.
- 函数 `sample_nodes`：示例节点列表 fixture。Sample nodes fixture.
- 函数 `multi_node_manager`：多节点管理器 fixture。Multi-node manager fixture.
- 函数 `node_health_checker`：节点健康检查器 fixture。Node health checker fixture.
- 函数 `sample_metrics`：示例连接指标 fixture。Sample connection metrics fixture.
- 函数 `sample_session`：示例连接会话 fixture。Sample connection session fixture.

## tests\test_adaptive_params.py
- 类 `TestAdaptiveParameterTuner`：自适应参数调整器测试类。Adaptive parameter tuner test class.
  - 方法 `test_initialization`：测试初始化。Test initialization.
  - 方法 `test_analyze_and_suggest`：测试分析和建议。Test analyze and suggest.
  - 方法 `test_parameter_set`：测试参数集合。Test parameter set.
  - 方法 `test_parameter_adjustment`：测试参数调整记录。Test parameter adjustment record.

## tests\test_chatgpt_optimizer.py
- 类 `TestChatGPTOptimizer`：ChatGPT 优化器测试类。ChatGPT optimizer test class.
  - 方法 `test_initialization`：测试初始化。Test initialization.
  - 方法 `test_resolve_chatgpt_domains`：测试解析 ChatGPT 域名。Test resolving ChatGPT domains.
  - 方法 `test_test_chatgpt_connectivity`：测试 ChatGPT 连接性。Test ChatGPT connectivity.

## tests\test_connection_monitor.py
- 类 `TestConnectionMonitor`：连接监控测试类。Connection monitor test class.
  - 方法 `test_monitor_initialization`：测试监控器初始化。Test monitor initialization.
  - 方法 `test_start_stop_monitoring`：测试启动和停止监控。Test starting and stopping monitoring.
  - 方法 `test_generate_report`：测试生成报告。Test generating report.
  - 方法 `test_get_current_stats`：测试获取当前统计。Test getting current stats.

## tests\test_integration.py
- 类 `TestIntegration`：集成测试类。Integration test class.
  - 方法 `test_full_workflow`：测试完整工作流程。Test full workflow.
  - 方法 `test_node_failover`：测试节点故障转移。Test node failover.

## tests\test_multi_node_manager.py
- 类 `TestMultiNodeManager`：多节点管理器测试类。Multi-node manager test class.
  - 方法 `test_add_node`：测试添加节点。Test adding node.
  - 方法 `test_get_all_nodes`：测试获取所有节点。Test getting all nodes.
  - 方法 `test_find_best_node`：测试查找最佳节点。Test finding best node.
  - 方法 `test_switch_to_backup_node`：测试切换到备用节点。Test switching to backup node.
  - 方法 `test_update_node_status`：测试更新节点状态。Test updating node status.
  - 方法 `test_get_active_nodes`：测试获取活跃节点。Test getting active nodes.

## tests\test_node_health_checker.py
- 类 `TestNodeHealthChecker`：节点健康检查器测试类。Node health checker test class.
  - 方法 `test_check_tcp`：测试 TCP 连接检查。Test TCP connection check.
  - 方法 `test_check_https`：测试 HTTPS 连接检查。Test HTTPS connection check.
  - 方法 `test_check_dns`：测试 DNS 解析检查。Test DNS resolution check.
  - 方法 `test_check_node`：测试完整节点检查。Test complete node check.
  - 方法 `test_health_check_metrics`：测试健康检查指标。Test health check metrics.

## tests\test_proxy_integration.py
- 类 `TestProxyIntegration`：代理功能集成测试。Integration tests for proxy.
  - 方法 `test_proxy_config_with_env_var`：测试通过环境变量配置代理。Test proxy configuration via environment variable.
  - 方法 `test_proxy_config_without_env_var`：测试未配置代理时的行为。Test behavior without proxy configuration.
  - 方法 `test_proxy_priority`：测试代理优先级。Test proxy priority.
  - 方法 `test_detect_local_proxy_no_service`：测试无代理服务时的检测。Test detection when no proxy service is running.
  - 方法 `test_auto_configure_proxy_no_env`：测试自动配置代理（不设置环境变量）。Test auto-configure without setting env.
  - 方法 `test_log_proxy_status`：测试代理状态日志。Test proxy status logging.

## tests\test_proxy_utils.py
- 类 `TestGetProxyConfig`：测试 get_proxy_config() 函数。
  - 方法 `test_all_proxy_uppercase`：测试 ALL_PROXY 环境变量（大写）。
  - 方法 `test_all_proxy_lowercase`：测试 all_proxy 环境变量（小写）。
  - 方法 `test_https_proxy`：测试 HTTPS_PROXY 环境变量。
  - 方法 `test_http_proxy`：测试 HTTP_PROXY 环境变量。
  - 方法 `test_priority_all_proxy_over_http_proxy`：测试优先级：ALL_PROXY 优先于 HTTP_PROXY。
  - 方法 `test_priority_https_proxy_over_http_proxy`：测试优先级：HTTPS_PROXY 优先于 HTTP_PROXY。
  - 方法 `test_no_proxy_configured`：测试未配置代理时返回 None。
  - 方法 `test_empty_string_proxy`：测试空字符串处理。
  - 方法 `test_whitespace_only_proxy`：测试仅包含空白字符的环境变量。
  - 方法 `test_auto_add_http_prefix`：测试自动添加 http:// 协议前缀。
  - 方法 `test_socks5_proxy`：测试 SOCKS5 代理协议。
  - 方法 `test_socks4_proxy`：测试 SOCKS4 代理协议。
  - 方法 `test_https_protocol_proxy`：测试 https:// 协议前缀。
  - 方法 `test_case_insensitive_env_vars`：测试环境变量名大小写不敏感。
- 类 `TestGetProxyForUrllib`：测试 get_proxy_for_urllib() 函数。
  - 方法 `test_returns_same_as_get_proxy_config`：测试返回格式与 get_proxy_config() 相同。
  - 方法 `test_returns_none_when_no_proxy`：测试未配置代理时返回 None。
- 类 `TestIsProxyConfigured`：测试 is_proxy_configured() 函数。
  - 方法 `test_returns_true_when_all_proxy_set`：测试配置了 ALL_PROXY 时返回 True。
  - 方法 `test_returns_true_when_https_proxy_set`：测试配置了 HTTPS_PROXY 时返回 True。
  - 方法 `test_returns_true_when_http_proxy_set`：测试配置了 HTTP_PROXY 时返回 True。
  - 方法 `test_returns_false_when_no_proxy`：测试未配置代理时返回 False。
  - 方法 `test_returns_false_when_empty_string`：测试环境变量为空字符串时返回 False。
  - 方法 `test_returns_false_when_whitespace_only`：测试环境变量仅包含空白字符时返回 False。
  - 方法 `test_case_insensitive`：测试大小写不敏感。
- 类 `TestLogProxyStatus`：测试 log_proxy_status() 函数。
  - 方法 `test_logs_proxy_when_configured`：测试配置了代理时记录代理信息。
  - 方法 `test_logs_no_proxy_when_not_configured`：测试未配置代理时记录未配置信息。
  - 方法 `test_logs_with_custom_logger`：测试使用自定义 logger。
  - 方法 `test_logs_https_proxy_source`：测试记录 HTTPS_PROXY 来源。
  - 方法 `test_logs_http_proxy_source`：测试记录 HTTP_PROXY 来源。

## tests\test_smart_routing.py
- 类 `TestSmartRouter`：智能选路测试类。Smart routing test class.
  - 方法 `test_calculate_node_score`：测试节点评分计算。Test node score calculation.
  - 方法 `test_select_best_node`：测试选择最佳节点。Test selecting best node.
  - 方法 `test_different_strategies`：测试不同选路策略。Test different routing strategies.
  - 方法 `test_node_score_calculation`：测试节点评分计算逻辑。Test node score calculation logic.

## tests\test_utils.py
- 函数 `load_test_data`：加载测试数据。Load test data.
- 函数 `create_mock_node`：创建模拟节点。Create mock node.

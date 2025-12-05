# 项目功能概览

自动生成时间：2025-12-05 23:25:23

## artifacts\tools\networkCheck.py
- 函数 `check_instance_status`：检查远程实例是否还在运行

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

## core\tools\render_from_env.py
- 函数 `parse_args`：无文档
- 函数 `substitute_env`：Substitute ${VAR} placeholders using the process environment.
- 函数 `ensure_no_placeholders`：Abort if *text* still contains ${VAR} markers.
- 函数 `render`：无文档
- 函数 `main`：无文档

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
- 函数 `_update_server_info`：无文档
- 函数 `_wireguard_windows_candidate_paths`：Return likely installation paths for WireGuard for Windows.
- 函数 `_locate_wireguard_windows_executable`：Locate the WireGuard for Windows executable if it exists.
- 函数 `_install_wireguard_windows_via_powershell`：Attempt to install WireGuard for Windows using PowerShell.
- 函数 `_ensure_wireguard_for_windows`：Ensure WireGuard for Windows is installed on the local machine.
- 函数 `_desktop_usage_tip`：无文档
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

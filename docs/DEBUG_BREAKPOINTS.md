# Debug Breakpoint Guide for `main.py`

The `main.py` entrypoint drives all user-facing flows. When you execute the
`main()` method, use the following breakpoints to trace the control path and
inspect state.

## Menu Loop (`main.py`)

| Location | Why to break |
| --- | --- |
| `main.py:L668` (`main()` before reading `choice`) | Inspect the rendered menu and confirm what `input()` returns. Useful when menu choices behave unexpectedly. |
| `main.py:L676-L683` (branching on `choice`) | Step into the selected workflow (`run_doctor`, `create_vps`, `deploy_wireguard`, `run_prune`). |

## Vultr Provisioning (`create_vps` in `main.py`)

| Location | Why to break |
| --- | --- |
| `main.py:L198-L215` | Verify environment variables (`VULTR_API_KEY`, `VULTR_REGION`, etc.) and user input fallbacks. |
| `main.py:L255-L263` | Inspect `list_ssh_keys` results to ensure the account contains the expected SSH keys. |
| `main.py:L266-L287` | Confirm the user selection logic chooses the intended SSH key. |
| `main.py:L297-L319` | Check the `create_instance` response, watch `wait_instance_active`, and inspect the resolved public IP. |
| `main.py:L320-L333` | Examine the error handling path when provisioning fails (including cleanup via `destroy_instance`). |
| `main.py:L334-L352` | Validate the contents written to `artifacts/instance.json` before they are consumed by later steps. |

Supporting functions worth instrumenting:

| Function | Suggested breakpoint |
| --- | --- |
| `_stream_command_output` (`main.py:L62-L113`) | Pause inside the receive loop to inspect raw Paramiko output when remote commands misbehave. |
| `_run_remote_script` (`main.py:L116-L140`) | Break before returning to capture `exit_code`, `stdout_data`, and `stderr_data`. |
| `_run_remote_command` (`main.py:L142-L164`) | Similar to above for single-command executions. |
| `_download_file` (`main.py:L167-L183`) | Verify SFTP transfers and path creation. |
| `wait_instance_ping` (`main.py:L378-L411`) | Inspect each ping attempt and captured stdout/stderr when the instance never becomes reachable. |

## WireGuard Deployment (`deploy_wireguard` in `main.py`)

| Location | Why to break |
| --- | --- |
| `main.py:L417-L428` | Confirm the previously saved `artifacts/instance.json` is readable and parseable. |
| `main.py:L430-L447` | Watch the extracted IP/instance metadata and port readiness checks. |
| `main.py:L449-L486` | Debug SSH public-key probing and the optional `reinstall_with_ssh_keys` recovery path. |
| `main.py:L489-L505` | Examine Paramiko connection parameters and failures when establishing SSH. |
| `main.py:L508-L576` | Step through each installation script in `setup_steps` to identify which remote stage fails. |
| `main.py:L578-L625` | Verify service validation and client configuration generation commands. |
| `main.py:L626-L639` | Confirm SFTP downloads (QR code and client config) succeed and land in `artifacts/`. |
| `main.py:L641-L660` | Inspect the metadata written to `artifacts/server.json` (including `server_pub`). |

## Health & Prune Utilities (`run_doctor` / `run_prune`)

| Location | Why to break |
| --- | --- |
| `main.py:L355-L360` | Inspect the exit code of `scripts/project_doctor.py` when the health check fails. |
| `main.py:L363-L368` | Inspect the exit code of `scripts/prune_non_windows_only.py` when pruning fails. |

# SSH Helper Breakpoints (`core/ssh_utils.py`)

| Function | Key lines | Why to break |
| --- | --- | --- |
| `ask_key_path` | `core/ssh_utils.py:L126-L145` | Validate user-supplied private key paths when prompts keep rejecting input. |
| `pick_default_key` | `core/ssh_utils.py:L112-L123` | Confirm which default key path is offered on Windows systems. |
| `wait_port_open` | `core/ssh_utils.py:L148-L158` | Observe retry timing when port 22 never opens. |
| `probe_publickey_auth` | `core/ssh_utils.py:L161-L226` | Inspect the assembled SSH command, stdout/stderr, and retry counters to diagnose auth failures. |
| `run_ssh_paramiko_script_via_stdin` | `core/ssh_utils.py:L300-L357` | Determine why Paramiko uploads fail before falling back to `ssh.exe`. |
| `run_ssh_script_via_stdin` / `smart_push_script` | `core/ssh_utils.py:L269-L378` | Debug fallback execution and remote exit codes when scripts misbehave. |
| `run_ssh_paramiko` | `core/ssh_utils.py:L381+` | Inspect direct command execution attempts that precede `SmartSSHError`. |
| `nuke_known_host` | `core/ssh_utils.py:L78-L109` | Verify known-host cleanup runs when host key mismatches persist. |

# Vultr API Helpers (`core/tools/vultr_manager.py`)

| Function | Key lines | Why to break |
| --- | --- | --- |
| `_session` / `_hdr` | `core/tools/vultr_manager.py:L41-L55` | Confirm the API key is injected and IPv4-only adapter is applied when needed. |
| `_friendly_error_message` | `core/tools/vultr_manager.py:L58-L70` | Inspect generated messages for HTTP errors surfaced in the UI. |
| `list_ssh_keys` | `core/tools/vultr_manager.py:L73-L96` | Debug pagination or authentication problems when no keys are returned. |
| `create_instance` | `core/tools/vultr_manager.py:L113-L159` | Inspect the request payload and server response when provisioning fails. |
| `wait_instance_active` | `core/tools/vultr_manager.py:L162-L194` | Monitor polling state and the final payload that provides the public IP. |
| `destroy_instance` | `core/tools/vultr_manager.py:L197-L211` | Ensure cleanup requests succeed after failed provisioning. |
| `reinstall_with_ssh_keys` | `core/tools/vultr_manager.py:L214-L242` | Debug the recovery path that re-injects SSH keys when public-key auth fails. |

# How to Use This Guide

1. Start from the `main()` loop and set the relevant breakpoint for the menu option
   you plan to exercise.
2. Step into the selected workflow and place the suggested breakpoints in the
   downstream helpers before re-running the scenario. This keeps call stacks
   aligned with the runtime path you are investigating.
3. When remote operations fail, capture both the helper-level state (e.g.,
   `_run_remote_script` exit codes) and the underlying Paramiko/requests
   responses to isolate whether the issue originates locally or on the VPS.

Following this sequence ensures that every significant branch after invoking the
entrypoint is observable in the debugger.

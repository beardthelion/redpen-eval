# Source: https://github.com/anthropics/claude-agent-sdk-python
# Ref: 347a1cb88d7652199399db1b7f914e0a459a6662 Path: src/claude_agent_sdk/_internal/transport/subprocess_cli.py
# Excerpted and modified from https://github.com/anthropics/claude-agent-sdk-python@347a1cb88d7652199399db1b7f914e0a459a6662 on 2026-10-20
# License: MIT, see licenses/anthropics__claude-agent-sdk-python/LICENSE
# Copyright (c) 2025 Anthropic, PBC
    def _build_command(self) -> list[str]:
        """Build CLI command with arguments."""
        if self._cli_path is None:
            raise CLINotFoundError("CLI path not resolved. Call connect() first.")
        cmd = [self._cli_path, "--output-format", "stream-json", "--verbose"]

        if self._options.system_prompt is None:
            cmd.extend(["--system-prompt", ""])
        elif isinstance(self._options.system_prompt, str):
            cmd.extend(["--system-prompt", self._options.system_prompt])
        else:
            sp = self._options.system_prompt
            if sp.get("type") == "file":
                cmd.extend(["--system-prompt-file", cast(SystemPromptFile, sp)["path"]])
            elif sp.get("type") == "preset" and "append" in sp:
                cmd.extend(
                    ["--append-system-prompt", cast(SystemPromptPreset, sp)["append"]]
                )

        # Handle tools option (base set of tools)
        if self._options.tools is not None:
            tools = self._options.tools
            if isinstance(tools, list):
                if len(tools) == 0:
                    cmd.extend(["--tools", ""])
                else:
                    cmd.extend(["--tools", ",".join(tools)])
            else:
                # Preset object - 'claude_code' preset maps to 'default'
                cmd.extend(["--tools", "default"])

        effective_allowed_tools, effective_setting_sources = (
            self._apply_skills_defaults()
        )

        if effective_allowed_tools:
            cmd.extend(["--allowedTools", ",".join(effective_allowed_tools)])

        if self._options.max_turns:
            cmd.extend(["--max-turns", str(self._options.max_turns)])

        if self._options.max_budget_usd is not None:
            cmd.extend(["--max-budget-usd", str(self._options.max_budget_usd)])

        if self._options.disallowed_tools:
            cmd.extend(["--disallowedTools", ",".join(self._options.disallowed_tools)])

        if self._options.task_budget is not None:
            cmd.extend(["--task-budget", str(self._options.task_budget["total"])])

        if self._options.model:
            cmd.extend(["--model", self._options.model])

        if self._options.fallback_model:
            cmd.extend(["--fallback-model", self._options.fallback_model])

        if self._options.betas:
            cmd.extend(["--betas", ",".join(self._options.betas)])

        if self._options.permission_prompt_tool_name:
            cmd.extend(
                ["--permission-prompt-tool", self._options.permission_prompt_tool_name]
            )

        if self._options.permission_mode:
            cmd.extend(["--permission-mode", self._options.permission_mode])

        if self._options.continue_conversation:
            cmd.append("--continue")

        # Pass these as --flag=value rather than as two argv tokens. The CLI
        # declares --resume with an optional value, so in the two-token form a
        # dash-leading value is not bound to the flag and is instead parsed as
        # a separate CLI flag -- letting an untrusted value inject arbitrary
        # flags. The equals form always binds the value to the flag.
        if self._options.resume:
            cmd.append(f"--resume={self._options.resume}")

        if self._options.session_id:
            cmd.append(f"--session-id={self._options.session_id}")

        # Handle settings and sandbox: merge sandbox into settings if both are provided
        settings_value = self._build_settings_value()
        if settings_value:
            cmd.extend(["--settings", settings_value])

        if self._options.add_dirs:
            # Convert all paths to strings and add each directory
            for directory in self._options.add_dirs:
                cmd.extend(["--add-dir", str(directory)])

        if self._options.mcp_servers:
            if isinstance(self._options.mcp_servers, dict):
                # Process all servers, stripping instance field from SDK servers
                servers_for_cli: dict[str, Any] = {}
                for name, config in self._options.mcp_servers.items():
                    if isinstance(config, dict) and config.get("type") == "sdk":
                        # For SDK servers, pass everything except the instance field
                        sdk_config: dict[str, object] = {
                            k: v for k, v in config.items() if k != "instance"
                        }
                        servers_for_cli[name] = sdk_config
                    else:
                        # For external servers, pass as-is
                        servers_for_cli[name] = config

                # Pass all servers to CLI
                if servers_for_cli:
                    cmd.extend(
                        [
                            "--mcp-config",
                            json.dumps({"mcpServers": servers_for_cli}),
                        ]
                    )
            else:
                # String or Path format: pass directly as file path or JSON string
                cmd.extend(["--mcp-config", str(self._options.mcp_servers)])

        if self._options.include_partial_messages:
            cmd.append("--include-partial-messages")

        if self._options.include_hook_events:
            cmd.append("--include-hook-events")

        if self._options.strict_mcp_config:
            cmd.append("--strict-mcp-config")

        if self._options.fork_session:
            cmd.append("--fork-session")

        if self._options.session_store is not None:
            cmd.append("--session-mirror")

        # Agents are always sent via initialize request (matching TypeScript SDK)
        # No --agents CLI flag needed

        if effective_setting_sources is not None:
            cmd.append(f"--setting-sources={','.join(effective_setting_sources)}")

        # Add plugin directories
        if self._options.plugins:
            for plugin in self._options.plugins:
                if plugin["type"] == "local":
                    cmd.extend(["--plugin-dir", plugin["path"]])
                else:
                    raise ValueError(f"Unsupported plugin type: {plugin['type']}")

        # Add extra args for future CLI flags
        for flag, value in self._options.extra_args.items():
            if value is None:
                # Boolean flag without value
                cmd.append(f"--{flag}")
            else:
                # Flag with value
                cmd.extend([f"--{flag}", str(value)])

        # Resolve thinking config -> --thinking / --max-thinking-tokens
        # `thinking` takes precedence over the deprecated `max_thinking_tokens`
        if self._options.thinking is not None:
            t = self._options.thinking
            if t["type"] == "adaptive":
                cmd.extend(["--thinking", "adaptive"])
            elif t["type"] == "enabled":
                cmd.extend(["--max-thinking-tokens", str(t["budget_tokens"])])
            elif t["type"] == "disabled":
                cmd.extend(["--thinking", "disabled"])

            # Narrow off the Disabled variant first so mypy knows `t["display"]` is a str
            # rather than widening to `object` across the union.
            if t["type"] != "disabled" and "display" in t:
                cmd.extend(["--thinking-display", t["display"]])
        elif self._options.max_thinking_tokens is not None:
            cmd.extend(
                ["--max-thinking-tokens", str(self._options.max_thinking_tokens)]
            )

        if self._options.effort is not None:
            cmd.extend(["--effort", self._options.effort])

        # Extract schema from output_format structure if provided
        # Expected: {"type": "json_schema", "schema": {...}}
        if (
            self._options.output_format is not None
            and isinstance(self._options.output_format, dict)
            and self._options.output_format.get("type") == "json_schema"
        ):
            schema = self._options.output_format.get("schema")
            if schema is not None:
                cmd.extend(["--json-schema", json.dumps(schema)])

        # Always use streaming mode with stdin (matching TypeScript SDK)
        # This allows agents and other large configs to be sent via initialize request
        cmd.extend(["--input-format", "stream-json"])

        return cmd

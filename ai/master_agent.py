"""Master AI Agent - The brain of PEN-AI that orchestrates the entire engagement."""

import asyncio
import json
from typing import Any, Optional

from ai.planner import Planner, CandidateAction
from ai.reasoner import Reasoner, Hypothesis
from ai.memory import AIMemory
from ai.tool_registry import ToolRegistry, registry, ToolCategory
from ai.llm_client import LLMClient, Message, MessageRole, ToolCall
from core.state.engagement_state import EngagementState, AccessLevel
from core.scope.rules import RulesOfEngagement, ScopeValidator
from core.events.models import Event, EventType, EventChain


SYSTEM_PROMPT = """You are PEN-AI, an AI-powered adaptive penetration testing operator.

## Your Role
You operate within an authorized penetration testing environment.
Your goal is to discover vulnerabilities, gain access, escalate privileges, and complete objectives.

## Core Principles
1. **Observe** the environment before acting
2. **Build state** from observations
3. **Generate hypotheses** about attack paths
4. **Plan actions** based on information gain and risk
5. **Execute tools** to gather evidence
6. **Learn** from successes and failures
7. **Replan** based on new information

## Decision Framework
For each cycle, consider:
- What information do we have?
- What are the most promising attack vectors?
- Which action provides the highest information gain?
- What are the risks of each action?
- Have we tried this before? Did it fail?

## Scope Rules
- ONLY operate within the authorized target scope
- NEVER attack systems outside the defined ROE
- Capture evidence for all findings
- Document everything for the final report

## Available Tools
You have access to tools for:
- Network reconnaissance (nmap, scanning)
- Service enumeration
- Active Directory attacks
- Web application testing
- Binary exploitation
- IoT analysis
- CTF challenges
- Post-exploitation
- Pivoting
- Evidence collection

## Response Format
When deciding on an action:
1. First, analyze the current state
2. List your hypotheses
3. Evaluate candidate actions
4. Select the best action with reasoning
5. Call the appropriate tool

Always explain your reasoning before selecting a tool."""


class MasterAgent:
    """The master AI agent that orchestrates PEN-AI's engagement."""

    def __init__(
        self,
        state: EngagementState,
        roe: RulesOfEngagement,
        tool_registry: Optional[ToolRegistry] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        self.state = state
        self.roe = roe
        self.validator = ScopeValidator(roe)
        self.registry = tool_registry or registry

        # AI components
        self.planner = Planner()
        self.reasoner = Reasoner()
        self.memory = AIMemory()
        self.llm = llm_client

        # Event tracking
        self._event_chain = EventChain()
        self._running = False
        self._cycle_count = 0

    async def start(self) -> None:
        """Start the agent's main loop."""
        self._running = True
        self._record_event(
            EventType.AGENT_STARTED,
            "Master agent started",
        )

        # Set system prompt on LLM
        if self.llm:
            self.llm.set_system_prompt(SYSTEM_PROMPT)

        print("[bold green]PEN-AI Agent Started[/bold green]")
        print(f"Target scope: {self.roe.allowed_networks}")
        print(f"Max pivots: {self.roe.max_pivots}")
        if self.llm:
            print(f"LLM Model: {self.llm.model}")

    async def stop(self) -> None:
        """Stop the agent."""
        self._running = False
        self._record_event(
            EventType.AGENT_STOPPED,
            "Master agent stopped",
        )
        print("[bold red]PEN-AI Agent Stopped[/bold red]")

    async def run_cycle(self) -> Optional[CandidateAction]:
        """Execute one reasoning cycle using LLM."""
        if not self._running:
            return None

        self._cycle_count += 1
        print(f"\n[bold cyan]â•â•â• Reasoning Cycle {self._cycle_count} â•â•â•[/bold cyan]")

        # Step 1: OBSERVE - Build current state summary
        print("[yellow]1. Observing state...[/yellow]")
        state_summary = self._build_state_summary()
        self.reasoner.observe(state_summary)

        # Step 2: HYPOTHESIZE
        print("[yellow]2. Generating hypotheses...[/yellow]")
        hypotheses = self.reasoner.hypothesize(self.state, self.memory)
        hypotheses_text = self._format_hypotheses(hypotheses)

        # Step 3: PLAN - Get candidate actions
        print("[yellow]3. Planning actions...[/yellow]")
        tools = self.registry.list_names()
        actions = self.planner.generate_actions(self.state, self.memory, tools)
        actions_text = self._format_actions(actions)

        # Step 4: LLM REASONING - Ask LLM to decide
        print("[yellow]4. Asking LLM to decide...[/yellow]")
        selected = await self._llm_decide(
            state_summary=state_summary,
            hypotheses=hypotheses_text,
            actions=actions_text,
            available_tools=tools,
        )

        if selected is None:
            print("[dim]LLM did not select an action[/dim]")
            return None

        print(f"   [green]Selected: {selected.name}[/green]")
        print(f"   [dim]Reasoning: {selected.reasoning}[/dim]")

        # Step 5: EXECUTE
        print("[yellow]5. Executing tool...[/yellow]")
        result = await self._execute_action(selected)

        # Step 6: ANALYZE RESULT
        print("[yellow]6. Analyzing result...[/yellow]")
        await self._analyze_result(selected, result)

        # Step 7: UPDATE STATE
        print("[yellow]7. Updating state...[/yellow]")
        self._update_state_from_result(selected, result)

        # Step 8: RECORD
        self.planner.record_action(selected)

        print("[bold cyan]â•â•â• Cycle Complete â•â•â•[/bold cyan]")
        return selected

    async def _llm_decide(
        self,
        state_summary: str,
        hypotheses: str,
        actions: str,
        available_tools: list[str],
    ) -> Optional[CandidateAction]:
        """Use LLM to decide the next action."""
        if not self.llm:
            # Fallback to planner if no LLM
            tools = self.registry.list_names()
            actions = self.planner.generate_actions(self.state, self.memory, tools)
            return actions[0] if actions else None

        # Get tool schemas for function calling
        tool_schemas = self.registry.get_schemas()

        # Ask LLM to decide
        response = await self.llm.decide_action(
            state_summary=state_summary,
            hypotheses=hypotheses,
            available_actions=actions,
            tools=tool_schemas,
        )

        # Process response
        if response.tool_calls:
            # LLM selected a tool
            tool_call = response.tool_calls[0]
            return self._parse_tool_call(tool_call)
        elif response.content:
            # LLM provided text response - try to parse action
            return self._parse_text_response(response.content)
        else:
            return None

    def _parse_tool_call(self, tool_call: ToolCall) -> CandidateAction:
        """Parse a tool call from LLM into a CandidateAction."""
        # Find matching action from planner
        tools = self.registry.list_names()
        actions = self.planner.generate_actions(self.state, self.memory, tools)

        # Try to match tool name
        for action in actions:
            if action.tool_name == tool_call.name:
                action.parameters = tool_call.arguments
                action.reasoning = f"LLM selected tool: {tool_call.name}"
                return action

        # Create new action from tool call
        return CandidateAction(
            name=tool_call.name,
            action_type="recon",  # Default
            description=f"LLM-selected action: {tool_call.name}",
            tool_name=tool_call.name,
            parameters=tool_call.arguments,
            reasoning=f"LLM selected tool: {tool_call.name}",
        )

    def _parse_text_response(self, text: str) -> Optional[CandidateAction]:
        """Parse a text response from LLM into a CandidateAction."""
        # Try to extract tool name from text
        text_lower = text.lower()

        # Common tool patterns
        tool_patterns = {
            "nmap_host_scan": ["host discovery", "scan hosts", "discover hosts"],
            "nmap_service_scan": ["service scan", "enumerate services", "port scan"],
            "ad_enumerate": ["active directory", "ad enumerate", "ldap"],
            "web_enumerate": ["web scan", "web enumerate", "http"],
            "binary_analyze": ["binary analysis", "analyze binary"],
            "ctf_linux_enum": ["linux enum", "linux enumeration"],
        }

        for tool_name, patterns in tool_patterns.items():
            for pattern in patterns:
                if pattern in text_lower:
                    tools = self.registry.list_names()
                    actions = self.planner.generate_actions(self.state, self.memory, tools)
                    for action in actions:
                        if action.tool_name == tool_name:
                            action.reasoning = text[:200]
                            return action

        return None

    def _build_state_summary(self) -> str:
        """Build a comprehensive state summary for LLM."""
        summary = f"""## Current Engagement State

### Network
- Hosts Discovered: {self.state.hosts_discovered}
- Services Found: {self.state.services_discovered}
- Networks: {len(self.state.networks)}

### Access
- Current Access Level: {self.state.current_access.value}
- Pivot Depth: {self.state.pivot_depth}/{self.state.max_pivot_depth}

### Findings
- Vulnerabilities: {self.state.vulnerabilities_found}
- Credentials: {self.state.credentials_found}
- Objectives Completed: {self.state.objectives_completed}/{len(self.state.objectives)}

### History
- Hosts Visited: {len(self.state.visited_hosts)}
- Failed Actions: {len(self.state.failed_actions)}
"""

        # Add discovered hosts
        if self.state.hosts:
            summary += "\n### Discovered Hosts\n"
            for host in self.state.hosts[:10]:
                summary += f"- {host.ip} ({host.os or 'unknown OS'})\n"

        # Add credentials
        if self.state.credentials:
            summary += "\n### Discovered Credentials\n"
            for cred in self.state.credentials:
                summary += f"- {cred.username}@{cred.target}\n"

        # Add vulnerabilities
        if self.state.vulnerabilities:
            summary += "\n### Discovered Vulnerabilities\n"
            for vuln in self.state.vulnerabilities[:5]:
                summary += f"- {vuln.title} ({vuln.severity})\n"

        # Add recent failures
        if self.state.failed_actions:
            summary += "\n### Recent Failures (avoid repeating)\n"
            for failure in self.state.failed_actions[-3:]:
                summary += f"- {failure['action']}: {failure['reason']}\n"

        return summary

    def _format_hypotheses(self, hypotheses: list[Hypothesis]) -> str:
        """Format hypotheses for LLM."""
        if not hypotheses:
            return "No active hypotheses."

        lines = ["## Active Hypotheses\n"]
        for i, h in enumerate(hypotheses[:5], 1):
            lines.append(f"{i}. [{h.confidence.value}] {h.statement}")
            if h.suggested_actions:
                lines.append(f"   Suggested: {', '.join(h.suggested_actions)}")

        return "\n".join(lines)

    def _format_actions(self, actions: list[CandidateAction]) -> str:
        """Format actions for LLM."""
        if not actions:
            return "No candidate actions."

        lines = ["## Candidate Actions\n"]
        for i, action in enumerate(actions[:10], 1):
            lines.append(
                f"{i}. **{action.name}** (Priority: {action.priority.value}, "
                f"Score: {action.score:.2f})"
            )
            lines.append(f"   Tool: {action.tool_name or 'N/A'}")
            lines.append(f"   Reasoning: {action.reasoning}")

        return "\n".join(lines)

    async def _execute_action(self, action: CandidateAction) -> dict[str, Any]:
        """Execute an action using the appropriate tool."""
        if not action.tool_name:
            return {"error": "No tool specified"}

        tool = self.registry.get(action.tool_name)
        if not tool:
            return {"error": f"Tool '{action.tool_name}' not found"}

        # Record the tool call event
        self._record_event(
            EventType.TOOL_CALLED,
            f"Calling tool: {action.tool_name}",
            tool=action.tool_name,
            action=action.name,
        )

        # Execute
        result = await self.registry.execute(action.tool_name, **action.parameters)

        # Record result
        event_type = EventType.TOOL_COMPLETED if result.get("success") else EventType.TOOL_FAILED
        self._record_event(
            event_type,
            f"Tool {action.tool_name} completed",
            tool=action.tool_name,
            action=action.name,
        )

        return result

    async def _analyze_result(self, action: CandidateAction, result: dict[str, Any]) -> None:
        """Analyze action result using LLM."""
        if not self.llm:
            return

        try:
            response = await self.llm.analyze_result(
                action=f"{action.name}: {action.description}",
                result=json.dumps(result, indent=2, default=str),
                state_summary=self._build_state_summary(),
            )

            if response.content:
                # Update memory with analysis
                self.memory.short_term.add(
                    f"Analysis of {action.name}: {response.content[:500]}",
                    category="analysis",
                    importance=0.7,
                )
        except Exception as e:
            print(f"[dim]Analysis error: {e}[/dim]")

    def _update_state_from_result(self, action: CandidateAction, result: dict[str, Any]) -> None:
        """Update engagement state based on action result."""
        if result.get("success"):
            self.memory.engagement.add_discovery(
                f"Action {action.name} completed successfully"
            )

            # Parse result to update state
            self._parse_result_to_state(action, result)
        else:
            self.memory.engagement.add_failure(
                f"Action {action.name} failed: {result.get('error', 'unknown')}"
            )
            self.state.record_failure(action.name, result.get("error", "unknown"))

    def _parse_result_to_state(self, action: CandidateAction, result: dict[str, Any]) -> None:
        """Parse action result and update state."""
        # This is a simplified version - full implementation would parse each tool's output

        if action.tool_name == "nmap_host_scan":
            # Parse host discovery results
            if "hosts" in result:
                for host_data in result["hosts"]:
                    from core.state.engagement_state import Host
                    host = Host(ip=host_data.get("ip", ""))
                    self.state.add_host(host)

        elif action.tool_name == "nmap_service_scan":
            # Parse service scan results
            if "services" in result:
                for svc_data in result["services"]:
                    from core.state.engagement_state import Service
                    service = Service(
                        host_id=None,  # Would need to lookup
                        port=svc_data.get("port", 0),
                        service_name=svc_data.get("service"),
                        version=svc_data.get("version"),
                    )
                    self.state.add_service(service)

    def _record_event(
        self,
        event_type: EventType,
        action: str,
        tool: Optional[str] = None,
        target: Optional[str] = None,
        command: Optional[str] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        exit_code: Optional[int] = None,
    ) -> Event:
        """Record an event."""
        event = Event(
            event_type=event_type,
            action=action,
            tool=tool,
            target=target,
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
        )
        self._event_chain.add_event(event)
        return event

    async def execute_tool(self, tool_name: str, **kwargs) -> dict[str, Any]:
        """Execute a tool directly (for manual commands)."""
        return await self.registry.execute(tool_name, **kwargs)

    def get_state_summary(self) -> str:
        """Get current state summary."""
        return self.state.to_summary()

    def get_memory_context(self) -> str:
        """Get memory context for LLM."""
        return self.memory.to_context()

    def get_hypotheses(self) -> list[Hypothesis]:
        """Get current hypotheses."""
        return self.reasoner._hypotheses

    def get_action_plan(self) -> list[CandidateAction]:
        """Get planned actions."""
        tools = self.registry.list_names()
        return self.planner.generate_actions(self.state, self.memory, tools)

    def get_event_chain(self) -> EventChain:
        """Get the event chain."""
        return self._event_chain

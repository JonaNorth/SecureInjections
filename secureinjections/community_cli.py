"""Community product CLI without private research command dependencies."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import threading
import webbrowser
from pathlib import Path

from .guard import Guard, InspectionRequest
from .guard.policy import GuardPolicyError
from .integrations import integration_status
from .product_protection import query_product_status
from .product_runtime import (
    ProductInstallation,
    ProductInstallationError,
    ProductInstanceLock,
    ProductPaths,
)
from .version import ENGINE_VERSION


def _emit_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _installation(args: argparse.Namespace) -> ProductInstallation:
    root = Path(args.data_dir).resolve() if args.data_dir else None
    installation = ProductInstallation(ProductPaths.default(root=root))
    installation.initialize()
    return installation


def _product(args: argparse.Namespace) -> int:
    try:
        installation = _installation(args)
        config = installation.runtime_config()
    except (OSError, ValueError, ProductInstallationError) as exc:
        print(f"Product setup failed safely: {exc}", file=sys.stderr)
        return 2
    endpoint = f"http://{config.listen_host}:{config.listen_port}"
    if args.command == "doctor":
        report = installation.doctor()
        if args.json:
            _emit_json(report)
        else:
            print("SecureInjections Community Doctor")
            print(f"Result: {report['result']}")
            for check in report["checks"]:
                print(f"- {check['id']}: {check['status']} — {check['message']}")
        return 2 if report["result"] == "FAIL" else 0
    if args.command == "status":
        status_report = query_product_status(endpoint)
        if args.json:
            _emit_json(
                status_report
                or {
                    "schema_version": "local-protection-status-error-v0.1",
                    "service_running": False,
                    "message": "SecureInjections is not running on its configured endpoint.",
                }
            )
        else:
            state = "running" if status_report else "not running"
            print(f"SecureInjections Community is {state} at {endpoint}.")
        return 0 if status_report else 2
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        print(
            "SecureInjections Community v0.6.0-rc1 supports macOS Apple Silicon; "
            "this platform is unvalidated.",
            file=sys.stderr,
        )
        return 2
    running = query_product_status(endpoint)
    if running is not None:
        print(f"SecureInjections Community is already running at {endpoint}")
        if not args.no_open:
            webbrowser.open(endpoint)
        return 0
    readiness = installation.doctor()
    service_check = next(
        (item for item in readiness["checks"] if item["id"] == "product_service"), None
    )
    if service_check is None or service_check["status"] == "FAIL":
        print(
            "Product could not start safely: the configured loopback port is occupied by an "
            "unverified process.",
            file=sys.stderr,
        )
        return 2
    try:
        lock = ProductInstanceLock(installation.paths.instance_lock)
        lock.acquire()
    except (OSError, ProductInstallationError) as exc:
        print(f"Product could not start safely: {exc}", file=sys.stderr)
        return 2
    try:
        try:
            import uvicorn

            from .service import create_app
        except ImportError:
            print("Install secureinjections[service] to start Community.", file=sys.stderr)
            return 2
        if not args.no_open:
            threading.Timer(0.7, lambda: webbrowser.open(endpoint)).start()
        print("SecureInjections Community")
        print(f"Open: {endpoint}")
        print(f"Product data: {installation.paths.root}")
        print("Raw-content logging: OFF")
        uvicorn.run(
            create_app(runtime_config=config, installation=installation),
            host=config.listen_host,
            port=config.listen_port,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Product service failed to start: {type(exc).__name__}", file=sys.stderr)
        return 2
    finally:
        lock.release()
    return 0


def _inspect(args: argparse.Namespace) -> int:
    content = args.text if args.text is not None else sys.stdin.read()
    try:
        context = json.loads(args.context_json) if args.context_json else {}
        if not isinstance(context, dict):
            raise ValueError("--context-json must contain a JSON object")
        result = Guard(policy_path=args.policy, audit_path=args.audit).inspect(
            InspectionRequest(content, args.source, args.destination, context),
            dry_run=args.dry_run,
        )
    except (GuardPolicyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Inspection failed safely: {exc}", file=sys.stderr)
        return 2
    if args.json:
        _emit_json(result.to_dict())
    else:
        print(f"Decision: {result.decision.value}")
        print(f"Risk: {result.risk.value}")
        print(f"Reason: {result.policy.reason_code}")
        print(f"Audit ID: {result.audit_id}")
    return 2 if result.decision.value == "BLOCK" else 1 if result.decision.value == "REVIEW" else 0


def _integrations(args: argparse.Namespace) -> int:
    report = integration_status()
    if args.json:
        _emit_json(report)
    else:
        print("SecureInjections Community integrations")
        for item in report["integrations"]:
            print(
                f"- {item['id']}: {item['status_display']} "
                f"(validated {', '.join(item['validated_versions'])})"
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secureinjections",
        description="SecureInjections Community local protection for supported AI workflows",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {ENGINE_VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    start = commands.add_parser("start", help="start the local Community protection product")
    start.add_argument("--no-open", action="store_true", help="do not open the browser UI")
    start.add_argument("--data-dir", help=argparse.SUPPRESS)
    start.set_defaults(handler=_product)

    status = commands.add_parser("status", help="show local Community runtime status")
    status.add_argument("--json", action="store_true")
    status.add_argument("--data-dir", help=argparse.SUPPRESS)
    status.set_defaults(handler=_product)

    doctor = commands.add_parser("doctor", help="check local Community readiness")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--data-dir", help=argparse.SUPPRESS)
    doctor.set_defaults(handler=_product)

    inspect = commands.add_parser("inspect", help="inspect content with the deterministic Guard")
    inspect.add_argument("--text")
    inspect.add_argument(
        "--source",
        default="user",
        choices=(
            "user",
            "system",
            "model",
            "retrieved_content",
            "tool_input",
            "tool_output",
            "memory",
            "file",
            "external",
            "internal",
        ),
    )
    inspect.add_argument(
        "--destination",
        default="model",
        choices=("model", "tool", "memory", "user", "external", "internal"),
    )
    inspect.add_argument("--context-json")
    inspect.add_argument("--policy")
    inspect.add_argument("--audit")
    inspect.add_argument("--dry-run", action="store_true")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(handler=_inspect)

    integrations = commands.add_parser(
        "integrations", help="show the exact Community integration scope"
    )
    integrations.add_argument("--json", action="store_true")
    integrations.set_defaults(handler=_integrations)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Module entry point so the bundle can be executed with ``python -m``."""

from __future__ import annotations

from .main import main


def run() -> None:
    """Dispatch to :func:`portable_bundle.main.main`."""

    main()


if __name__ == "__main__":  # pragma: no cover - module execution hook
    run()


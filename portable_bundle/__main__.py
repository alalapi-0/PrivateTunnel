"""便携包的模块入口，使其可通过 ``python -m portable_bundle`` 直接运行。Module entry point so the bundle can be executed with ``python -m``."""

from __future__ import annotations

from .main import main


def run() -> None:
    """Dispatch to :func:`portable_bundle.main.main`."""

    main()


if __name__ == "__main__":  # pragma: no cover - module execution hook
    run()


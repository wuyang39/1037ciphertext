"""Run the KAS with a required production configuration."""

from __future__ import annotations

import uvicorn

from .app import create_app
from .settings import KASSettings, build_service


def main() -> None:
    settings = KASSettings.from_env()
    uvicorn.run(
        create_app(build_service(settings)),
        host=settings.host,
        port=settings.port,
    )


if __name__ == "__main__":
    main()

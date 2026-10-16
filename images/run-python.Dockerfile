# gatehouse-run-python: the Python ecosystem runner (plan §13).
# Ruff (lint+format), Bandit (SAST), mypy (types), pytest + coverage.py.
FROM python:3.13-slim-bookworm

RUN pip install --no-cache-dir \
      ruff==0.8.4 \
      bandit[sarif]==1.8.0 \
      mypy==1.14.0 \
      pytest==8.3.4 \
      coverage==7.6.9

RUN useradd -m -u 65532 runner
USER 65532:65532
WORKDIR /src
ENV PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
ENTRYPOINT []

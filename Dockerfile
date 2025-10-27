# SPDX-FileCopyrightText: © 2025 DSLab - Fondazione Bruno Kessler
#
# SPDX-License-Identifier: Apache-2.0
FROM python:3.9

# Repo info
LABEL org.opencontainers.image.source=https://github.com/scc-digitalhub/digitalhub-sdk-wrapper-kfp

ARG ver_sdk=0.14.0
ARG ver_python=0.14.0
ARG ver_container=0.14.0
ARG ver_modelserve=0.14.0
ARG ver_dbt=0.14.0
ARG ver_kfp=0.14.1
ARG ver_hera=0.14.0
ARG ver_flower=0.14.0

# Set working dir
WORKDIR /app/

# Install digitalhub-core
RUN python -m pip install "digitalhub[pandas]==${ver_sdk}" \
                          "digitalhub-runtime-kfp[local]==${ver_kfp}" && \
    python -m pip install "digitalhub-runtime-python==${ver_python}" \
                          "digitalhub-runtime-container==${ver_container}"  \
                          "digitalhub-runtime-modelserve==${ver_modelserve}" \
                          "digitalhub-runtime-hera==${ver_hera}" \
                          "digitalhub-runtime-flower==${ver_flower}" \
                          "digitalhub-runtime-dbt==${ver_dbt}" --no-deps && \
    python -m pip install "pydantic>=2"

# Copy wrapper and set entry point
COPY wrapper.py /app/
COPY step.py /app/

# Add nonroot group and user
RUN useradd -r -m -u 8877 nonroot && \
    chown -R nonroot /app
USER 8877

ENTRYPOINT ["python", "wrapper.py"]

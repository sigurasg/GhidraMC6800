# Copyright 2025 Sigurdur Asgeirsson <siggi@sort.is>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:24.04

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

ENV VERSION=12.2_PUBLIC
ENV GHIDRA_SHA=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip


RUN \
    userdel ubuntu && \
    groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash && \
    apt-get update && \
    apt-get upgrade -y && \
    apt install -y \
            git \
            ssh \
            openjdk-25-jdk \
            openjdk-25-dbg \
            wget \
            unzip \
            less \
            --no-install-recommends && \
    wget --progress=bar:force -O /tmp/ghidra.zip ${GHIDRA_URL} && \
    echo "$GHIDRA_SHA /tmp/ghidra.zip" | sha256sum -c - && \
    unzip /tmp/ghidra.zip && \
    mv ghidra_${VERSION} /ghidra && \
    chmod +x /ghidra/ghidraRun

ENV GHIDRA_INSTALL_DIR=/ghidra
USER $USERNAME

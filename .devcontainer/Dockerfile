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

ENV VERSION=11.2.1_PUBLIC
ENV GHIDRA_SHA=ce4db5117da0fbaf8f33863fec4f40902f754f06b68945a59fb1c0f9b1bc461c
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip


RUN \
    userdel ubuntu && \
    groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash && \
    apt-get update && \
    apt-get upgrade -y && \
    apt install -y \
            git \
            ssh \
            openjdk-21-dbg \
            wget \
            unzip \
            --no-install-recommends && \
    wget --progress=bar:force -O /tmp/ghidra.zip ${GHIDRA_URL} && \
    echo "$GHIDRA_SHA /tmp/ghidra.zip" | sha256sum -c - && \
    unzip /tmp/ghidra.zip && \
    mv ghidra_${VERSION} /ghidra && \
    chmod +x /ghidra/ghidraRun

ENV GHIDRA_INSTALL_DIR=/ghidra
USER $USERNAME

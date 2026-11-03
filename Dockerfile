# ecdet 检测工具容器（方案 3.3.1 工具链容器固化 / 阶段五试点部署）
# 构建：docker build -t ecdet:codechecker-core .
# 使用：docker run --rm -v /path/to/project:/work ecdet:codechecker-core scan /work
FROM python:3.13-slim-trixie

# 固化 CodeChecker 分析器及 ARM 交叉编译头文件。
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang clang-tidy cppcheck g++ gcc-arm-none-eabi \
        libnewlib-arm-none-eabi libstdc++-arm-none-eabi-dev \
        ca-certificates curl xz-utils libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Infer upstream publishes Linux x86_64 binaries; verify the pinned release.
ARG INFER_VERSION=1.3.0
ARG INFER_SHA256=02be62ba931cb43e2d42bbf7abf4bd9a410cf8464cce5453934e25c90a825850
RUN test "$(dpkg --print-architecture)" = amd64 \
    && curl --fail --location --retry 3 \
        "https://github.com/facebook/infer/releases/download/v${INFER_VERSION}/infer-linux-x86_64-v${INFER_VERSION}.tar.xz" \
        --output /tmp/infer.tar.xz \
    && echo "${INFER_SHA256}  /tmp/infer.tar.xz" | sha256sum --check - \
    && mkdir -p /opt/infer \
    && tar -xJf /tmp/infer.tar.xz --strip-components=1 -C /opt/infer \
    && ln -s /opt/infer/bin/infer /usr/local/bin/infer \
    && rm /tmp/infer.tar.xz \
    && infer --version

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang-tools make cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
RUN python -c "import subprocess,sys,tomllib; deps=tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']; subprocess.check_call([sys.executable,'-m','pip','install','--no-cache-dir',*deps])"
COPY ecdet ./ecdet
COPY scripts ./scripts

RUN pip install --no-cache-dir --no-deps . \
    && useradd --create-home ecdet

USER ecdet
WORKDIR /work

ENTRYPOINT ["ecdet"]
CMD ["--version"]

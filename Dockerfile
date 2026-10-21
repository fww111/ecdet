# ecdet 检测工具容器（方案 3.3.1 工具链容器固化 / 阶段五试点部署）
# 构建：docker build -t ecdet:0.5.0 .
# 使用：docker run --rm -v /path/to/project:/work ecdet:0.5.0 scan /work
FROM python:3.13-slim

# cppcheck 作为基线引擎一并固化（检测到即接入）
RUN apt-get update \
    && apt-get install -y --no-install-recommends cppcheck \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY ecdet ./ecdet
COPY scripts ./scripts

RUN pip install --no-cache-dir . \
    && useradd --create-home ecdet

USER ecdet
WORKDIR /work

ENTRYPOINT ["ecdet"]
CMD ["--version"]

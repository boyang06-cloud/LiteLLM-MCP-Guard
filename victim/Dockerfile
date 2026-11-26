FROM python:3.11-slim

WORKDIR /app

# 安装 LiteLLM Proxy
RUN pip install --no-cache-dir "litellm[proxy]==1.83.6"

COPY config.yaml .
COPY entrypoint.sh .
COPY flag.txt /flag.txt

RUN chmod +x entrypoint.sh

EXPOSE 4000

ENTRYPOINT ["./entrypoint.sh"]
FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY mcpscope/ mcpscope/

RUN pip install --no-cache-dir -e .

EXPOSE 8080

VOLUME /root/.mcpscope

CMD ["mcpscope", "serve", "--host", "0.0.0.0", "--port", "8080"]

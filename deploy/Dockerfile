FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY thithi ./thithi
RUN pip install --no-cache-dir .
COPY config ./config
COPY agents ./agents
EXPOSE 8080
CMD ["uvicorn", "thithi.gateway.app:app", "--host", "0.0.0.0", "--port", "8080"]

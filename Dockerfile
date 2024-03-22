FROM python:3.11

RUN apt update && apt install -y pipx
RUN pipx install poetry
ENV PATH="$PATH:/root/.local/bin"

WORKDIR /app
ENTRYPOINT bash
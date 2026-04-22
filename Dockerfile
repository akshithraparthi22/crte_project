FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN gcc server.c database.c attack-history-db.c -o server -lsqlite3

EXPOSE 8080

CMD ["./server"]
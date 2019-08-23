FROM alpine:3.10 as build

RUN apk add --no-cache \
    cmake \
    gcc \
    git \
    libmilter-dev \
    make \
    musl-dev

COPY . /milterfrom

WORKDIR /milterfrom

RUN mkdir build \
    && cd build \
    && cmake -DWITH_SYSTEMD=OFF .. \
    && make


FROM alpine:3.10 as service

RUN adduser -S milterfrom \
    && apk add libmilter

COPY --from=build /milterfrom/build/milterfrom /usr/local/bin/

USER milterfrom

EXPOSE 8890/tcp

CMD ["milterfrom", "-s", "inet:8890"]

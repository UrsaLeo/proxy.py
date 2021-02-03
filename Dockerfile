FROM python:3.8-alpine as base
FROM base as builder

RUN apk add build-base
RUN apk add --no-cache libressl-dev musl-dev libffi-dev

COPY requirements.txt /app/
COPY setup.py /app/
COPY README.md /app/
COPY proxy/ /app/proxy/

WORKDIR /app
RUN pip install --upgrade pip && \
    pip install --prefix=/deps .

FROM base

LABEL com.abhinavsingh.name="abhinavsingh/proxy.py" \
      com.abhinavsingh.description="⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on \
        Network monitoring, controls & Application development, testing, debugging." \
      com.abhinavsingh.url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.vcs-url="https://github.com/abhinavsingh/proxy.py" \
      com.abhinavsingh.docker.cmd="docker run -it --rm -p 8899:8899 abhinavsingh/proxy.py"

COPY --from=builder /deps /usr/local

COPY ca-cert.pem /tmp/
COPY ca-cert-bundle.pem /tmp/
COPY ca-key.pem /tmp/
COPY ca-signing-key.pem /tmp/

# Install openssl to enable TLS interception within container
RUN apk update && apk add openssl
# RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

EXPOSE 8899/tcp
ENTRYPOINT [ "proxy" ]

CMD [ "--hostname=0.0.0.0", \
      "--port", "8899", \
      "--plugins", "proxy.plugin.AddJwtAuthorization", \
      "--ca-key-file", "/tmp/ca-key.pem", \
      "--ca-cert-file", "/tmp/ca-cert.pem", \
      "--ca-signing-key-file", "/tmp/ca-signing-key.pem", \
      "--ca-file", "/etc/ssl/certs/ca-certificates.crt", \
      "--threadless" ]

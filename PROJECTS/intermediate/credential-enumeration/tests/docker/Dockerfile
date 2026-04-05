# ©AngelaMos | 2026
# Dockerfile

FROM nimlang/nim:2.2.0-alpine AS builder

WORKDIR /build
COPY src/ src/
COPY config.nims .
COPY credential-enumeration.nimble .

RUN nim c -d:release --opt:size --passL:-static -o:/build/credenum src/harvester.nim && \
    strip -s /build/credenum

# ---------------------------------------------------------------------------

FROM ubuntu:24.04

RUN useradd -m -s /bin/bash testuser

COPY --from=builder /build/credenum /usr/local/bin/credenum
COPY tests/docker/planted/ /home/testuser/

RUN chown -R testuser:testuser /home/testuser

RUN chmod 0644 /home/testuser/.ssh/id_rsa_unprotected && \
    chmod 0600 /home/testuser/.ssh/id_ed25519_encrypted && \
    chmod 0700 /home/testuser/.ssh && \
    chmod 0644 /home/testuser/.ssh/config && \
    chmod 0644 /home/testuser/.ssh/authorized_keys && \
    chmod 0644 /home/testuser/.ssh/known_hosts

RUN chmod 0644 /home/testuser/.aws/credentials && \
    chmod 0644 /home/testuser/.git-credentials && \
    chmod 0644 /home/testuser/.pgpass && \
    chmod 0644 /home/testuser/.my.cnf && \
    chmod 0644 /home/testuser/.netrc && \
    chmod 0644 /home/testuser/.npmrc && \
    chmod 0644 /home/testuser/.pypirc && \
    chmod 0644 /home/testuser/.vault-token

COPY tests/docker/validate.sh /validate.sh
RUN chmod +x /validate.sh

USER testuser
WORKDIR /home/testuser

CMD ["/validate.sh"]

# ©AngelaMos | 2026
# chain.Dockerfile

ARG RUBY_IMAGE=ruby:4.0.2-slim
FROM ${RUBY_IMAGE}

RUN gem install --no-document activesupport:8.1.3.1

WORKDIR /app

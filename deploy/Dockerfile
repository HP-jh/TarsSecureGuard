# TarsSecureGuard v3.0.0 容器镜像（Tier 0：多阶段构建，运行层零依赖）
FROM golang:1.22.5-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/tsg .

FROM alpine:3.20
RUN adduser -D -H -u 10001 tars && mkdir -p /data && chown tars /data
USER tars
WORKDIR /data
COPY --from=build /out/tsg /usr/local/bin/tsg
EXPOSE 18889
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:18889/health || exit 1
ENTRYPOINT ["tsg"]

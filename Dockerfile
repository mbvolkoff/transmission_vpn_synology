# Official Xray 26.10.31 multi-architecture index, verified to include native TUN.
ARG XRAY_IMAGE=ghcr.io/xtls/xray-core@sha256:ceabeac03a89d991d2a247361825c1d1d2e9c91cd5dc010f298c7dc0c2f325c9
FROM ${XRAY_IMAGE} AS xray

FROM alpine:3.23
RUN apk add --no-cache python3 transmission-daemon openvpn iptables iptables-legacy iproute2 curl ca-certificates tzdata
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
WORKDIR /opt/transmission-vpn
COPY app ./app
COPY transmission/settings.json ./transmission/settings.json
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python3", "-m", "app.web"]

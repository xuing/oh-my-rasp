FROM golang:1.26.5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test ./... \
	&& CGO_ENABLED=0 go build -o /out/ohmyrasp-api ./cmd/ohmyrasp-api \
	&& CGO_ENABLED=0 go build -o /out/ohmyrasp-migrate ./cmd/ohmyrasp-migrate \
	&& mkdir -p /out/agent-artifacts

FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/ohmyrasp/oh-my-rasp
LABEL org.opencontainers.image.title="OhMyRasp Control API" \
	org.opencontainers.image.description="Self-hosted OhMyRasp control plane API and migration binary" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${REVISION}" \
	org.opencontainers.image.source="${SOURCE}"
COPY --from=build /out/ohmyrasp-api /ohmyrasp-api
COPY --from=build /out/ohmyrasp-migrate /ohmyrasp-migrate
COPY --from=build --chown=65532:65532 /out/agent-artifacts /var/lib/ohmyrasp/artifacts
EXPOSE 8080
ENTRYPOINT ["/ohmyrasp-api"]

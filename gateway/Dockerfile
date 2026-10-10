# Static binary, distroless image: the one process that holds credentials
# ships with no shell, no package manager and no interpreter.
FROM golang:1.24 AS build
WORKDIR /src
COPY gateway/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /valkyrie ./cmd/valkyrie

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /valkyrie /valkyrie
# Registry comes from registryd (VALKYRIE_REGISTRY=http://registryd:8090/v1/registry);
# a baked file is only for air-gapped single-node use.
ENV VALKYRIE_REGISTRY=http://valkyrie-registryd:8090/v1/registry
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/valkyrie"]

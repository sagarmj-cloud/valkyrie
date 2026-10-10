FROM golang:1.24 AS build
WORKDIR /src
COPY controlplane/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /registryd ./cmd/registryd && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /valkyriectl ./cmd/valkyriectl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /registryd /registryd
COPY --from=build /valkyriectl /valkyriectl
COPY policies /etc/valkyrie/policies
USER nonroot
EXPOSE 8090
ENTRYPOINT ["/registryd"]

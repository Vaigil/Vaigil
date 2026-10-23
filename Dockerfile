# Build.
#
# Static, CGO off, so the image can carry one file and nothing to patch.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY . .
# The version the binary reports, passed in by the release workflow.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o /out/vaigil ./cmd/vaigil
# An empty store directory, carried into the final image so it exists there
# owned by nonroot: Docker seeds a named volume from what is at the mount point
# in the image, ownership included, and this image has no shell to fix it.
RUN mkdir -p /out/store

# Run.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/vaigil /usr/local/bin/vaigil
# The licence and the notices of the third-party material in the binary go
# with every copy of it.
COPY --from=build /src/LICENSE /src/NOTICE /usr/share/doc/vaigil/
COPY --from=build --chown=65532:65532 /out/store /srv/store
USER nonroot:nonroot
WORKDIR /srv
# No VOLUME instruction: a declared volume nobody mounts gets an anonymous one
# that shadows the store. Mount one with -v to keep it.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vaigil"]
CMD ["--root", "/srv/store", "serve", "--addr", "0.0.0.0:8080"]

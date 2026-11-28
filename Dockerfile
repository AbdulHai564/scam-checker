FROM gcc:14-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . .
RUN cmake -S . -B /build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF "-DCMAKE_EXE_LINKER_FLAGS=-static-libstdc++ -static-libgcc" \
    && cmake --build /build --parallel 2

FROM debian:bookworm-slim
COPY --from=build /build/scam-checker /usr/local/bin/scam-checker
USER 65534:65534
ENV SCAM_BIND=0.0.0.0 PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/scam-checker"]

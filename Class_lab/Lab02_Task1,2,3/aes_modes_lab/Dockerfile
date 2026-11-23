# === STAGE 1: Build ===
FROM debian:bookworm-slim AS build

# Bổ sung 'make' để CMake tìm thấy CMAKE_MAKE_PROGRAM
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake g++ make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/
COPY tests/ ./tests/

# Biên dịch ứng dụng, chạy test và sinh ra cả file chạy + thư viện động .so
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --parallel \
    && ctest --test-dir build --output-on-failure

# === STAGE 2: Runtime ===
FROM debian:bookworm-slim

# Cài đặt libstdc++6 và Python3
RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy file thực thi test và thư viện động .so vào container
COPY --from=build /app/build/aes_tests ./aes_tests
COPY --from=build /app/build/libaes_modes.so ./libaes_modes.so

ARG LD_LIBRARY_PATH=""
ENV LD_LIBRARY_PATH=/app:${LD_LIBRARY_PATH}

CMD ["./aes_tests"]
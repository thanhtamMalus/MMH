![alt text](https://example.com)
# C++ Development and Crypto++ Setup Guide

## 1. Install Code Editor (Visual Studio Code)

Download Visual Studio Code at:  
https://code.visualstudio.com/download

---

## 2. Install C++ Compile Library (MinGW-w64)

**Note:** You should disable all old versions of gcc and g++

### 2.1 Setup msys2 (msys2-x86_64-20250830.exe)

- Download msys2 at: https://www.msys2.org/  
- Install msys2  
- Update packages:  

  ```bash
  pacman -Syu
  pacman -Su
  ```

- Install gcc, g++ compiler:  

  ```bash
  pacman -S git mingw-w64-x86_64-gcc base-devel
  ```

### 2.2 Set Windows Environment for g++, gcc

(See "Set window environment variables.docx" for more detail)

- Open System Properties box  
  - Method 1: Search `env` → open: **Edit the system environment variables**  
  - Method 2: Control Panel → System → Advanced system settings → Advanced  

- Set path for g++, gcc in "environment variables":  
  - Click **Environment Variables** → edit **Path** under **System variables**  
  - Add the following two lines (edit to your install location if ones need):  

    ```ini
    C:\msys64\mingw64\bin
    C:\msys64\usr\bin
    ```

**Note:** Ensure msys64 was installed in `C:\msys64`. If not, replace with the correct path.

### 2.3 Compile Crypto++ Library Using g++

- Download and extract Crypto++:  

  ```bash
  git clone https://github.com/weidai11/cryptopp
  ```

- Open **MSYS2 MinGW 64-bit terminal**  
- Build with g++:  

  ```bash
  make clean
  make CXX="/mingw64/bin/g++" -j 8
  make all CXX="/mingw64/bin/g++" -j 8
  make test CXX="/mingw64/bin/g++" -j 8
  ```

  *(replace `-j 16` with your number of CPU threads)*

- Copy library and header files:  

  ```bash
  mkdir -p "include/cryptopp"
  mkdir -p "lib/cryptopp/gcc" 
  cp *.h -p "include/cryptopp"
    cp *.a -p "lib/cryptopp/gcc"
  cp *.so -p "lib/cryptopp/gcc"
  examples:
  cp *.h -p "D:\cryptolibrary\include\cryptopp"
  gcc lib:
  cp *.a -p "D:\cryptolibrary\libs\cryptopp\gcc"
  cp *.so  "D:\cryptolibrary\libs\cryptopp\gcc"
  ```


- Copy the `include` and `lib` folders into your **gccproject**.

### 2.4 Set Windows Environment for clang, clang++

```bash
pacman -S mingw-w64-x86_64-clang
```

### 2.5 Compile Crypto++ Library Using clang++ (clangproject)

- Open **MSYS2 MinGW 64-bit terminal**  
- Build with clang++:  

  ```bash
  make clean
  make CXX="/mingw64/bin/clang++" CXXFLAGS="-DCRYPTOPP_DISABLE_ASM" -j 8
  make all CXX="/mingw64/bin/clang++" CXXFLAGS="-DCRYPTOPP_DISABLE_ASM" -j 8
  make test CXX="/mingw64/bin/clang++" CXXFLAGS="-DCRYPTOPP_DISABLE_ASM" -j 8
  ```

- Copy library and header files:  

  ```bash
  mkdir -p "lib/cryptopp/clang" 
  cp -p *.a "lib/cryptopp/clang" 
  cp -p *.so "lib/cryptopp/clang"
  examples:
  clang lib:
  cp *.a -p "D:\cryptolibrary\libs\cryptopp\clang"
  cp *.so  "D:\cryptolibrary\libs\cryptopp\clang"

  ```

- Copy the `include` and `lib` folders into your **clangproject**.

See more at:  
https://www.cryptopp.com/wiki/GNUmakefile

### 3. Build Crypto++ with MSVC

1. Open **Developer Command Prompt for VS 2019/2022**  
   (search `Developer Command Prompt` in Start menu).
2. Change directory to the Crypto++ folder.
3. Compiler using VS Studio 2019/2022:
Open the .sln files and compile the library to cryptlib.lib or cryptopp.dll

### 4. Example Benchmark Code (AES + Timing)

```cpp
#include <iostream>
#include <vector>
#include <chrono>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool prng;

    // Generate random key and IV
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    // Example plaintext (16 bytes)
    std::string plaintext = "0123456789ABCDEF";
    std::string ciphertext, recovered;

    // Benchmark parameters
    constexpr int BLOCK_SIZE = 1000;
    constexpr int N_TRIALS = 30;
    std::vector<double> latencies;

    // Warm-up
    auto warm_start = std::chrono::high_resolution_clock::now();
    while (true) {
        CBC_Mode<AES>::Encryption e(key, key.size(), iv);
        StringSource ss(plaintext, true,
            new StreamTransformationFilter(e, new StringSink(ciphertext))
        );
        auto warm_end = std::chrono::high_resolution_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(warm_end - warm_start).count() >= 2) break;
    }

    // Benchmark loop
    for (int t = 0; t < N_TRIALS; t++) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < BLOCK_SIZE; i++) {
            CBC_Mode<AES>::Encryption e(key, key.size(), iv);
            StringSource ss(plaintext, true,
                new StreamTransformationFilter(e, new StringSink(ciphertext))
            );
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        latencies.push_back(static_cast<double>(duration_us) / BLOCK_SIZE);
    }

    // Compute average latency
    double sum = 0;
    for (auto v : latencies) sum += v;
    double mean_latency = sum / latencies.size();

    std::cout << "AES-CBC encryption latency (µs per op): " << mean_latency << std::endl;
    return 0;
}
```

---

### 6. Notes

- Use `Release` build mode, not `Debug`, for realistic benchmarks.
- You can adapt the loop to measure **decryption** by using:

  ```cpp
  CBC_Mode<AES>::Decryption d(key, key.size(), iv);
  ```

- For more accuracy, compute **mean, median, stdev, 95% CI** like in the MinGW example.

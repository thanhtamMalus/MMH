# Setup Guide: Visual Studio Code, C++ Toolchains, and Crypto++ (Ubuntu & macOS)

## 1. Setup Visual Studio Code

i) Update packages:

```bash
sudo apt update
sudo apt install software-properties-common apt-transport-https wget
```

ii) Import the Microsoft GPG key:

```bash
wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add -
```

iii) Enable the Visual Studio Code repository:

```bash
sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main"
```

iv) Install Visual Studio Code:

```bash
sudo apt update
sudo apt install code
```

---

## 2. Setup C++ Compiler

i) Setup Ubuntu toolchains:

```bash
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt-get update
```

ii) Install build essentials:

```bash
sudo apt install build-essential
sudo apt-get install manpages-dev
```

iii) Install GCC/G++ 10:

```bash
sudo apt-get install g++-10
sudo apt-get install gcc-10
```

iv) Check compiler versions:

```bash
g++-10 --version
gcc-10 --version
gcc --version
g++ --version
```

---

## 3. Compile Crypto++

Change directory to the Crypto++ source folder, then run:

```bash
make
make all
make test
```

---

## 4. Copy the Crypto++ Library

```bash
mkdir libsudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main"

mkdir -p include/cryptopp
cp *.h include/cryptopp
cp *.a lib
cp *.so lib
```

Copy the `include` and `lib` folders to your C++ project.

> **Note:** You may also install the Crypto++ library system-wide:

```bash
sudo make install
```

This installs to `/usr/local`.

---

## 5. macOS Note

If you encounter locale issues, you may need:

```cpp
std::wcout.imbue(std::locale("en_US.UTF-8"));
```

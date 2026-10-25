# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "D:/GitHub/MMH/build/_deps/cryptopp_cmake-src"
  "D:/GitHub/MMH/build/_deps/cryptopp_cmake-build"
  "D:/GitHub/MMH/build/_deps/cryptopp_cmake-subbuild/cryptopp_cmake-populate-prefix"
  "D:/GitHub/MMH/build/_deps/cryptopp_cmake-subbuild/cryptopp_cmake-populate-prefix/tmp"
  "D:/GitHub/MMH/build/_deps/cryptopp_cmake-subbuild/cryptopp_cmake-populate-prefix/src/cryptopp_cmake-populate-stamp"
  "D:/GitHub/MMH/build/_deps/cryptopp_cmake-subbuild/cryptopp_cmake-populate-prefix/src"
  "D:/GitHub/MMH/build/_deps/cryptopp_cmake-subbuild/cryptopp_cmake-populate-prefix/src/cryptopp_cmake-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "D:/GitHub/MMH/build/_deps/cryptopp_cmake-subbuild/cryptopp_cmake-populate-prefix/src/cryptopp_cmake-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "D:/GitHub/MMH/build/_deps/cryptopp_cmake-subbuild/cryptopp_cmake-populate-prefix/src/cryptopp_cmake-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()

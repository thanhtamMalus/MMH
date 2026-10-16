# CMake generated Testfile for 
# Source directory: /home/malus/Github/MMH/aestool
# Build directory: /home/malus/Github/MMH/aestool/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(nist_kat "/home/malus/Github/MMH/aestool/build/bin/aestool" "--kat" "/home/malus/Github/MMH/aestool/vectors/nist_vectors.json")
set_tests_properties(nist_kat PROPERTIES  _BACKTRACE_TRIPLES "/home/malus/Github/MMH/aestool/CMakeLists.txt;156;add_test;/home/malus/Github/MMH/aestool/CMakeLists.txt;0;")
add_test(unit_tests "/home/malus/Github/MMH/aestool/build/bin/aescore_tests")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/malus/Github/MMH/aestool/CMakeLists.txt;174;add_test;/home/malus/Github/MMH/aestool/CMakeLists.txt;0;")
subdirs("_deps/catch2-build")

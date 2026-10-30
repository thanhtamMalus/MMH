# CMake generated Testfile for 
# Source directory: D:/GitHub/MMH/Final_lab/lab1
# Build directory: D:/GitHub/MMH/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(nist_kat "D:/GitHub/MMH/build/bin/aestool.exe" "--kat" "D:/GitHub/MMH/Final_lab/lab1/vectors/nist_vectors.json")
set_tests_properties(nist_kat PROPERTIES  _BACKTRACE_TRIPLES "D:/GitHub/MMH/Final_lab/lab1/CMakeLists.txt;217;add_test;D:/GitHub/MMH/Final_lab/lab1/CMakeLists.txt;0;")
add_test(unit_tests "D:/GitHub/MMH/build/bin/aescore_tests.exe")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/GitHub/MMH/Final_lab/lab1/CMakeLists.txt;235;add_test;D:/GitHub/MMH/Final_lab/lab1/CMakeLists.txt;0;")
subdirs("_deps/catch2-build")

# CMake generated Testfile for 
# Source directory: D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab
# Build directory: D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(aes_tests "D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/build/Debug/aes_tests.exe")
  set_tests_properties(aes_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/CMakeLists.txt;35;add_test;D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(aes_tests "D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/build/Release/aes_tests.exe")
  set_tests_properties(aes_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/CMakeLists.txt;35;add_test;D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(aes_tests "D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/build/MinSizeRel/aes_tests.exe")
  set_tests_properties(aes_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/CMakeLists.txt;35;add_test;D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(aes_tests "D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/build/RelWithDebInfo/aes_tests.exe")
  set_tests_properties(aes_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/CMakeLists.txt;35;add_test;D:/GitHub/MMH/Class_lab/Lab2_Task1,2,3/aes_modes_lab/CMakeLists.txt;0;")
else()
  add_test(aes_tests NOT_AVAILABLE)
endif()

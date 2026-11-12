file(REMOVE_RECURSE
  "bin/libaescore.dll"
  "bin/libaescore.dll.manifest"
  "bin/libaescore.pdb"
  "lib/libaescore.dll.a"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/aescore_shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()

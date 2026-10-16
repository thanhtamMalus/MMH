file(REMOVE_RECURSE
  "lib/libaescore_static.a"
  "lib/libaescore_static.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/aescore_core.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()

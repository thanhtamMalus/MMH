# ═══════════════════════════════════════════════════════════════════════════
# RsatoolOpenSSL.cmake — tự động tìm OpenSSL >= 4.0 trên BẤT KỲ máy nào
#
# Cách dùng (sau project()):
#     include(RsatoolOpenSSL)
#     rsatool_find_openssl4()
#
# Thứ tự ưu tiên khi tìm (dừng ở nơi đầu tiên có OpenSSL >= 4.0 hợp lệ):
#   1. -DOPENSSL_ROOT_DIR=...                (người dùng chỉ định rõ → sai là báo lỗi)
#   2. Biến môi trường OPENSSL_ROOT_DIR / OPENSSL_DIR / OPENSSL_HOME / OPENSSL4_ROOT_DIR
#   3. Lần tìm thành công trước đó (cache) và thư mục .deps/ do auto-build tạo ra
#   4. Các thư mục trong PATH / LD_LIBRARY_PATH / CMAKE_PREFIX_PATH (cha của bin/ lib/)
#   5. Các vị trí cài đặt quen thuộc (Linux/macOS/Windows/vcpkg/Homebrew) theo glob
#   6. /usr/local, /usr  (OpenSSL hệ thống — thường là 3.x nên sẽ bị loại)
#   7. (tuỳ chọn) -DRSATOOL_AUTO_BUILD_OPENSSL=ON: tải và build OpenSSL 4 từ source
#
# Mỗi ứng viên được kiểm tra bằng cách ĐỌC opensslv.h (không chạy file nào),
# nên OpenSSL 3.x / 1.1.x trên hệ thống bị loại ngay, không bao giờ bị chọn nhầm.
# ═══════════════════════════════════════════════════════════════════════════
include_guard(GLOBAL)

set(RSATOOL_OPENSSL_MIN_VERSION "4.0" CACHE STRING "Phiên bản OpenSSL tối thiểu")
set(RSATOOL_OPENSSL_BUILD_TAG "openssl-4.0.3" CACHE STRING
    "Git tag OpenSSL dùng khi RSATOOL_AUTO_BUILD_OPENSSL=ON")
option(RSATOOL_AUTO_BUILD_OPENSSL
       "Nếu không tìm thấy OpenSSL >= 4.0: tải source và build ngay lúc configure" OFF)
option(RSATOOL_OPENSSL_STATIC
       "Liên kết tĩnh libcrypto (file chạy được không cần .so/.dll đi kèm)" OFF)
option(RSATOOL_OPENSSL_VERBOSE "In chi tiết quá trình dò OpenSSL" OFF)

# ── Đọc phiên bản từ <root>/include/openssl/opensslv.h ──────────────────────
function(_rsatool_ossl_root_version root out)
    set(${out} "" PARENT_SCOPE)
    set(_hdr "${root}/include/openssl/opensslv.h")
    if(NOT EXISTS "${_hdr}")
        return()
    endif()
    file(STRINGS "${_hdr}" _lines
         REGEX "^[ \t]*#[ \t]*define[ \t]+OPENSSL_VERSION_(MAJOR|MINOR|PATCH)[ \t]+[0-9]+")
    set(_maj "")
    set(_min "")
    set(_pat "")
    foreach(_l IN LISTS _lines)
        if(_l MATCHES "OPENSSL_VERSION_MAJOR[ \t]+([0-9]+)")
            set(_maj "${CMAKE_MATCH_1}")
        elseif(_l MATCHES "OPENSSL_VERSION_MINOR[ \t]+([0-9]+)")
            set(_min "${CMAKE_MATCH_1}")
        elseif(_l MATCHES "OPENSSL_VERSION_PATCH[ \t]+([0-9]+)")
            set(_pat "${CMAKE_MATCH_1}")
        endif()
    endforeach()
    if(_maj STREQUAL "" OR _min STREQUAL "" OR _pat STREQUAL "")
        return()   # OpenSSL 1.1.x chỉ có OPENSSL_VERSION_NUMBER → coi như không hợp lệ
    endif()
    set(${out} "${_maj}.${_min}.${_pat}" PARENT_SCOPE)
endfunction()

# ── Root này có thư viện libcrypto không? (không chỉ có header) ─────────────
function(_rsatool_ossl_has_crypto_lib root out)
    set(${out} FALSE PARENT_SCOPE)
    foreach(_sub IN ITEMS lib lib64 lib/x64 lib/VC/x64/MD lib/VC/x64/MT lib/VC/static
                          lib/x86_64-linux-gnu lib/aarch64-linux-gnu bin)
        file(GLOB _hit "${root}/${_sub}/libcrypto*" "${root}/${_sub}/crypto*.lib")
        if(_hit)
            set(${out} TRUE PARENT_SCOPE)
            return()
        endif()
    endforeach()
endfunction()

# ── Thêm vào danh sách ứng viên (chuẩn hoá đường dẫn, bỏ trùng) ─────────────
macro(_rsatool_ossl_add_candidate path)
    if(NOT "${path}" STREQUAL "")
        file(TO_CMAKE_PATH "${path}" _p)
        get_filename_component(_p "${_p}" ABSOLUTE)
        if(IS_DIRECTORY "${_p}")
            list(APPEND _cands "${_p}")
        endif()
    endif()
endmacro()

macro(_rsatool_ossl_add_globs)
    foreach(_pat IN ITEMS ${ARGN})
        file(GLOB _m LIST_DIRECTORIES true "${_pat}")
        list(SORT _m ORDER DESCENDING)           # openssl-4.0.3 trước openssl-4.0.1
        foreach(_d IN LISTS _m)
            _rsatool_ossl_add_candidate("${_d}")
        endforeach()
    endforeach()
endmacro()

# ── Thu thập ứng viên "tự động" theo thứ tự ưu tiên ─────────────────────────
function(_rsatool_ossl_auto_candidates out)
    set(_cands "")

    # (3) lần trước + thư mục auto-build
    if(RSATOOL_OPENSSL_ROOT)
        _rsatool_ossl_add_candidate("${RSATOOL_OPENSSL_ROOT}")
    endif()
    _rsatool_ossl_add_globs("${CMAKE_SOURCE_DIR}/.deps/openssl-*")

    # (4) PATH / LD_LIBRARY_PATH / CMAKE_PREFIX_PATH → thử chính nó và thư mục cha
    set(_dirs "")
    foreach(_var IN ITEMS PATH LD_LIBRARY_PATH DYLD_LIBRARY_PATH LIBRARY_PATH CPATH)
        if(DEFINED ENV{${_var}})
            file(TO_CMAKE_PATH "$ENV{${_var}}" _conv)   # tách theo ';' hoặc ':' tuỳ OS
            list(APPEND _dirs ${_conv})
        endif()
    endforeach()
    list(APPEND _dirs ${CMAKE_PREFIX_PATH})
    if(DEFINED ENV{CMAKE_PREFIX_PATH})
        file(TO_CMAKE_PATH "$ENV{CMAKE_PREFIX_PATH}" _conv)
        list(APPEND _dirs ${_conv})
    endif()
    foreach(_d IN LISTS _dirs)
        if(NOT "${_d}" STREQUAL "")
            _rsatool_ossl_add_candidate("${_d}")
            _rsatool_ossl_add_candidate("${_d}/..")
        endif()
    endforeach()

    # (5) vị trí quen thuộc
    set(_home "")
    if(DEFINED ENV{HOME})
        set(_home "$ENV{HOME}")
    elseif(DEFINED ENV{USERPROFILE})
        set(_home "$ENV{USERPROFILE}")
    endif()
    file(TO_CMAKE_PATH "${_home}" _home)

    if(_home)
        _rsatool_ossl_add_globs(
            "${_home}/openssl*" "${_home}/OpenSSL*" "${_home}/opt/openssl*"
            "${_home}/.local/openssl*" "${_home}/.local" "${_home}/local/openssl*"
            "${_home}/libs/openssl*" "${_home}/lib/openssl*" "${_home}/tools/openssl*"
            "${_home}/cryptolibrary/openssl*")
    endif()

    # vcpkg
    foreach(_v IN ITEMS VCPKG_ROOT VCPKG_INSTALLATION_ROOT)
        if(DEFINED ENV{${_v}})
            file(TO_CMAKE_PATH "$ENV{${_v}}" _vr)
            _rsatool_ossl_add_globs("${_vr}/installed/*")
        endif()
    endforeach()

    if(WIN32)
        foreach(_drv IN ITEMS C D E F G H)
            _rsatool_ossl_add_globs(
                "${_drv}:/cryptolibrary/openssl*" "${_drv}:/cryptolibrary/OpenSSL*"
                "${_drv}:/crypto*/openssl*"
                "${_drv}:/openssl*" "${_drv}:/OpenSSL*" "${_drv}:/OpenSSL-Win64*"
                "${_drv}:/libs/openssl*" "${_drv}:/lib/openssl*" "${_drv}:/dev/openssl*"
                "${_drv}:/tools/openssl*" "${_drv}:/third_party/openssl*"
                "${_drv}:/Program Files/OpenSSL*" "${_drv}:/Program Files (x86)/OpenSSL*"
                "${_drv}:/Program Files/openssl*")
        endforeach()
    else()
        _rsatool_ossl_add_globs(
            "/opt/openssl*" "/opt/OpenSSL*" "/opt/openssl@4*" "/opt/local/libexec/openssl*"
            "/usr/local/openssl*" "/usr/local/ssl*" "/usr/local/opt/openssl@4*"
            "/usr/local/Cellar/openssl@4/*"
            "/opt/homebrew/opt/openssl@4*" "/opt/homebrew/Cellar/openssl@4/*"
            "/usr/openssl*" "/opt/*/openssl*"
            "/usr/local" "/usr")
    endif()

    list(REMOVE_DUPLICATES _cands)
    set(${out} "${_cands}" PARENT_SCOPE)
endfunction()

# ── Tự build OpenSSL 4 từ source (fallback, chỉ khi bật option) ─────────────
function(_rsatool_ossl_autobuild out)
    set(_prefix "${CMAKE_SOURCE_DIR}/.deps/${RSATOOL_OPENSSL_BUILD_TAG}")
    set(_src    "${CMAKE_BINARY_DIR}/_openssl_src")
    set(_log    "${CMAKE_BINARY_DIR}/openssl_build.log")
    set(${out} "" PARENT_SCOPE)

    find_package(Git QUIET)
    find_program(RSATOOL_PERL perl)
    if(NOT GIT_FOUND OR NOT RSATOOL_PERL)
        message(FATAL_ERROR "RSATOOL_AUTO_BUILD_OPENSSL cần 'git' và 'perl' trong PATH.")
    endif()

    cmake_host_system_information(RESULT _jobs QUERY NUMBER_OF_LOGICAL_CORES)
    if(NOT _jobs)
        set(_jobs 2)
    endif()

    if(WIN32)
        find_program(RSATOOL_NMAKE nmake)
        if(NOT RSATOOL_NMAKE)
            message(FATAL_ERROR
                "Auto-build trên Windows cần chạy trong \"x64 Native Tools Command Prompt "
                "for VS 2022\" (để có nmake/cl). Hoặc cài OpenSSL 4 sẵn rồi đặt OPENSSL_ROOT_DIR.")
        endif()
        find_program(RSATOOL_NASM nasm)
        set(_cfg ${RSATOOL_PERL} Configure VC-WIN64A)
        if(NOT RSATOOL_NASM)
            list(APPEND _cfg no-asm)
        endif()
        file(TO_NATIVE_PATH "${_prefix}" _prefix_native)
        list(APPEND _cfg "--prefix=${_prefix_native}" "--openssldir=${_prefix_native}\\ssl")
        set(_make ${RSATOOL_NMAKE})
        set(_make_install ${RSATOOL_NMAKE} install_sw)
    else()
        find_program(RSATOOL_MAKE NAMES gmake make)
        if(NOT RSATOOL_MAKE)
            message(FATAL_ERROR "Auto-build OpenSSL cần 'make' trong PATH.")
        endif()
        set(_cfg ${RSATOOL_PERL} Configure "--prefix=${_prefix}" "--openssldir=${_prefix}/ssl")
        list(APPEND _cfg --libdir=lib)
        set(_make ${RSATOOL_MAKE} -j${_jobs})
        set(_make_install ${RSATOOL_MAKE} install_sw)
    endif()
    list(APPEND _cfg no-tests no-docs)
    if(RSATOOL_OPENSSL_STATIC)
        list(APPEND _cfg no-shared)
    endif()

    message(STATUS "RSATool: tải OpenSSL ${RSATOOL_OPENSSL_BUILD_TAG} và build (vài phút)...")
    message(STATUS "RSATool: log chi tiết: ${_log}")
    file(REMOVE_RECURSE "${_src}")
    foreach(_step IN ITEMS clone configure build install)
        if(_step STREQUAL "clone")
            set(_cmd ${GIT_EXECUTABLE} clone --depth 1 --branch ${RSATOOL_OPENSSL_BUILD_TAG}
                     https://github.com/openssl/openssl.git "${_src}")
            set(_wd "${CMAKE_BINARY_DIR}")
        elseif(_step STREQUAL "configure")
            set(_cmd ${_cfg})
            set(_wd "${_src}")
        elseif(_step STREQUAL "build")
            set(_cmd ${_make})
            set(_wd "${_src}")
        else()
            set(_cmd ${_make_install})
            set(_wd "${_src}")
        endif()
        execute_process(COMMAND ${_cmd} WORKING_DIRECTORY "${_wd}"
                        RESULT_VARIABLE _rc OUTPUT_FILE "${_log}" ERROR_FILE "${_log}")
        if(NOT _rc EQUAL 0)
            message(FATAL_ERROR "Auto-build OpenSSL lỗi ở bước '${_step}' (mã ${_rc}). Xem ${_log}")
        endif()
    endforeach()
    file(REMOVE_RECURSE "${_src}")
    set(${out} "${_prefix}" PARENT_SCOPE)
endfunction()

# ── Thông điệp lỗi đầy đủ khi không tìm được ────────────────────────────────
function(_rsatool_ossl_fail skipped)
    set(_msg "Không tìm thấy OpenSSL >= ${RSATOOL_OPENSSL_MIN_VERSION} trên máy này.\n")
    if(skipped)
        string(APPEND _msg "\nĐã thấy nhưng BỎ QUA (quá cũ / thiếu thư viện):\n")
        foreach(_s IN LISTS skipped)
            string(APPEND _msg "    - ${_s}\n")
        endforeach()
    endif()
    string(APPEND _msg
"\nCách khắc phục (chọn 1):
  A) Đã cài OpenSSL 4 ở thư mục lạ → chỉ đường dẫn:
       Linux  : cmake -B build -DOPENSSL_ROOT_DIR=/duong/dan/openssl4
       Windows: cmake -B build -DOPENSSL_ROOT_DIR=D:/duong/dan/openssl4
     (hoặc đặt biến môi trường OPENSSL_ROOT_DIR)
  B) Chưa cài → để CMake tự tải & build (cần git, perl, make/nmake, internet):
       cmake -B build -DRSATOOL_AUTO_BUILD_OPENSSL=ON
  C) Tự cài theo docs/INSTALL_OPENSSL.md
")
    message(FATAL_ERROR "${_msg}")
endfunction()

# ── Hàm chính ───────────────────────────────────────────────────────────────
macro(rsatool_find_openssl4)
    # Gom nguồn "chỉ định rõ"
    set(_explicit "")        # cặp "nguồn|đường dẫn"
    if(OPENSSL_ROOT_DIR AND NOT "${OPENSSL_ROOT_DIR}" STREQUAL "")
        list(APPEND _explicit "-DOPENSSL_ROOT_DIR|${OPENSSL_ROOT_DIR}")
    endif()
    foreach(_ev IN ITEMS OPENSSL_ROOT_DIR OPENSSL_DIR OPENSSL_HOME OPENSSL4_ROOT_DIR)
        if(DEFINED ENV{${_ev}} AND NOT "$ENV{${_ev}}" STREQUAL "")
            list(APPEND _explicit "env ${_ev}|$ENV{${_ev}}")
        endif()
    endforeach()

    set(_chosen "")
    set(_chosen_ver "")
    set(_skipped "")

    # (1)(2) chỉ định rõ
    foreach(_item IN LISTS _explicit)
        string(REPLACE "|" ";" _pair "${_item}")
        list(GET _pair 0 _src)
        list(GET _pair 1 _path)
        file(TO_CMAKE_PATH "${_path}" _path)
        _rsatool_ossl_root_version("${_path}" _ver)
        _rsatool_ossl_has_crypto_lib("${_path}" _haslib)
        if(_ver AND _ver VERSION_GREATER_EQUAL RSATOOL_OPENSSL_MIN_VERSION AND _haslib)
            set(_chosen "${_path}")
            set(_chosen_ver "${_ver}")
            message(STATUS "RSATool: dùng OpenSSL ${_ver} theo ${_src}: ${_path}")
            break()
        endif()
        if(NOT _ver)
            set(_why "không có include/openssl/opensslv.h hợp lệ")
        elseif(NOT _ver VERSION_GREATER_EQUAL RSATOOL_OPENSSL_MIN_VERSION)
            set(_why "là OpenSSL ${_ver}, cần >= ${RSATOOL_OPENSSL_MIN_VERSION}")
        else()
            set(_why "thiếu thư viện libcrypto")
        endif()
        if(_src STREQUAL "-DOPENSSL_ROOT_DIR")
            message(FATAL_ERROR "OPENSSL_ROOT_DIR='${_path}' không dùng được: ${_why}.")
        endif()
        message(WARNING "RSATool: bỏ qua ${_src}='${_path}' (${_why}); chuyển sang tự dò.")
        list(APPEND _skipped "${_path}  (${_why})")
    endforeach()

    # (3)-(6) tự dò
    if(NOT _chosen)
        _rsatool_ossl_auto_candidates(_auto)
        foreach(_c IN LISTS _auto)
            _rsatool_ossl_root_version("${_c}" _ver)
            if(NOT _ver)
                continue()
            endif()
            _rsatool_ossl_has_crypto_lib("${_c}" _haslib)
            if(NOT _ver VERSION_GREATER_EQUAL RSATOOL_OPENSSL_MIN_VERSION)
                list(APPEND _skipped "${_c}  (OpenSSL ${_ver} < ${RSATOOL_OPENSSL_MIN_VERSION})")
            elseif(NOT _haslib)
                list(APPEND _skipped "${_c}  (OpenSSL ${_ver} nhưng thiếu libcrypto)")
            elseif(NOT _chosen OR _ver VERSION_GREATER _chosen_ver)
                set(_chosen "${_c}")
                set(_chosen_ver "${_ver}")
                if(NOT RSATOOL_OPENSSL_VERBOSE)
                    # ứng viên đầu tiên hợp lệ có ưu tiên cao nhất; chỉ so tiếp nếu VERBOSE
                    break()
                endif()
            endif()
        endforeach()
        if(_chosen)
            message(STATUS "RSATool: tự tìm thấy OpenSSL ${_chosen_ver} tại ${_chosen}")
        endif()
    endif()

    # (7) auto-build
    if(NOT _chosen AND RSATOOL_AUTO_BUILD_OPENSSL)
        _rsatool_ossl_autobuild(_built)
        _rsatool_ossl_root_version("${_built}" _ver)
        if(_ver AND _ver VERSION_GREATER_EQUAL RSATOOL_OPENSSL_MIN_VERSION)
            set(_chosen "${_built}")
            set(_chosen_ver "${_ver}")
            message(STATUS "RSATool: đã build OpenSSL ${_ver} tại ${_built}")
        endif()
    endif()

    if(NOT _chosen)
        _rsatool_ossl_fail("${_skipped}")
    endif()
    if(_skipped AND RSATOOL_OPENSSL_VERBOSE)
        foreach(_s IN LISTS _skipped)
            message(STATUS "RSATool: bỏ qua ${_s}")
        endforeach()
    endif()

    # Nếu root đổi so với lần configure trước → xoá cache cũ của FindOpenSSL
    if(DEFINED RSATOOL_OPENSSL_ROOT AND NOT "${RSATOOL_OPENSSL_ROOT}" STREQUAL "${_chosen}")
        foreach(_cv IN ITEMS OPENSSL_INCLUDE_DIR OPENSSL_CRYPTO_LIBRARY OPENSSL_SSL_LIBRARY
                             LIB_EAY_DEBUG LIB_EAY_RELEASE SSL_EAY_DEBUG SSL_EAY_RELEASE
                             OPENSSL_APPLINK_SOURCE)
            unset(${_cv} CACHE)
        endforeach()
    endif()
    set(RSATOOL_OPENSSL_ROOT "${_chosen}" CACHE INTERNAL "OpenSSL root đã chọn")

    # Đưa vào FindOpenSSL của CMake (biến thường che biến cache → luôn thắng)
    set(OPENSSL_ROOT_DIR "${_chosen}")
    if(RSATOOL_OPENSSL_STATIC)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()
    find_package(OpenSSL ${RSATOOL_OPENSSL_MIN_VERSION} REQUIRED)

    # Kiểm tra chéo: header/lib FindOpenSSL trả về PHẢI nằm trong root đã chọn
    # (tránh trường hợp lẫn header 4.x với libcrypto 3.x của hệ thống).
    # So sánh sau khi resolve symlink; không phân biệt hoa/thường (Windows: D:/ vs d:/).
    get_filename_component(_root_r "${_chosen}" REALPATH)
    get_filename_component(_inc_r  "${OPENSSL_INCLUDE_DIR}" REALPATH)
    get_filename_component(_lib_r  "${OPENSSL_CRYPTO_LIBRARY}" REALPATH)
    string(TOLOWER "${_root_r}" _root_l)
    string(TOLOWER "${_inc_r}"  _inc_l)
    string(TOLOWER "${_lib_r}"  _lib_l)
    string(FIND "${_inc_l}" "${_root_l}" _inc_pos)
    string(FIND "${_lib_l}" "${_root_l}" _lib_pos)
    if(NOT _inc_pos EQUAL 0 OR NOT _lib_pos EQUAL 0)
        message(FATAL_ERROR
            "FindOpenSSL trả về đường dẫn nằm ngoài ${_chosen}:\n"
            "  include: ${OPENSSL_INCLUDE_DIR}\n  crypto : ${OPENSSL_CRYPTO_LIBRARY}\n"
            "Xoá thư mục build rồi configure lại (rm -rf build).")
    endif()
    if(OPENSSL_VERSION VERSION_LESS RSATOOL_OPENSSL_MIN_VERSION)
        message(FATAL_ERROR "OpenSSL ${OPENSSL_VERSION} < ${RSATOOL_OPENSSL_MIN_VERSION}")
    endif()

    get_filename_component(RSATOOL_OPENSSL_LIB_DIR "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
    message(STATUS "OpenSSL version : ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL root    : ${_chosen}")
    message(STATUS "OpenSSL include : ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL crypto  : ${OPENSSL_CRYPTO_LIBRARY}")

    # Windows: tìm DLL runtime (OPENSSL_CRYPTO_LIBRARY chỉ là import lib .lib)
    set(RSATOOL_OPENSSL_DLLS "")
    if(WIN32 AND NOT RSATOOL_OPENSSL_STATIC)
        file(GLOB RSATOOL_OPENSSL_DLLS
            "${_chosen}/bin/libcrypto*.dll" "${_chosen}/bin/*/libcrypto*.dll"
            "${_chosen}/lib/libcrypto*.dll"  "${_chosen}/libcrypto*.dll"
            "${RSATOOL_OPENSSL_LIB_DIR}/../bin/libcrypto*.dll"
            "${RSATOOL_OPENSSL_LIB_DIR}/../../bin/libcrypto*.dll")
        list(REMOVE_DUPLICATES RSATOOL_OPENSSL_DLLS)
        if(RSATOOL_OPENSSL_DLLS)
            message(STATUS "OpenSSL DLL     : ${RSATOOL_OPENSSL_DLLS}")
        else()
            message(WARNING "Không thấy libcrypto*.dll trong ${_chosen}/bin — "
                            "chạy .exe có thể báo thiếu DLL (hãy thêm thư mục bin vào PATH).")
        endif()
    endif()

    # RPATH: binary tự tìm libcrypto.so.4 ở đúng thư mục đã build, kể cả khi
    # LD_LIBRARY_PATH trống. $ORIGIN cho phép đặt .so cạnh file chạy.
    if(UNIX)
        if(APPLE)
            set(_origin "@loader_path")
        else()
            set(_origin "$ORIGIN")
        endif()
        set(CMAKE_BUILD_RPATH   "${_origin};${RSATOOL_OPENSSL_LIB_DIR}")
        set(CMAKE_INSTALL_RPATH "${_origin};${RSATOOL_OPENSSL_LIB_DIR}")
    endif()
endmacro()

# ── Gắn cấu hình runtime cho 1 target (Windows: copy DLL cạnh file .exe) ────
function(rsatool_setup_runtime tgt)
    if(WIN32 AND RSATOOL_OPENSSL_DLLS)
        foreach(_dll IN LISTS RSATOOL_OPENSSL_DLLS)
            add_custom_command(TARGET ${tgt} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${_dll}" "$<TARGET_FILE_DIR:${tgt}>"
                COMMENT "Copy ${_dll} -> $<TARGET_FILE_DIR:${tgt}>")
        endforeach()
    endif()
endfunction()

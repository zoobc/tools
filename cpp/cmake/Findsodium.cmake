# FindSodium.cmake
# Find libsodium library
#
# This will define:
#  sodium_FOUND - System has libsodium
#  sodium_INCLUDE_DIRS - The libsodium include directories
#  sodium_LIBRARIES - The libraries needed to use libsodium

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_SODIUM QUIET libsodium)
endif()

find_path(sodium_INCLUDE_DIR
    NAMES sodium.h
    PATHS ${PC_SODIUM_INCLUDE_DIRS}
    PATH_SUFFIXES sodium
)

find_library(sodium_LIBRARY
    NAMES sodium libsodium
    PATHS ${PC_SODIUM_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(sodium
    REQUIRED_VARS sodium_LIBRARY sodium_INCLUDE_DIR
)

if(sodium_FOUND)
    set(sodium_LIBRARIES ${sodium_LIBRARY})
    set(sodium_INCLUDE_DIRS ${sodium_INCLUDE_DIR})

    if(NOT TARGET sodium)
        add_library(sodium UNKNOWN IMPORTED)
        set_target_properties(sodium PROPERTIES
            IMPORTED_LOCATION "${sodium_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${sodium_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(sodium_INCLUDE_DIR sodium_LIBRARY)

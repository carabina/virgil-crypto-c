#
# Copyright (C) 2015-2019 Virgil Security, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

include_guard()

# ---------------------------------------------------------------------------
#   Add compiler pedantic diagnostic options to the <target>
# ---------------------------------------------------------------------------
function(enable_target_pedantic target)
    target_compile_options(${target}
            PRIVATE
                $<$<C_COMPILER_ID:GNU>:
                        -Wall -Werror -pedantic>

                $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>>:
                        -Werror -Wall -pedantic -Wassign-enum -Wextra>
            )
endfunction()

# ---------------------------------------------------------------------------
#   Add compiler and linker profiling options to the <target>
# ---------------------------------------------------------------------------
function(enable_target_profiling target)
    target_compile_options(${target}
            PRIVATE $<$<C_COMPILER_ID:GNU>:-pg>
            )

    target_link_libraries(${target}
            PRIVATE $<$<C_COMPILER_ID:GNU>:-pg>
            )
endfunction()

# ---------------------------------------------------------------------------
#   Add __FILENAME__ compiler definition, that handles file name
#   without path, to each source file.
# ---------------------------------------------------------------------------
function(target_add_filename_definitions target)
    get_target_property(SOURCES ${target} SOURCES)
    foreach(src ${SOURCES})
        get_filename_component(file_name "${src}" NAME)
        get_filename_component(file_ext "${src}" EXT)

        if(file_ext STREQUAL ".c")
            set_property(SOURCE "${src}" APPEND_STRING PROPERTY COMPILE_DEFINITIONS "__FILENAME__=\"${file_name}\"")
        endif()
    endforeach()
endfunction()

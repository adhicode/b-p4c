# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Makefile for a fake backend that is used for testing the P4-16 front-end.

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.h.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/version.h" @ONLY)

set (P4TEST_SRCS
  p4frontendlib.cpp
  midend.cpp
  )
set (P4TEST_HDRS
  midend.h
  )

add_cpplint_files (${CMAKE_CURRENT_SOURCE_DIR} "${P4TEST_SRCS};${P4TEST_HDRS}")

build_unified(P4TEST_SRCS ALL)
add_library(p4frontendlib SHARED ${P4TEST_SRCS} ${EXTENSION_P4_14_CONV_SOURCES})
target_link_libraries (p4frontendlib ${P4_SHARED_LIBRARIES})
add_dependencies(p4frontendlib genIR frontend-shlib midend-shlib)

#install

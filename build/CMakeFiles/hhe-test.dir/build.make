# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.24

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/mrgenie/Projects/hhe_ppml

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/mrgenie/Projects/hhe_ppml/build

# Include any dependencies generated for this target.
include CMakeFiles/hhe-test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/hhe-test.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/hhe-test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/hhe-test.dir/flags.make

CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o: CMakeFiles/hhe-test.dir/flags.make
CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o: /home/mrgenie/Projects/hhe_ppml/pasta_simple_test.cpp
CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o: CMakeFiles/hhe-test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mrgenie/Projects/hhe_ppml/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o -MF CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o.d -o CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o -c /home/mrgenie/Projects/hhe_ppml/pasta_simple_test.cpp

CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.i"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/mrgenie/Projects/hhe_ppml/pasta_simple_test.cpp > CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.i

CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.s"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/mrgenie/Projects/hhe_ppml/pasta_simple_test.cpp -o CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.s

CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o: CMakeFiles/hhe-test.dir/flags.make
CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o: /home/mrgenie/Projects/hhe_ppml/SEAL_Cipher.cpp
CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o: CMakeFiles/hhe-test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mrgenie/Projects/hhe_ppml/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o -MF CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o.d -o CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o -c /home/mrgenie/Projects/hhe_ppml/SEAL_Cipher.cpp

CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.i"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/mrgenie/Projects/hhe_ppml/SEAL_Cipher.cpp > CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.i

CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.s"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/mrgenie/Projects/hhe_ppml/SEAL_Cipher.cpp -o CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.s

CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o: CMakeFiles/hhe-test.dir/flags.make
CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o: /home/mrgenie/Projects/hhe_ppml/pasta_3_seal.cpp
CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o: CMakeFiles/hhe-test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mrgenie/Projects/hhe_ppml/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o -MF CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o.d -o CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o -c /home/mrgenie/Projects/hhe_ppml/pasta_3_seal.cpp

CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.i"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/mrgenie/Projects/hhe_ppml/pasta_3_seal.cpp > CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.i

CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.s"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/mrgenie/Projects/hhe_ppml/pasta_3_seal.cpp -o CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.s

CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o: CMakeFiles/hhe-test.dir/flags.make
CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o: /home/mrgenie/Projects/hhe_ppml/pasta_3_plain.cpp
CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o: CMakeFiles/hhe-test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mrgenie/Projects/hhe_ppml/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o -MF CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o.d -o CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o -c /home/mrgenie/Projects/hhe_ppml/pasta_3_plain.cpp

CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.i"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/mrgenie/Projects/hhe_ppml/pasta_3_plain.cpp > CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.i

CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.s"
	/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/mrgenie/Projects/hhe_ppml/pasta_3_plain.cpp -o CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.s

# Object files for target hhe-test
hhe__test_OBJECTS = \
"CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o" \
"CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o" \
"CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o" \
"CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o"

# External object files for target hhe-test
hhe__test_EXTERNAL_OBJECTS =

hhe-test: CMakeFiles/hhe-test.dir/pasta_simple_test.cpp.o
hhe-test: CMakeFiles/hhe-test.dir/SEAL_Cipher.cpp.o
hhe-test: CMakeFiles/hhe-test.dir/pasta_3_seal.cpp.o
hhe-test: CMakeFiles/hhe-test.dir/pasta_3_plain.cpp.o
hhe-test: CMakeFiles/hhe-test.dir/build.make
hhe-test: /usr/local/lib/libseal-4.0.a
hhe-test: util/keccak/libkeccak.a
hhe-test: util/aes/libaes.a
hhe-test: CMakeFiles/hhe-test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mrgenie/Projects/hhe_ppml/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX executable hhe-test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/hhe-test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/hhe-test.dir/build: hhe-test
.PHONY : CMakeFiles/hhe-test.dir/build

CMakeFiles/hhe-test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/hhe-test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/hhe-test.dir/clean

CMakeFiles/hhe-test.dir/depend:
	cd /home/mrgenie/Projects/hhe_ppml/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mrgenie/Projects/hhe_ppml /home/mrgenie/Projects/hhe_ppml /home/mrgenie/Projects/hhe_ppml/build /home/mrgenie/Projects/hhe_ppml/build /home/mrgenie/Projects/hhe_ppml/build/CMakeFiles/hhe-test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/hhe-test.dir/depend


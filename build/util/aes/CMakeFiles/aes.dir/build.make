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
include util/aes/CMakeFiles/aes.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include util/aes/CMakeFiles/aes.dir/compiler_depend.make

# Include the progress variables for this target.
include util/aes/CMakeFiles/aes.dir/progress.make

# Include the compile flags for this target's objects.
include util/aes/CMakeFiles/aes.dir/flags.make

util/aes/CMakeFiles/aes.dir/aes.cpp.o: util/aes/CMakeFiles/aes.dir/flags.make
util/aes/CMakeFiles/aes.dir/aes.cpp.o: /home/mrgenie/Projects/hhe_ppml/util/aes/aes.cpp
util/aes/CMakeFiles/aes.dir/aes.cpp.o: util/aes/CMakeFiles/aes.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mrgenie/Projects/hhe_ppml/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object util/aes/CMakeFiles/aes.dir/aes.cpp.o"
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && /bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT util/aes/CMakeFiles/aes.dir/aes.cpp.o -MF CMakeFiles/aes.dir/aes.cpp.o.d -o CMakeFiles/aes.dir/aes.cpp.o -c /home/mrgenie/Projects/hhe_ppml/util/aes/aes.cpp

util/aes/CMakeFiles/aes.dir/aes.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aes.dir/aes.cpp.i"
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && /bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/mrgenie/Projects/hhe_ppml/util/aes/aes.cpp > CMakeFiles/aes.dir/aes.cpp.i

util/aes/CMakeFiles/aes.dir/aes.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aes.dir/aes.cpp.s"
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && /bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/mrgenie/Projects/hhe_ppml/util/aes/aes.cpp -o CMakeFiles/aes.dir/aes.cpp.s

util/aes/CMakeFiles/aes.dir/block.cpp.o: util/aes/CMakeFiles/aes.dir/flags.make
util/aes/CMakeFiles/aes.dir/block.cpp.o: /home/mrgenie/Projects/hhe_ppml/util/aes/block.cpp
util/aes/CMakeFiles/aes.dir/block.cpp.o: util/aes/CMakeFiles/aes.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/mrgenie/Projects/hhe_ppml/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object util/aes/CMakeFiles/aes.dir/block.cpp.o"
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && /bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT util/aes/CMakeFiles/aes.dir/block.cpp.o -MF CMakeFiles/aes.dir/block.cpp.o.d -o CMakeFiles/aes.dir/block.cpp.o -c /home/mrgenie/Projects/hhe_ppml/util/aes/block.cpp

util/aes/CMakeFiles/aes.dir/block.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/aes.dir/block.cpp.i"
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && /bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/mrgenie/Projects/hhe_ppml/util/aes/block.cpp > CMakeFiles/aes.dir/block.cpp.i

util/aes/CMakeFiles/aes.dir/block.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/aes.dir/block.cpp.s"
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && /bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/mrgenie/Projects/hhe_ppml/util/aes/block.cpp -o CMakeFiles/aes.dir/block.cpp.s

# Object files for target aes
aes_OBJECTS = \
"CMakeFiles/aes.dir/aes.cpp.o" \
"CMakeFiles/aes.dir/block.cpp.o"

# External object files for target aes
aes_EXTERNAL_OBJECTS =

util/aes/libaes.a: util/aes/CMakeFiles/aes.dir/aes.cpp.o
util/aes/libaes.a: util/aes/CMakeFiles/aes.dir/block.cpp.o
util/aes/libaes.a: util/aes/CMakeFiles/aes.dir/build.make
util/aes/libaes.a: util/aes/CMakeFiles/aes.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/mrgenie/Projects/hhe_ppml/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX static library libaes.a"
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && $(CMAKE_COMMAND) -P CMakeFiles/aes.dir/cmake_clean_target.cmake
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/aes.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
util/aes/CMakeFiles/aes.dir/build: util/aes/libaes.a
.PHONY : util/aes/CMakeFiles/aes.dir/build

util/aes/CMakeFiles/aes.dir/clean:
	cd /home/mrgenie/Projects/hhe_ppml/build/util/aes && $(CMAKE_COMMAND) -P CMakeFiles/aes.dir/cmake_clean.cmake
.PHONY : util/aes/CMakeFiles/aes.dir/clean

util/aes/CMakeFiles/aes.dir/depend:
	cd /home/mrgenie/Projects/hhe_ppml/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/mrgenie/Projects/hhe_ppml /home/mrgenie/Projects/hhe_ppml/util/aes /home/mrgenie/Projects/hhe_ppml/build /home/mrgenie/Projects/hhe_ppml/build/util/aes /home/mrgenie/Projects/hhe_ppml/build/util/aes/CMakeFiles/aes.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : util/aes/CMakeFiles/aes.dir/depend


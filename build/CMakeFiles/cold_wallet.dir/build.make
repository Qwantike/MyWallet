# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

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
CMAKE_SOURCE_DIR = /home/paul/Bureau/BTC_WALLET/COLD_WALLET

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/paul/Bureau/BTC_WALLET/COLD_WALLET/build

# Include any dependencies generated for this target.
include CMakeFiles/cold_wallet.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/cold_wallet.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/cold_wallet.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/cold_wallet.dir/flags.make

CMakeFiles/cold_wallet.dir/src/main.cpp.o: CMakeFiles/cold_wallet.dir/flags.make
CMakeFiles/cold_wallet.dir/src/main.cpp.o: ../src/main.cpp
CMakeFiles/cold_wallet.dir/src/main.cpp.o: CMakeFiles/cold_wallet.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/paul/Bureau/BTC_WALLET/COLD_WALLET/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/cold_wallet.dir/src/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/cold_wallet.dir/src/main.cpp.o -MF CMakeFiles/cold_wallet.dir/src/main.cpp.o.d -o CMakeFiles/cold_wallet.dir/src/main.cpp.o -c /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/main.cpp

CMakeFiles/cold_wallet.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cold_wallet.dir/src/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/main.cpp > CMakeFiles/cold_wallet.dir/src/main.cpp.i

CMakeFiles/cold_wallet.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cold_wallet.dir/src/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/main.cpp -o CMakeFiles/cold_wallet.dir/src/main.cpp.s

CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o: CMakeFiles/cold_wallet.dir/flags.make
CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o: ../src/Wallet.cpp
CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o: CMakeFiles/cold_wallet.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/paul/Bureau/BTC_WALLET/COLD_WALLET/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o -MF CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o.d -o CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o -c /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Wallet.cpp

CMakeFiles/cold_wallet.dir/src/Wallet.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cold_wallet.dir/src/Wallet.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Wallet.cpp > CMakeFiles/cold_wallet.dir/src/Wallet.cpp.i

CMakeFiles/cold_wallet.dir/src/Wallet.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cold_wallet.dir/src/Wallet.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Wallet.cpp -o CMakeFiles/cold_wallet.dir/src/Wallet.cpp.s

CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o: CMakeFiles/cold_wallet.dir/flags.make
CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o: ../src/KeyGeneration.cpp
CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o: CMakeFiles/cold_wallet.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/paul/Bureau/BTC_WALLET/COLD_WALLET/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o -MF CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o.d -o CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o -c /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/KeyGeneration.cpp

CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/KeyGeneration.cpp > CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.i

CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/KeyGeneration.cpp -o CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.s

CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o: CMakeFiles/cold_wallet.dir/flags.make
CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o: ../src/Transaction.cpp
CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o: CMakeFiles/cold_wallet.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/paul/Bureau/BTC_WALLET/COLD_WALLET/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o -MF CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o.d -o CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o -c /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Transaction.cpp

CMakeFiles/cold_wallet.dir/src/Transaction.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cold_wallet.dir/src/Transaction.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Transaction.cpp > CMakeFiles/cold_wallet.dir/src/Transaction.cpp.i

CMakeFiles/cold_wallet.dir/src/Transaction.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cold_wallet.dir/src/Transaction.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Transaction.cpp -o CMakeFiles/cold_wallet.dir/src/Transaction.cpp.s

CMakeFiles/cold_wallet.dir/src/Utils.cpp.o: CMakeFiles/cold_wallet.dir/flags.make
CMakeFiles/cold_wallet.dir/src/Utils.cpp.o: ../src/Utils.cpp
CMakeFiles/cold_wallet.dir/src/Utils.cpp.o: CMakeFiles/cold_wallet.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/paul/Bureau/BTC_WALLET/COLD_WALLET/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/cold_wallet.dir/src/Utils.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/cold_wallet.dir/src/Utils.cpp.o -MF CMakeFiles/cold_wallet.dir/src/Utils.cpp.o.d -o CMakeFiles/cold_wallet.dir/src/Utils.cpp.o -c /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Utils.cpp

CMakeFiles/cold_wallet.dir/src/Utils.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cold_wallet.dir/src/Utils.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Utils.cpp > CMakeFiles/cold_wallet.dir/src/Utils.cpp.i

CMakeFiles/cold_wallet.dir/src/Utils.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cold_wallet.dir/src/Utils.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/Utils.cpp -o CMakeFiles/cold_wallet.dir/src/Utils.cpp.s

CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o: CMakeFiles/cold_wallet.dir/flags.make
CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o: ../src/WalletSecurity.cpp
CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o: CMakeFiles/cold_wallet.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/paul/Bureau/BTC_WALLET/COLD_WALLET/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o -MF CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o.d -o CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o -c /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/WalletSecurity.cpp

CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/WalletSecurity.cpp > CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.i

CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/paul/Bureau/BTC_WALLET/COLD_WALLET/src/WalletSecurity.cpp -o CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.s

# Object files for target cold_wallet
cold_wallet_OBJECTS = \
"CMakeFiles/cold_wallet.dir/src/main.cpp.o" \
"CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o" \
"CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o" \
"CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o" \
"CMakeFiles/cold_wallet.dir/src/Utils.cpp.o" \
"CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o"

# External object files for target cold_wallet
cold_wallet_EXTERNAL_OBJECTS =

cold_wallet: CMakeFiles/cold_wallet.dir/src/main.cpp.o
cold_wallet: CMakeFiles/cold_wallet.dir/src/Wallet.cpp.o
cold_wallet: CMakeFiles/cold_wallet.dir/src/KeyGeneration.cpp.o
cold_wallet: CMakeFiles/cold_wallet.dir/src/Transaction.cpp.o
cold_wallet: CMakeFiles/cold_wallet.dir/src/Utils.cpp.o
cold_wallet: CMakeFiles/cold_wallet.dir/src/WalletSecurity.cpp.o
cold_wallet: CMakeFiles/cold_wallet.dir/build.make
cold_wallet: /usr/lib/x86_64-linux-gnu/libcrypto.so
cold_wallet: /usr/lib/x86_64-linux-gnu/libssl.so
cold_wallet: /usr/lib/x86_64-linux-gnu/libcrypto.so
cold_wallet: CMakeFiles/cold_wallet.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/paul/Bureau/BTC_WALLET/COLD_WALLET/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking CXX executable cold_wallet"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/cold_wallet.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/cold_wallet.dir/build: cold_wallet
.PHONY : CMakeFiles/cold_wallet.dir/build

CMakeFiles/cold_wallet.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/cold_wallet.dir/cmake_clean.cmake
.PHONY : CMakeFiles/cold_wallet.dir/clean

CMakeFiles/cold_wallet.dir/depend:
	cd /home/paul/Bureau/BTC_WALLET/COLD_WALLET/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/paul/Bureau/BTC_WALLET/COLD_WALLET /home/paul/Bureau/BTC_WALLET/COLD_WALLET /home/paul/Bureau/BTC_WALLET/COLD_WALLET/build /home/paul/Bureau/BTC_WALLET/COLD_WALLET/build /home/paul/Bureau/BTC_WALLET/COLD_WALLET/build/CMakeFiles/cold_wallet.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/cold_wallet.dir/depend


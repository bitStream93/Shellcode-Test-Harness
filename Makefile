BINARY      := loader.exe
SRC_DIR     := loader
BUILD_DIR   := bin
SRC         := $(SRC_DIR)/loader.cc
TARGET      := $(BUILD_DIR)/$(BINARY)

# Flags 
LIBS        := -ladvapi32 -luser32 -lkernel32
CXXFLAGS    := -O2 -Wall -std=c++17 -static

# Arch 
ifeq ($(OS),Windows_NT)
    CXX = g++
    MKDIR = if not exist $(subst /,\,$(BUILD_DIR)) mkdir $(subst /,\,$(BUILD_DIR))
    RM = del /Q
    FIX_PATH = $(subst /,\,$(1))
else
    CXX = x86_64-w64-mingw32-g++
    MKDIR = mkdir -p $(BUILD_DIR)
    RM = rm -rf
    FIX_PATH = $(1)
endif


.PHONY: all clean setup

all: setup $(TARGET)

$(TARGET): $(SRC)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LIBS)
	@echo "[+] Build complete: $(TARGET)"

setup:
	@$(MKDIR)

clean:
	$(RM) $(call FIX_PATH,$(TARGET))

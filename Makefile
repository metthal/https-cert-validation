PROJECT=kry
CXX=g++
CXXFLAGS=-std=c++14 -Wall -Wextra
LXXFLAGS=-lboost_system -lpthread -ldl -lssl -lcrypto

BUILD_DIR=build

SOURCES=$(wildcard src/*.cpp)
OBJECTS=$(patsubst src/%.cpp,$(BUILD_DIR)/%.o,$(SOURCES))

RM=rm -rf
MKDIR=mkdir -p

release: build

debug: CXXFLAGS += -g
debug: build

build: build_dir build_step

build_dir:
	$(MKDIR) $(BUILD_DIR)

build_step: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(PROJECT) $^ $(LXXFLAGS)

$(BUILD_DIR)/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	$(RM) $(BUILD_DIR) $(PROJECT)

.PHONY: release debug build build_dir clean

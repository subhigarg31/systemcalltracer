CXX ?= clang++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -pthread
SRC_DIR = src
BIN_DIR = bin
TARGET = $(BIN_DIR)/syscall_tracer_sim

SRCS = $(SRC_DIR)/main.cpp $(SRC_DIR)/generator.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(SRC_DIR)/*.o $(TARGET)

.PHONY: all clean

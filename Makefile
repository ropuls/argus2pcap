
CXX=g++-7
CXXFLAGS = -std=c++17 -Wall -Iinclude -pthread -ggdb -I../include
LDFLAGS =  -ggdb -lpthread -pthread

all: a2w 
.PHONY: clean

clean: 
	@rm -fr bin
	@rm -fr obj

a2w: bin obj bin/a2w 

INC := $(wildcard include/*)
SRC := src/a2w.cpp src/pcap.cpp
OBJ := $(SRC:src/%.cpp=obj/%.o)


bin:
	@mkdir -p bin

obj:
	@mkdir -p obj

bin/a2w: $(OBJ)
	@echo "ld $< => $@"
	@$(CXX) $(LDFLAGS) $^ -o $@

$(OBJ): obj/%.o : src/%.cpp ${INC} 
	@echo "g++ $< => $@";
	@$(CXX) $(CXXFLAGS) -c $< -o $@


CXX = g++
CXXFLAGS = -Wall -O2
LIBS = -lpcap

all: csa-attack

csa-attack: main.cpp
	$(CXX) $(CXXFLAGS) -o csa-attack main.cpp $(LIBS)

clean:
	rm -f csa-attack

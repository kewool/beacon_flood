LDLIBS=-lpcap -lpthread

all: beacon-flood

beacon-flood: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o

clean:
	rm -f beacon-flood *.o

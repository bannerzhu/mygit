# Makefile
# author:cp
# time:2012-7-21

CC = gcc

BIN=dnsatt
INC = -I.
CFLAGS = -Wall -g -O2

SYS_DIGITS=$(shell getconf LONG_BIT)
ifeq ($(SYS_DIGITS),32)
	LIBS = -ldl -lpthread  -L/usr/lib/ -I /usr/include/libxml2/ -lxml2
else
	LIBS = -ldl -lpthread  -L/usr/lib64/ -I /usr/include/libxml2/ -lxml2
endif

all: $(BIN)

OBJECTS = maindnsatt.c attack.c packetdns.c xmlparse.c xmlctr.c packetTime.c dataList.c 
	
$(BIN):$(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(INC) $(LIBS)

clean:
	rm -f $(BIN)




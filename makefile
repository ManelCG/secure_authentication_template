BDIR = build
SDIR = src
KDIR = keys

IDIR = include
CC = gcc
CFLAGS = -I$(IDIR) -Wall -lssl -lcrypto

ODIR=obj
LDIR=lib

LIBS = -lm

_DEPS = crypto.h connection.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = crypto.o connection.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

_OBJ_cl = client.o
OBJ_cl = $(patsubst %,$(ODIR)/%,$(_OBJ_cl))

_OBJ_sv = server.o
OBJ_sv = $(patsubst %,$(ODIR)/%,$(_OBJ_sv))

$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	mkdir -p $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)

client: $(OBJ) $(OBJ_cl)
	mkdir -p $(BDIR)
	mkdir -p $(KDIR)
	$(CC) -o $(BDIR)/$@ $^ $(CFLAGS) $(LIBS)

server: $(OBJ) $(OBJ_sv)
	mkdir -p $(BDIR)
	mkdir -p $(KDIR)
	$(CC) -o $(BDIR)/$@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~

.PHONY: all
all: client server clean

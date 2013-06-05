CC=gcc
CFLAGS=-Wall -g

SRC=			\
	p2p_common.c	\
	p2p_file.c	\
	p2p_addr.c	\
	p2p_msg.c	\
	p2p_do_msg.c  \
	p2p_ui.c	\
	p2p_search.c \
	p2p_main.c

OBJ=$(SRC:.c=.o)
BIN=p2p_node

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@

%.o:%.c
	$(CC) -c $(CFLAGS) $< 

tar: clean
	(cd .. ; tar --exclude=src-dist/.svn -zcvf 3TC-P2P-sources.tgz src-dist ) 
clean:
	rm -f $(OBJ) $(BIN)

p2p_main.o: p2p_main.c p2p_common.h
p2p_addr.o: p2p_addr.c p2p_addr.h p2p_common.h
p2p_search.o: p2p_search.c p2p_search.h p2p_msg.h 	
p2p_msg.o:  p2p_msg.c p2p_msg.h p2p_addr.h p2p_common.h
p2p_common.o: p2p_common.c p2p_common.h
p2p_search.o: p2p_search.c p2p_common.h p2p_do_msg.h
p2p_do_msg.o: p2p_do_msg.c p2p_do_msg.h p2p_addr.h p2p_msg.h p2p_common.h
p2p_sharing.o : p2p_sharing.c p2p_sharing.h p2p_msg.h 

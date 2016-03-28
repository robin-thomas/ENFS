CC = g++
CLIENT = enfs_client
SERVER = enfs_server
TARGETS = $(CLIENT) $(SERVER)

CLIENT_c = enfs_client.cc rsa.cc client_fs.cc
CLIENT_h = rsa.h client_fs.h
SERVER_c = enfs_server.cc rsa.cc server_fs.cc
SERVER_h = rsa.h server_fs.h

# Compiler flags 
CPPFLAGS    = -g -Wall -D_FILE_OFFSET_BITS=64 -Wno-unused-variable -std=c++11
LDLIBS      = -ldl -lfuse -lssl -lcrypto -lpthread

# Targets
all: $(TARGETS)

$(CLIENT): $(CLIENT_c) $(CLIENT_h)
	$(CC) $(CPPFLAGS) -o $(CLIENT) $(CLIENT_c) $(CLIENT_h) $(LDLIBS)
$(SERVER): $(SERVER_c) $(SERVER_h)
	$(CC) $(CPPFLAGS) -o $(SERVER) $(SERVER_c) $(SERVER_h) $(LDLIBS)

# clean
clean:
	$(RM) $(TARGETS)


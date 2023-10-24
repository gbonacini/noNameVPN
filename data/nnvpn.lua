--[[ Flag:           address
     Type:           String representing IP address
     Synopsis:       Set value to specify listening address for server or remote server address for client
     Valid values:   A valid IPv4 address
--]]
address = "192.168.178.113"

--[[ Flag:           port
     Type:           uint16_t integer representing TCP port
     Synopsis:       Set value to specify listening port for server or remote server port for client
     Valid values:   A 16 bit number representing a valid TCP port
--]]
port = 8181

--[[ Flag:           cert
     Type:           String representing SSL cetificate full path
     Synopsis:       Set value to specify the SSL cetificate used to connect cliente/server full path
     Valid values:   A valid file system path pointing to a SSL cerificate
--]]
cert = "/home/test/vpn/.keys/server.pem"

--[[ Flag:           key
     Type:           String representing SSL key full path
     Synopsis:       Set value to specify the SSL key used to connect cliente/server full path
     Valid values:   A valid file system path pointing to a SSL key
--]]
key = "/home/test/vpn/.keys/server.key"

--[[ Flag:           device
     Type:           String representing TUN special device
     Synopsis:       Set value to specify the TUN Special device name
     Valid values:   A valid TUN device name composed by alphanumeric characters
--]]
device = "tun222"

--[[ Flag:           psize
     Type:           Number representing max payload size
     Valid values:   A multiple of 1500
--]]
psize = 1500

--[[ Flag:           log
     Type:           String representing log file full path
     Valid values:   A valid file system path writable for the user
--]]
log = "/home/test/vpn/nnvpn.log.txt"


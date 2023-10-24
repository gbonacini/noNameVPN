bin_PROGRAMS   = nnvpn
dist_man_MANS  = ../doc/nnvpn.1

nnvpn_SOURCES = nnvpn.cpp parseCmdLine.cpp debug.cpp configFile.cpp StringUtilsImpl.cpp TypesImpl.cpp capabilities.cpp inetclient.cpp inetserver.cpp inetTunTap.cpp inetgeneral.cpp  

nnvpn_CPPFLAGS         = ${LUA_INCLUDE}
nnvpn_LDADD            = ${LUA_LIB}

install-exec-hook:
	setcap cap_net_admin=ep  $(bindir)/nnvpn

g++ -std=c++17 -o mls_in_line_v11 mls_in_line_v11.cpp \
  -Imlspp/include \
  -Imlspp/lib/bytes/include \
  -Imlspp/lib/tls_syntax/include \
  -Imlspp/lib/hpke/include \
  -Ibpv7/include \
  -Iici/include \
  -Lmlspp/build \
  -Lmlspp/build/lib/bytes \
  -Lmlspp/build/lib/hpke \
  -Lmlspp/build/lib/tls_syntax \
  -Lbpv7/library \
  -Lici/library \
  -L/opt/homebrew/opt/openssl@3/lib \
  -lmlspp -lhpke -ltls_syntax -lbytes \
  -lbp  -lici \
  -lssl -lcrypto -ldl
    
    # g++ -std=c++17 -o mls_in_line_v11 mls_in_line_v11.cpp \
#   -Imlspp/include \
#   -Imlspp/lib/bytes/include \
#   -Imlspp/lib/tls_syntax/include \
#   -Imlspp/lib/hpke/include \
#   -Ibpv7/include \
#   -Iici/include \
#   -Lmlspp/build \
#   -Lmlspp/build/lib/bytes \
#   -Lmlspp/build/lib/hpke \
#   -Lmlspp/build/lib/tls_syntax \
#   -Lbpv7/library \
#   -Lici/library \
#   -L/opt/homebrew/opt/openssl@3/lib \
#   -lmlspp -lhpke -ltls_syntax -lbytes \
#   -lbp -lzco -lsdr -lion -lsec -lici \
#   -lssl -lcrypto -v
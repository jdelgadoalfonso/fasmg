; --- Offsets básicos ---
ETH_HLEN    = 14

; --- Campos IP (Offset desde el inicio del header IP) ---
IP_VERSION_IHL = 0
IP_TOS         = 1
IP_TOTAL_LEN   = 2
IP_ID          = 4
IP_FRAG_OFF    = 6
IP_TTL         = 8
IP_PROTO       = 9
IP_CHECKSUM    = 10
IP_SRC         = 12
IP_DST         = 16

; --- Campos TCP (Offset desde el inicio del header TCP) ---
TCP_SRC_PORT   = 0
TCP_DST_PORT   = 2
TCP_SEQ_NUM    = 4
TCP_ACK_NUM    = 8
TCP_DATA_OFF   = 12 ; Incluye Flags

; Carga un campo de IP (IPv4)
; Uso: ld_ip_field r0, r1, IP_SRC
macro ld_ip_field dst, src, field
    if field = IP_SRC | field = IP_DST
        ld_hdr_swap w, dst, src, (ETH_HLEN + field)
    else if field = IP_TOTAL_LEN | field = IP_ID
        ld_hdr_swap h, dst, src, (ETH_HLEN + field)
    else
        ld_hdr_swap b, dst, src, (ETH_HLEN + field)
    end if
end macro

; Carga un campo de TCP
; Uso: ld_tcp_field r0, r1, TCP_DST_PORT
macro ld_tcp_field dst, src, field
    ; TCP empieza tras Ethernet (14) + Header IP minimo (20) = 34
    ld_hdr_swap h, dst, src, (34 + field)
end macro

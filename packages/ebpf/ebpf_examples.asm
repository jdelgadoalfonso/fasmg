; =============================================================================
; ebpf_examples.asm  —  Ejemplos de uso de ebpf_jit.inc para fasmg g.l5p0
; SINTAXIS ESTILO x86
; =============================================================================
; Ensamblar:
;   fasmg ebpf_examples.asm ebpf_examples.o
; =============================================================================

include '../x86/include/format/elf64.inc'
include 'ebpf_jit.inc'

; =============================================================================
; EJEMPLO 1 — xdp_pass
; -----------------------------------------------------------------------------
; Programa XDP minimo: acepta todos los paquetes devolviendo XDP_PASS (2).
; =============================================================================

section '.xdp_pass' writeable

public xdp_pass_prog
public xdp_pass_prog_end

xdp_pass_prog:

    mov r0, XDP_PASS            ; r0 = 2
    ret                         ; return r0

xdp_pass_prog_end:


; =============================================================================
; EJEMPLO 2 — tc_count_pkts
; -----------------------------------------------------------------------------
; Filtro TC que incrementa atomicamente un contador en un mapa ARRAY[0]
; y devuelve TC_ACT_OK. El loader parchea el fd del mapa antes de cargar.
; =============================================================================

section '.tc_count' writeable

public tc_count_prog
public tc_count_prog_end

tc_count_prog:

    ; r6 = fd del mapa (loader parchea imm con fd real)
    ld_map_fd  r6, 0

    ; *(u32*)(r10 - 4) = 0   <-  key = 0 en la pila BPF
    st_mem     w, r10, -4, 0

    ; bpf_map_lookup_elem(r6, &key)
    mov r1, r6                  ; Se detecta automáticamente que r6 es un registro
    mov r2, r10
    add r2, -4                  ; Se detecta automáticamente que -4 es inmediato
    call BPF_FUNC_map_lookup_elem

    ; if (r0 == NULL) goto .ret_ok
    cmp r0, 0
    je .ret_ok

    ; r7 = puntero al valor en el mapa (callee-saved)
    mov r7, r0

    ; *(u64*)(r7 + 0) += 1  (atomico)
    mov r1, 1
    ;atomic_op  BPF_DW, BPF_XADD, r7, r1, 0
    stx_mem     BPF_DW, r7, r1, 0

  .ret_ok:
    mov r0, TC_ACT_OK
    ret

tc_count_prog_end:


; =============================================================================
; EJEMPLO 3 — sockfilter_len
; -----------------------------------------------------------------------------
; Filtro de socket que descarta paquetes menores de 64 bytes.
; =============================================================================

section '.sockfilter' writeable

public sockfilter_prog
public sockfilter_prog_end

SKB_LEN_OFF = 0
MIN_LEN     = 64

sockfilter_prog:

    ; r0 = skb->len (u32, offset 0 en el contexto BPF)
    ldx_mem w, r0, r1, SKB_LEN_OFF

    ; if (r0 >= MIN_LEN) goto .pass
    cmp r0, MIN_LEN
    jge .pass

    ; paquete corto: descartar
    mov r0, 0

  .pass:
    ret

sockfilter_prog_end:


; =============================================================================
; EJEMPLO 4 — jit_thunk  (codigo nativo x86-64)
; -----------------------------------------------------------------------------
; NOTA: Como estamos emitiendo x86 crudo y r0-r10 ahora son elementos tipados
; eBPF, usamos directamente BPF_REG_X para pasar numeros puros a las macros x86.
; =============================================================================

section '.text' executable

public jit_thunk

jit_thunk:

    jit_prologue  BPF_MAX_STACK

    ; r6 = r1  →  mov rbx, rdi
    emit_alu64_mov      BPF_REG_6, BPF_REG_1

    ; r6 += 100  →  mov r10, 100 / add rbx, r10
    emit_alu64_mov_imm  BPF_REG_AX, 100
    emit_alu64_add      BPF_REG_6, BPF_REG_AX

    ; if r6 != 200 goto .exit
    emit_cmp64_imm      BPF_REG_6, 200
    emit_jne_rel32      (.jit_exit - $ - 4)

    ; *(u64*)(rbp - 8) = rbx
    emit_stx_mem_dw     BPF_REG_10, -8, BPF_REG_6

    ; r0 = 1
    emit_alu64_mov_imm  BPF_REG_0, 1

  .jit_exit:
    jit_epilogue


; =============================================================================
; EJEMPLO 5 — bswap_demo  (codigo nativo x86-64)
; =============================================================================

section '.text' executable

public bswap_demo

bswap_demo:

    jit_prologue  64

    ; r0 = r1  →  mov rax, rdi
    emit_alu64_mov   BPF_REG_0, BPF_REG_1

    ; bswap rax
    emit_bswap64     BPF_REG_0

    jit_epilogue


; =============================================================================
; TABLA DE METADATOS para el loader en C
; =============================================================================

section '.rodata' writeable

public prog_table

prog_table:

    qword  xdp_pass_prog
    qword  xdp_pass_prog_end
    dd     BPF_PROG_TYPE_XDP
    dd     0

    qword  tc_count_prog
    qword  tc_count_prog_end
    dd     BPF_PROG_TYPE_SCHED_CLS
    dd     0

    qword  sockfilter_prog
    qword  sockfilter_prog_end
    dd     BPF_PROG_TYPE_SOCKET_FILTER
    dd     0

prog_table_end:


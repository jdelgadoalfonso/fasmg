; =============================================================================
; ebpf_jit.inc  —  Soporte de arquitectura JIT eBPF para fasmg g.l5p0
; =============================================================================
; Uso en el archivo principal:
;   include 'packages/x86/include/format/elf64.inc'
;   include 'packages/x86/include/cpu/x64.inc'
;   include 'packages/ebpf/ebpf_jit.inc'
;
; Referencias del kernel Linux:
;   linux/arch/x86/net/bpf_jit_comp.c
;   linux/include/uapi/linux/bpf.h
;   linux/include/linux/filter.h
; =============================================================================

; =============================================================================
; CLASES DE INSTRUCCION eBPF
; =============================================================================

BPF_LD    = 0x00
BPF_LDX   = 0x01
BPF_ST    = 0x02
BPF_STX   = 0x03
BPF_ALU   = 0x04
BPF_JMP   = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

; Modificadores de tamanyo
BPF_W   = 0x00
BPF_H   = 0x08
BPF_B   = 0x10
BPF_DW  = 0x18

; Modos de acceso a memoria
BPF_IMM    = 0x00
BPF_ABS    = 0x20
BPF_IND    = 0x40
BPF_MEM    = 0x60
BPF_ATOMIC = 0xC0

; Operaciones ALU
BPF_ADD  = 0x00
BPF_SUB  = 0x10
BPF_MUL  = 0x20
BPF_DIV  = 0x30
BPF_OR   = 0x40
BPF_AND  = 0x50
BPF_LSH  = 0x60
BPF_RSH  = 0x70
BPF_NEG  = 0x80
BPF_MOD  = 0x90
BPF_XOR  = 0xA0
BPF_MOV  = 0xB0
BPF_ARSH = 0xC0
BPF_END  = 0xD0

; Operaciones de salto
BPF_JA   = 0x00
BPF_JEQ  = 0x10
BPF_JGT  = 0x20
BPF_JGE  = 0x30
BPF_JSET = 0x40
BPF_JNE  = 0x50
BPF_JSGT = 0x60
BPF_JSGE = 0x70
BPF_CALL = 0x80
BPF_EXIT = 0x90
BPF_JLT  = 0xA0
BPF_JLE  = 0xB0
BPF_JSLT = 0xC0
BPF_JSLE = 0xD0

; Fuente del operando
BPF_K = 0x00
BPF_X = 0x08

; Operaciones atomicas (campo imm)
BPF_XADD    = 0x01
BPF_XAND    = 0x52
BPF_XCHG    = 0xE1
BPF_CMPXCHG = 0xF1


; =============================================================================
; REGISTROS VIRTUALES eBPF
; =============================================================================

BPF_REG_0  = 0
BPF_REG_1  = 1
BPF_REG_2  = 2
BPF_REG_3  = 3
BPF_REG_4  = 4
BPF_REG_5  = 5
BPF_REG_6  = 6
BPF_REG_7  = 7
BPF_REG_8  = 8
BPF_REG_9  = 9
BPF_REG_10 = 10
BPF_REG_AX = 11


; =============================================================================
; MAPEO BPF -> x86-64  (JIT de Linux)
; BPF_REG_0  -> rax (0)    BPF_REG_6  -> rbx (3)
; BPF_REG_1  -> rdi (7)    BPF_REG_7  -> r13 (13)
; BPF_REG_2  -> rsi (6)    BPF_REG_8  -> r14 (14)
; BPF_REG_3  -> rdx (2)    BPF_REG_9  -> r15 (15)
; BPF_REG_4  -> rcx (1)    BPF_REG_10 -> rbp (5)
; BPF_REG_5  -> r8  (8)    BPF_REG_AX -> r10 (10)
; =============================================================================

; calminstruction que resuelve el numero de registro x86-64
; a partir del numero de registro BPF, en tiempo de ensamblado.
calminstruction bpf2x86 bpf*
    check bpf = 0
    jyes reg0
    check bpf = 1
    jyes reg1
    check bpf = 2
    jyes reg2
    check bpf = 3
    jyes reg3
    check bpf = 4
    jyes reg4
    check bpf = 5
    jyes reg5
    check bpf = 6
    jyes reg6
    check bpf = 7
    jyes reg7
    check bpf = 8
    jyes reg8
    check bpf = 9
    jyes reg9
    check bpf = 10
    jyes reg10
    check bpf = 11
    jyes reg11
    err 'bpf2x86: registro BPF invalido (0-11)'
    exit
  reg0:
    compute bpf, 0
    exit   ; rax
  reg1:
    compute bpf, 7
    exit   ; rdi
  reg2:
    compute bpf, 6
    exit   ; rsi
  reg3:
    compute bpf, 2
    exit   ; rdx
  reg4:
    compute bpf, 1
    exit   ; rcx
  reg5:
    compute bpf, 8
    exit   ; r8
  reg6:
    compute bpf, 3
    exit   ; rbx
  reg7:
    compute bpf, 13
    exit   ; r13
  reg8:
    compute bpf, 14
    exit   ; r14
  reg9:
    compute bpf, 15
    exit   ; r15
  reg10:
    compute bpf, 5
    exit   ; rbp
  reg11:
    compute bpf, 10
    exit   ; r10
end calminstruction

; =============================================================================
; MACRO BASE: emite una instruccion eBPF de 64 bits
;
;   BPF_INSN opcode, dst, src, offset, imm
;
;   Layout (little-endian, 8 bytes):
;     [0]   opcode
;     [1]   dst[3:0] | src[7:4]
;     [2-3] offset s16
;     [4-7] imm    s32
; =============================================================================

macro BPF_INSN? op, dst, src, off, imm
    db  op
    db  (dst and 0xF) or ((src and 0xF) shl 4)
    dw  off
    dd  imm
end macro

macro BPF_CALL_FUNC? func_id
    local opcode
    opcode = BPF_JMP or BPF_CALL
    BPF_INSN opcode, 0, 0, 0, func_id
end macro

; =============================================================================
; MACROS DE BYTECODE eBPF (alto nivel)
; =============================================================================

macro BPF_ALU64_REG? op, dst, src
    BPF_INSN (BPF_ALU64 or op or BPF_X), dst, src, 0, 0
end macro

macro BPF_ALU64_IMM? op, dst, imm
    BPF_INSN (BPF_ALU64 or op or BPF_K), dst, 0, 0, imm
end macro

macro BPF_ALU32_REG? op, dst, src
    BPF_INSN (BPF_ALU or op or BPF_X), dst, src, 0, 0
end macro

macro BPF_ALU32_IMM? op, dst, imm
    BPF_INSN (BPF_ALU or op or BPF_K), dst, 0, 0, imm
end macro

macro BPF_MOV64_REG? dst, src
    BPF_INSN (BPF_ALU64 or BPF_MOV or BPF_X), dst, src, 0, 0
end macro

macro BPF_MOV64_IMM? dst, imm
    BPF_INSN (BPF_ALU64 or BPF_MOV or BPF_K), dst, 0, 0, imm
end macro

macro BPF_MOV32_IMM? dst, imm
    BPF_INSN (BPF_ALU or BPF_MOV or BPF_K), dst, 0, 0, imm
end macro

; Carga inmediata de 64 bits — emite DOS instrucciones de 8 bytes
macro BPF_LD_IMM64? dst, imm64
    BPF_INSN (BPF_LD or BPF_DW or BPF_IMM), dst, 0, 0, (imm64 and 0xFFFFFFFF)
    BPF_INSN 0, 0, 0, 0, ((imm64 shr 32) and 0xFFFFFFFF)
end macro

; Referencia a fd de mapa (src_reg = 1 = BPF_PSEUDO_MAP_FD)
macro BPF_LD_MAP_FD? dst, map_fd
    BPF_INSN (BPF_LD or BPF_DW or BPF_IMM), dst, 1, 0, map_fd
    BPF_INSN 0, 0, 0, 0, 0
end macro

macro BPF_LDX_MEM? sz, dst, src, off
    BPF_INSN (BPF_LDX or sz or BPF_MEM), dst, src, off, 0
end macro

macro BPF_STX_MEM? sz, dst, src, off
    BPF_INSN (BPF_STX or sz or BPF_MEM), dst, src, off, 0
end macro

macro BPF_ST_MEM? sz, dst, off, imm
    BPF_INSN (BPF_ST or sz or BPF_MEM), dst, 0, off, imm
end macro

; =============================================================================
; MACROS DE SALTO (Corregidas para mayor estabilidad de cálculo de offset)
; =============================================================================

macro BPF_JMP_REG? op, dst, src, target
    if target relativeto 0
        ; Si le pasas un número absoluto (ej. 3), úsalo directamente
        BPF_INSN (BPF_JMP or op or BPF_X), dst, src, target, 0
    else
        ; Si le pasas una etiqueta, calcula la distancia
        BPF_INSN (BPF_JMP or op or BPF_X), dst, src, (target - $) / 8, 0
    end if
end macro

macro BPF_JMP_IMM? op, dst, imm, target
    if target relativeto 0
        BPF_INSN (BPF_JMP or op or BPF_K), dst, 0, target, imm
    else
        BPF_INSN (BPF_JMP or op or BPF_K), dst, 0, (target - $) / 8, imm
    end if
end macro

macro BPF_JMP32_REG? op, dst, src, target
    if target relativeto 0
        BPF_INSN (BPF_JMP32 or op or BPF_X), dst, src, target, 0
    else
        BPF_INSN (BPF_JMP32 or op or BPF_X), dst, src, (target - $) / 8, 0
    end if
end macro

macro BPF_JMP32_IMM? op, dst, imm, target
    if target relativeto 0
        BPF_INSN (BPF_JMP32 or op or BPF_K), dst, 0, target, imm
    else
        BPF_INSN (BPF_JMP32 or op or BPF_K), dst, 0, (target - $) / 8, imm
    end if
end macro

macro BPF_JMP_A? target
    if target relativeto 0
        BPF_INSN (BPF_JMP or BPF_JA), 0, 0, target, 0
    else
        BPF_INSN (BPF_JMP or BPF_JA), 0, 0, (target - $) / 8, 0
    end if
end macro

macro BPF_CALL_FUNC? func_id
    BPF_INSN (BPF_JMP or BPF_CALL), 0, 0, 0, func_id
end macro

; =============================================================================
; MACRO PARA LLAMADAS LOCALES (BPF-to-BPF)
; src_reg = 1 (BPF_PSEUDO_CALL)
; El offset va en el campo 'imm' de 32-bits, no en el campo 'offset' de 16-bits
; =============================================================================

BPF_PSEUDO_CALL = 1
macro BPF_CALL_LOCAL? target
    if target relativeto 0
        ; Si le pasas un número absoluto de instrucciones
        BPF_INSN (BPF_JMP or BPF_CALL), 0, BPF_PSEUDO_CALL, 0, target
    else
        ; Si le pasas el nombre de una etiqueta (calcula la distancia)
        BPF_INSN (BPF_JMP or BPF_CALL), 0, BPF_PSEUDO_CALL, 0, (target - $) / 8
    end if
end macro

macro BPF_EXIT_INSN?
    BPF_INSN (BPF_JMP or BPF_EXIT), 0, 0, 0, 0
end macro

macro BPF_ATOMIC_OP? sz, op, dst, src, off
    BPF_INSN (BPF_STX or sz or BPF_ATOMIC), dst, src, off, op
end macro


; =============================================================================
; CAPA JIT x86-64: prologo y epilogo
; Replica emit_prologue / emit_epilogue de arch/x86/net/bpf_jit_comp.c
; =============================================================================

macro JIT_PROLOGUE? stack_depth
    db 0x53                    ; push rbx
    db 0x5D                    ; push r13
    db 0x5E                    ; push r14
    db 0x5F                    ; push r15
    db 0x55                    ; push rbp
    db 0x48, 0x89, 0xE5        ; mov rbp, rsp
    db 0x48, 0x83, 0xEC        ; sub rsp, imm32
    dd stack_depth
    db 0x31, 0xC0              ; xor eax, eax
end macro

macro JIT_EPILOGUE?
    db 0x48, 0x89, 0xEC        ; mov rsp, rbp
    db 0x5D                    ; pop rbp
    db 0x5F                    ; pop r15
    db 0x5E                    ; pop r14
    db 0x5D                    ; pop r13
    db 0x5B                    ; pop rbx
    db 0xC3                    ; ret
end macro


; =============================================================================
; CAPA JIT x86-64: emision de instrucciones ALU64
;
; Convenio de codificacion x86-64:
;   REX.W = 0x48 | (dst_num shr 3) | ((src_num shr 3) shl 2)
;   ModRM  = 0xC0 | ((src_num and 7) shl 3) | (dst_num and 7)
;
; Para instrucciones "store" (opcode 01h/09h/21h/29h/31h/89h):
;   el campo reg de ModRM lleva src, el campo r/m lleva dst.
; =============================================================================

calminstruction EMIT_ALU64_ADD? dst, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex,   0x48 or (d shr 3) or ((s shr 3) shl 2)
    compute modrm, 0xC0 or ((s and 7) shl 3) or (d and 7)
    emit 1, rex
    emit 1, 0x01
    emit 1, modrm
end calminstruction

calminstruction EMIT_ALU64_SUB? dst, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex,   0x48 or (d shr 3) or ((s shr 3) shl 2)
    compute modrm, 0xC0 or ((s and 7) shl 3) or (d and 7)
    emit 1, rex
    emit 1, 0x29
    emit 1, modrm
end calminstruction

calminstruction EMIT_ALU64_AND? dst, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex,   0x48 or (d shr 3) or ((s shr 3) shl 2)
    compute modrm, 0xC0 or ((s and 7) shl 3) or (d and 7)
    emit 1, rex
    emit 1, 0x21
    emit 1, modrm
end calminstruction

calminstruction EMIT_ALU64_OR? dst, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex,   0x48 or (d shr 3) or ((s shr 3) shl 2)
    compute modrm, 0xC0 or ((s and 7) shl 3) or (d and 7)
    emit 1, rex
    emit 1, 0x09
    emit 1, modrm
end calminstruction

calminstruction EMIT_ALU64_XOR? dst, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex,   0x48 or (d shr 3) or ((s shr 3) shl 2)
    compute modrm, 0xC0 or ((s and 7) shl 3) or (d and 7)
    emit 1, rex
    emit 1, 0x31
    emit 1, modrm
end calminstruction

calminstruction EMIT_ALU64_MOV? dst, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex,   0x48 or (d shr 3) or ((s shr 3) shl 2)
    compute modrm, 0xC0 or ((s and 7) shl 3) or (d and 7)
    emit 1, rex
    emit 1, 0x89
    emit 1, modrm
end calminstruction

; MOV r64, imm32 (sign-extended)  —  REX.W C7 /0 id
calminstruction EMIT_ALU64_MOV_IMM? dst, imm
    local d, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
    compute rex,   0x48 or (d shr 3)
    compute modrm, 0xC0 or (d and 7)
    emit 1, rex
    emit 1, 0xC7
    emit 1, modrm
    emit 4, imm
end calminstruction

; XOR r32, r32  (zero-extiende a 64 bits)  —  REX? 31 /r
calminstruction EMIT_ALU32_XOR? dst, src
    local d, s, rex_val, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute modrm, 0xC0 or ((s and 7) shl 3) or (d and 7)
    compute rex_val, (d shr 3) or ((s shr 3) shl 2)
    check rex_val <> 0
    jyes with_rex
    emit 1, 0x31
    emit 1, modrm
    exit
  with_rex:
    emit 1, (0x40 or rex_val)
    emit 1, 0x31
    emit 1, modrm
end calminstruction


; =============================================================================
; CAPA JIT x86-64: comparaciones
; =============================================================================

; CMP r64_dst, r64_src  —  REX.W 39 /r
calminstruction EMIT_CMP64? dst, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex,   0x48 or (d shr 3) or ((s shr 3) shl 2)
    compute modrm, 0xC0 or ((s and 7) shl 3) or (d and 7)
    emit 1, rex
    emit 1, 0x39
    emit 1, modrm
end calminstruction

; CMP r64, imm8/imm32  —  REX.W 83/F8+r ib  o  REX.W 81/F8+r id
calminstruction EMIT_CMP64_IMM? dst, imm
    local d, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
    compute rex,   0x48 or (d shr 3)
    compute modrm, 0xF8 or (d and 7)
    emit 1, rex
    check imm >= -128 & imm <= 127
    jyes use_imm8
    emit 1, 0x81
    emit 1, modrm
    emit 4, imm
    exit
  use_imm8:
    emit 1, 0x83
    emit 1, modrm
    emit 1, imm
end calminstruction


; =============================================================================
; CAPA JIT x86-64: saltos (rel32)
; El desplazamiento rel32 es relativo al primer byte TRAS el ultimo byte
; de la instruccion de salto (convenio Intel estandar).
; =============================================================================

macro EMIT_JMP_REL32?  rel  ;  JMP rel32
    db 0xE9
    dd rel
end macro

macro EMIT_JEQ_REL32?  rel  ;  JE  rel32
    db 0x0F, 0x84
    dd rel
end macro

macro EMIT_JNE_REL32?  rel  ;  JNZ rel32
    db 0x0F, 0x85
    dd rel
end macro

macro EMIT_JGT_REL32?  rel  ;  JA  rel32  (unsigned >)
    db 0x0F, 0x87
    dd rel
end macro

macro EMIT_JGE_REL32?  rel  ;  JAE rel32  (unsigned >=)
    db 0x0F, 0x83
    dd rel
end macro

macro EMIT_JLT_REL32?  rel  ;  JB  rel32  (unsigned <)
    db 0x0F, 0x82
    dd rel
end macro

macro EMIT_JLE_REL32?  rel  ;  JBE rel32  (unsigned <=)
    db 0x0F, 0x86
    dd rel
end macro

macro EMIT_JSGT_REL32? rel  ;  JG  rel32  (signed >)
    db 0x0F, 0x8F
    dd rel
end macro

macro EMIT_JSGE_REL32? rel  ;  JGE rel32  (signed >=)
    db 0x0F, 0x8D
    dd rel
end macro

macro EMIT_JSLT_REL32? rel  ;  JL  rel32  (signed <)
    db 0x0F, 0x8C
    dd rel
end macro

macro EMIT_JSLE_REL32? rel  ;  JLE rel32  (signed <=)
    db 0x0F, 0x8E
    dd rel
end macro

macro EMIT_CALL_REL32? rel  ;  CALL rel32
    db 0xE8
    dd rel
end macro

; CALL con placeholder — parchado en carga por el JIT del kernel
macro EMIT_BPF_CALL?
    db 0xE8
    dd 0x00000000
end macro


; =============================================================================
; CAPA JIT x86-64: memoria (load / store con desplazamiento)
; =============================================================================

; MOV [r64_dst + off], r64_src  —  REX.W 89 /r disp8/32
calminstruction EMIT_STX_MEM_DW? dst, off, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex, 0x48 or (d shr 3) or ((s shr 3) shl 2)
    emit 1, rex
    emit 1, 0x89
    check off >= -128 & off <= 127
    jyes  disp8
    compute modrm, 0x80 or ((s and 7) shl 3) or (d and 7)
    emit 1, modrm
    check (d and 7) = 4
    jno   no_sib32
    emit 1, 0x24
  no_sib32:
    emit 4, off
    exit
  disp8:
    compute modrm, 0x40 or ((s and 7) shl 3) or (d and 7)
    emit 1, modrm
    check (d and 7) = 4
    jno   no_sib8
    emit 1, 0x24
  no_sib8:
    emit 1, off
end calminstruction

; MOV r64_dst, [r64_src + off]  —  REX.W 8B /r disp8/32
calminstruction EMIT_LDX_MEM_DW? dst, src, off
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex, 0x48 or (s shr 3) or ((d shr 3) shl 2)
    emit 1, rex
    emit 1, 0x8B
    check off >= -128 & off <= 127
    jyes  disp8
    compute modrm, 0x80 or ((d and 7) shl 3) or (s and 7)
    emit 1, modrm
    check (s and 7) = 4
    jno   no_sib32
    emit 1, 0x24
  no_sib32:
    emit 4, off
    exit
  disp8:
    compute modrm, 0x40 or ((d and 7) shl 3) or (s and 7)
    emit 1, modrm
    check (s and 7) = 4
    jno   no_sib8
    emit 1, 0x24
  no_sib8:
    emit 1, off
end calminstruction


; =============================================================================
; CAPA JIT x86-64: operaciones atomicas
; =============================================================================

; LOCK ADD [r64_dst + off], r64_src
calminstruction EMIT_ATOMIC_XADD_DW? dst, off, src
    local d, s, rex, modrm
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
        check src = 0
        jyes s_is_0
        check src = 1
        jyes s_is_1
        check src = 2
        jyes s_is_2
        check src = 3
        jyes s_is_3
        check src = 4
        jyes s_is_4
        check src = 5
        jyes s_is_5
        check src = 6
        jyes s_is_6
        check src = 7
        jyes s_is_7
        check src = 8
        jyes s_is_8
        check src = 9
        jyes s_is_9
        check src = 10
        jyes s_is_10
        compute s, 10
        jump s_done
      s_is_0:
        compute s, 0
        jump s_done
      s_is_1:
        compute s, 7
        jump s_done
      s_is_2:
        compute s, 6
        jump s_done
      s_is_3:
        compute s, 2
        jump s_done
      s_is_4:
        compute s, 1
        jump s_done
      s_is_5:
        compute s, 8
        jump s_done
      s_is_6:
        compute s, 3
        jump s_done
      s_is_7:
        compute s, 13
        jump s_done
      s_is_8:
        compute s, 14
        jump s_done
      s_is_9:
        compute s, 15
        jump s_done
      s_is_10:
        compute s, 5
      s_done:
    compute rex, 0x48 or (d shr 3) or ((s shr 3) shl 2)
    emit 1, 0xF0
    emit 1, rex
    emit 1, 0x01
    check off >= -128 & off <= 127
    jyes  disp8
    compute modrm, 0x80 or ((s and 7) shl 3) or (d and 7)
    emit 1, modrm
    check (d and 7) = 4
    jno   no_sib32
    emit 1, 0x24
  no_sib32:
    emit 4, off
    exit
  disp8:
    compute modrm, 0x40 or ((s and 7) shl 3) or (d and 7)
    emit 1, modrm
    check (d and 7) = 4
    jno   no_sib8
    emit 1, 0x24
  no_sib8:
    emit 1, off
end calminstruction


; =============================================================================
; CAPA JIT x86-64: intercambio de endianness
; =============================================================================

; BSWAP r64  —  REX.W 0F C8+rd
calminstruction EMIT_BSWAP64? dst
    local d
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
    emit 1, (0x48 or (d shr 3))
    emit 1, 0x0F
    emit 1, (0xC8 or (d and 7))
end calminstruction

; BSWAP r32  —  (REX?) 0F C8+rd
calminstruction EMIT_BSWAP32? dst
    local d
        check dst = 0
        jyes d_is_0
        check dst = 1
        jyes d_is_1
        check dst = 2
        jyes d_is_2
        check dst = 3
        jyes d_is_3
        check dst = 4
        jyes d_is_4
        check dst = 5
        jyes d_is_5
        check dst = 6
        jyes d_is_6
        check dst = 7
        jyes d_is_7
        check dst = 8
        jyes d_is_8
        check dst = 9
        jyes d_is_9
        check dst = 10
        jyes d_is_10
        compute d, 10
        jump d_done
      d_is_0:
        compute d, 0
        jump d_done
      d_is_1:
        compute d, 7
        jump d_done
      d_is_2:
        compute d, 6
        jump d_done
      d_is_3:
        compute d, 2
        jump d_done
      d_is_4:
        compute d, 1
        jump d_done
      d_is_5:
        compute d, 8
        jump d_done
      d_is_6:
        compute d, 3
        jump d_done
      d_is_7:
        compute d, 13
        jump d_done
      d_is_8:
        compute d, 14
        jump d_done
      d_is_9:
        compute d, 15
        jump d_done
      d_is_10:
        compute d, 5
      d_done:
    check d >= 8
    jyes  need_rex
    emit 1, 0x0F
    emit 1, (0xC8 or (d and 7))
    exit
  need_rex:
    emit 1, 0x41
    emit 1, 0x0F
    emit 1, (0xC8 or (d and 7))
end calminstruction


; =============================================================================
; CONSTANTES GENERALES
; =============================================================================

BPF_MAX_STACK = 512

; Codigos de retorno XDP
XDP_ABORTED  = 0
XDP_DROP     = 1
XDP_PASS     = 2
XDP_TX       = 3
XDP_REDIRECT = 4

; Codigos de retorno TC
TC_ACT_UNSPEC   = -1
TC_ACT_OK       = 0
TC_ACT_SHOT     = 2
TC_ACT_STOLEN   = 4
TC_ACT_REDIRECT = 7

; =============================================================================
; TIPOS DE PROGRAMA  (enum bpf_prog_type)
; =============================================================================

BPF_PROG_TYPE_UNSPEC              = 0
BPF_PROG_TYPE_SOCKET_FILTER       = 1
BPF_PROG_TYPE_KPROBE              = 2
BPF_PROG_TYPE_SCHED_CLS           = 3
BPF_PROG_TYPE_SCHED_ACT           = 4
BPF_PROG_TYPE_TRACEPOINT          = 5
BPF_PROG_TYPE_XDP                 = 6
BPF_PROG_TYPE_PERF_EVENT          = 7
BPF_PROG_TYPE_CGROUP_SKB          = 8
BPF_PROG_TYPE_CGROUP_SOCK         = 9
BPF_PROG_TYPE_LWT_IN              = 10
BPF_PROG_TYPE_LWT_OUT             = 11
BPF_PROG_TYPE_LWT_XMIT            = 12
BPF_PROG_TYPE_SOCK_OPS            = 13
BPF_PROG_TYPE_SK_SKB              = 14
BPF_PROG_TYPE_CGROUP_DEVICE       = 15
BPF_PROG_TYPE_SK_MSG              = 16
BPF_PROG_TYPE_RAW_TRACEPOINT      = 17
BPF_PROG_TYPE_CGROUP_SOCK_ADDR    = 18
BPF_PROG_TYPE_LWT_SEG6LOCAL       = 19
BPF_PROG_TYPE_LIRC_MODE2          = 20
BPF_PROG_TYPE_SK_REUSEPORT        = 21
BPF_PROG_TYPE_FLOW_DISSECTOR      = 22
BPF_PROG_TYPE_CGROUP_SYSCTL       = 23
BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24
BPF_PROG_TYPE_CGROUP_SOCKOPT      = 25
BPF_PROG_TYPE_TRACING             = 26
BPF_PROG_TYPE_STRUCT_OPS          = 27
BPF_PROG_TYPE_EXT                 = 28
BPF_PROG_TYPE_LSM                 = 29
BPF_PROG_TYPE_SK_LOOKUP           = 30
BPF_PROG_TYPE_SYSCALL             = 31
BPF_PROG_TYPE_NETFILTER           = 32

; =============================================================================
; TIPOS DE MAPA  (enum bpf_map_type)
; =============================================================================

BPF_MAP_TYPE_UNSPEC               = 0
BPF_MAP_TYPE_HASH                 = 1
BPF_MAP_TYPE_ARRAY                = 2
BPF_MAP_TYPE_PROG_ARRAY           = 3
BPF_MAP_TYPE_PERF_EVENT_ARRAY     = 4
BPF_MAP_TYPE_PERCPU_HASH          = 5
BPF_MAP_TYPE_PERCPU_ARRAY         = 6
BPF_MAP_TYPE_STACK_TRACE          = 7
BPF_MAP_TYPE_CGROUP_ARRAY         = 8
BPF_MAP_TYPE_LRU_HASH             = 9
BPF_MAP_TYPE_LRU_PERCPU_HASH      = 10
BPF_MAP_TYPE_LPM_TRIE             = 11
BPF_MAP_TYPE_ARRAY_OF_MAPS        = 12
BPF_MAP_TYPE_HASH_OF_MAPS         = 13
BPF_MAP_TYPE_DEVMAP               = 14
BPF_MAP_TYPE_SOCKMAP              = 15
BPF_MAP_TYPE_CPUMAP               = 16
BPF_MAP_TYPE_XSKMAP               = 17
BPF_MAP_TYPE_SOCKHASH             = 18
BPF_MAP_TYPE_CGROUP_STORAGE       = 19
BPF_MAP_TYPE_REUSEPORT_SOCKARRAY  = 20
BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE= 21
BPF_MAP_TYPE_QUEUE                = 22
BPF_MAP_TYPE_STACK                = 23
BPF_MAP_TYPE_SK_STORAGE           = 24
BPF_MAP_TYPE_DEVMAP_HASH          = 25
BPF_MAP_TYPE_STRUCT_OPS           = 26
BPF_MAP_TYPE_RINGBUF              = 27
BPF_MAP_TYPE_INODE_STORAGE        = 28
BPF_MAP_TYPE_TASK_STORAGE         = 29
BPF_MAP_TYPE_BLOOM_FILTER         = 30
BPF_MAP_TYPE_USER_RINGBUF         = 31
BPF_MAP_TYPE_CGRP_STORAGE         = 32

; =============================================================================
; IDs DE HELPERS  (enum bpf_func_id)
; =============================================================================

BPF_FUNC_unspec                   = 0
BPF_FUNC_map_lookup_elem          = 1
BPF_FUNC_map_update_elem          = 2
BPF_FUNC_map_delete_elem          = 3
BPF_FUNC_probe_read               = 4
BPF_FUNC_ktime_get_ns             = 5
BPF_FUNC_trace_printk             = 6
BPF_FUNC_get_prandom_u32          = 7
BPF_FUNC_get_smp_processor_id     = 8
BPF_FUNC_skb_store_bytes          = 9
BPF_FUNC_l3_csum_replace          = 10
BPF_FUNC_l4_csum_replace          = 11
BPF_FUNC_tail_call                = 12
BPF_FUNC_clone_redirect           = 13
BPF_FUNC_get_current_pid_tgid     = 14
BPF_FUNC_get_current_uid_gid      = 15
BPF_FUNC_get_current_comm         = 16
BPF_FUNC_get_cgroup_classid       = 17
BPF_FUNC_skb_vlan_push            = 18
BPF_FUNC_skb_vlan_pop             = 19
BPF_FUNC_perf_event_read          = 22
BPF_FUNC_redirect                 = 23
BPF_FUNC_perf_event_output        = 25
BPF_FUNC_skb_load_bytes           = 26
BPF_FUNC_get_stackid              = 27
BPF_FUNC_csum_diff                = 28
BPF_FUNC_fib_lookup               = 69
BPF_FUNC_redirect_map             = 51
BPF_FUNC_sk_redirect_map          = 52
BPF_FUNC_sock_map_update          = 53
BPF_FUNC_perf_event_read_value    = 55
BPF_FUNC_spin_lock                = 93
BPF_FUNC_spin_unlock              = 94
BPF_FUNC_tcp_sock                 = 96
BPF_FUNC_sk_lookup_tcp            = 84
BPF_FUNC_sk_lookup_udp            = 85
BPF_FUNC_sk_release               = 86
BPF_FUNC_map_push_elem            = 87
BPF_FUNC_map_pop_elem             = 88
BPF_FUNC_map_peek_elem            = 89
BPF_FUNC_ringbuf_output           = 130
BPF_FUNC_ringbuf_reserve          = 131
BPF_FUNC_ringbuf_submit           = 132
BPF_FUNC_ringbuf_discard          = 133
BPF_FUNC_ringbuf_query            = 134
BPF_FUNC_probe_read_user          = 112
BPF_FUNC_probe_read_kernel        = 113
BPF_FUNC_probe_read_user_str      = 114
BPF_FUNC_probe_read_kernel_str    = 115
BPF_FUNC_get_current_task         = 35
BPF_FUNC_get_current_pid_tgid     = 14
BPF_FUNC_ktime_get_boot_ns        = 125
BPF_FUNC_jiffies64                = 118
BPF_FUNC_send_signal              = 109
BPF_FUNC_for_each_map_elem        = 164
BPF_FUNC_loop                     = 181
BPF_FUNC_strncmp                  = 182
BPF_FUNC_get_retval               = 186
BPF_FUNC_set_retval               = 187
BPF_FUNC_ktime_get_tai_ns         = 208
BPF_FUNC_cgrp_storage_get         = 210
BPF_FUNC_cgrp_storage_delete      = 211
__BPF_FUNC_MAX_ID                 = 212

; =============================================================================
; SINTAXIS ESTILO x86 PARA eBPF
; =============================================================================

; 1. REGISTROS INTELIGENTES
element bpf_reg
r0  = bpf_reg + 0
r1  = bpf_reg + 1
r2  = bpf_reg + 2
r3  = bpf_reg + 3
r4  = bpf_reg + 4
r5  = bpf_reg + 5
r6  = bpf_reg + 6
r7  = bpf_reg + 7
r8  = bpf_reg + 8
r9  = bpf_reg + 9
r10 = bpf_reg + 10
ax  = bpf_reg + 11

; --- Tamaños de operando para acceso a memoria ---
w = BPF_W
h = BPF_H
b = BPF_B

; 2. FABRICA DE INSTRUCCIONES ALU
macro alu mnemonic, bpf_opcode
    macro mnemonic dst, src
        if src relativeto bpf_reg
            BPF_ALU64_REG bpf_opcode, (dst - bpf_reg), (src - bpf_reg)
        else
            BPF_ALU64_IMM bpf_opcode, (dst - bpf_reg), src
        end if
    end macro
end macro

alu mov, BPF_MOV
alu add, BPF_ADD
alu sub, BPF_SUB
alu mul, BPF_MUL
alu div, BPF_DIV
alu and, BPF_AND
alu or,  BPF_OR
alu xor, BPF_XOR
alu shl, BPF_LSH
alu shr, BPF_RSH
alu sar, BPF_ARSH

; 3. ACCESO A MEMORIA Y OPERACIONES ATÓMICAS (Limpiamos el elemento bpf_reg)
macro ld_imm64 dst, imm64
    BPF_LD_IMM64 (dst - bpf_reg), imm64
end macro

macro ld_map_fd dst, map_fd
    BPF_LD_MAP_FD (dst - bpf_reg), map_fd
end macro

macro ldx_mem sz, dst, src, off
    BPF_LDX_MEM sz, (dst - bpf_reg), (src - bpf_reg), off
end macro

macro stx_mem sz, dst, src, off
    BPF_STX_MEM sz, (dst - bpf_reg), (src - bpf_reg), off
end macro

macro st_mem sz, dst, off, imm
    BPF_ST_MEM sz, (dst - bpf_reg), off, imm
end macro

macro atomic_op sz, op, dst, src, off
    BPF_ATOMIC_OP sz, op, (dst - bpf_reg), (src - bpf_reg), off
end macro

; 4. EMULACION DEL COMANDO 'CMP' Y SALTOS CONDICIONALES
_cmp_dst = 0
_cmp_src = 0
_cmp_is_reg = 0

macro cmp dst, src
    _cmp_dst = (dst - bpf_reg)
    if src relativeto bpf_reg
        _cmp_src = (src - bpf_reg)
        _cmp_is_reg = 1
    else
        _cmp_src = src
        _cmp_is_reg = 0
    end if
end macro

macro jcc mnemonic, bpf_cond
    macro mnemonic target
        if _cmp_is_reg = 1
            BPF_JMP_REG bpf_cond, _cmp_dst, _cmp_src, target
        else
            BPF_JMP_IMM bpf_cond, _cmp_dst, _cmp_src, target
        end if
    end macro
end macro

jcc je,  BPF_JEQ
jcc jne, BPF_JNE
jcc jg,  BPF_JGT
jcc jge, BPF_JGE
jcc jl,  BPF_JLT
jcc jle, BPF_JLE
jcc jsg,  BPF_JSGT
jcc jsge, BPF_JSGE
jcc jsl,  BPF_JSLT
jcc jsle, BPF_JSLE

; 5. SALTO INCONDICIONAL Y LLAMADAS
macro jmp target
    BPF_JMP_A target
end macro

macro call target
    if target relativeto 0
        BPF_CALL_FUNC target
    else
        BPF_INSN (BPF_JMP or BPF_CALL), 0, BPF_PSEUDO_CALL, 0, target
    end if
end macro

macro bswap64 dst
    BPF_ALU64_IMM BPF_END, (dst - bpf_reg), 64
end macro

macro bswap32 dst
    BPF_ALU64_IMM BPF_END, (dst - bpf_reg), 32
end macro

macro bswap16 dst
    BPF_ALU64_IMM BPF_END, (dst - bpf_reg), 16
end macro

macro nop
    BPF_INSN BPF_ALU64 or BPF_MOV or BPF_X, r0, r0, 0, 0
end macro

macro xor_zero dst
    ; xor r0, r0 es igual a ponerlo a cero
    BPF_ALU64_REG BPF_XOR, (dst - bpf_reg), (dst - bpf_reg)
end macro

macro neg dst
    BPF_ALU64_REG BPF_NEG, (dst - bpf_reg), 0
end macro

macro map_lookup map_fd, key_reg, value_reg
    ld_map_fd r1, map_fd
    mov       r2, key_reg
    call      BPF_FUNC_map_lookup_elem
    mov       value_reg, r0
end macro

; Acceso directo al contexto XDP (r1 es ctx)
; ctx->data es offset 0, ctx->data_end es offset 8
macro get_data dst, src
    ldx_mem dw, dst, src, 0
end macro

macro get_data_end dst, src
    ldx_mem dw, dst, src, 8
end macro

macro tail_call map_fd, index
    ld_map_fd r2, map_fd
    mov       r3, index
    call      BPF_FUNC_tail_call
end macro

macro clear_reg dst, size
    match =b, size
        and dst, 0xFF
    end match
    match =8, size
        and dst, 0xFF
    end match
    match =h, size
        and dst, 0xFFFF
    end match
    match =16, size
        and dst, 0xFFFF
    end match
    match =w, size
        and dst, 0xFFFFFFFF
    end match
    match =32, size
        and dst, 0xFFFFFFFF
    end match
end macro

macro ret
    BPF_EXIT_INSN
end macro

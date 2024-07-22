.global _shellcode_start_s_thumb
.global _shellcode_end_s_thumb
.global _hookstub_function_addr_s_thumb
.global _old_function_addr_s_thumb

.data
_shellcode_start_s_thumb:
    push    {r0, r1, r2, r3} 
    mrs     r0, cpsr
    str     r0, [sp, #0xC]
    str     r14, [sp, #8]
    add     r14, sp, #0x10
    str     r14, [sp, #4]
    pop     {r0}
    push    {r0-r12} 
    mov     r0, sp
    ldr     r3, [pc, #(_hookstub_function_addr_s_thumb - (. + 8))]
    blx     r3
    ldr     r3, [pc, #(_old_function_addr_s_thumb - (. + 8))]
    bic     r3, r3, #1
    add     r3, r3, #0x1
    str     r3, [pc, #(_old_function_addr_s_thumb - (. + 8))]
    ldr     r3, [sp, #-0x34]
    ldr     r0, [sp, #0x3C]
    msr     cpsr, r0
    ldmfd   sp!, {r0-r12}  
    ldr     r14, [sp, #4]
    ldr     sp, [r13]
    ldr     pc, [pc, #(_old_function_addr_s_thumb - (. + 8))]

_hookstub_function_addr_s_thumb:
.word 0xffffffff

_old_function_addr_s_thumb:
.word 0xffffffff

_shellcode_end_s_thumb:

.end


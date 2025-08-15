.text
.align 4096
.global copy_cat_victim_fn
/*
    - rdi  : uint64_t  inner_reps
    - rsi  : uint64_t* start_maker 
    - rdx  : uint64_t* stop_marker
    Unused arg registers: rcx, r8, r9
*/
copy_cat_victim_fn:

    //write to start marker
    movq $42, (%rsi)

    //main loop, do inner_reps repetitions
    2:
    dec %rdi
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jnz 2b

    //finished main loop, write to stop marker
    movq $42, (%rdx)
    ret



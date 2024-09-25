display/i $pc
display/s $rax
display/s $rbx
display/s $rcx
display/s $rdx
display/s $rsi
display/s $rdi

b phase5
    b phase5_word1
    b phase5_word2
    b phase5_word1_word2
b phase6
b phase7
b secret_phase

b explode_bomb
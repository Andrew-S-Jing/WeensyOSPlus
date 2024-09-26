display/i $pc
display/s $rdi
display/s $rsi

b *0x401b60
b *0x401ae1
b secret_phase

b explode_bomb
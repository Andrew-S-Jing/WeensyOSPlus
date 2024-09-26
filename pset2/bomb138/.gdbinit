display/i $pc
display/3dg 0x405110
display/dg $rdi
display/dg $rsi

b secret_phase
    b *0x4019d0

b explode_bomb
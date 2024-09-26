display/i $pc
display/dw 0x7fffffffe504

b phase6
    b calc6_expr
    b calc6_factor
    b calc6_term
b phase7
b secret_phase

b explode_bomb
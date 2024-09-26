display/i $pc
display/24dw 0x4052f0
display/s 0x4057a0
display/a *0x7fffffffe4e0
display/a *0x7fffffffe4e8
display/a *0x7fffffffe4f0
display/a *0x7fffffffe4f8
display/a *0x7fffffffe500
display/a *0x7fffffffe508

b phase7
    b *(phase7+89)
b secret_phase

b explode_bomb
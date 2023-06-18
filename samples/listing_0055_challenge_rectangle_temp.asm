bits 16

; Start image after one row, to avoid overwriting our code!
mov bp, 64*4

; Draw the solid rectangle red/blue/alpha
mov dx, 64
y_loop_start:
	
	mov cx, 64
	x_loop_start:
		mov byte [bp + 0], cl  ; Red
		mov byte [bp + 1], 0   ; Green
		mov byte [bp + 2], dl  ; Blue
		mov byte [bp + 3], 255 ; Alpha
		add bp, 4
			
		loop x_loop_start
	
	sub dx, 1
	jnz y_loop_start

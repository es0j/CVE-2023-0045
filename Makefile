all:
	
	gcc -o victim-PRCTL test.c -O0 -masm=intel -w  -DPRCTL
	gcc -o attacker test.c -O0 -masm=intel -w  -DATTACKER

clean:
	rm attacker
	rm victim*
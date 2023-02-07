all:
	
	gcc -o attacker attacker.c -O0 -masm=intel -no-pie -fno-stack-protector
	gcc -o victim victim.c -O0 -masm=intel -no-pie -fno-stack-protector

clean:
	rm attacker
	rm victim
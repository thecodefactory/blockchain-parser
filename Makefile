blockchain-parser: *.c *.h
	gcc -O3 *.c -o blockchain-parser
run:    blockchain-parser
	./blockchain-parser
clean: blockchain-parser
	rm -f blockchain-parser

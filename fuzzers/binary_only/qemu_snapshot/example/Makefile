all: model_malloc


model_malloc: model_malloc.c
	gcc -o model_malloc model_malloc.c
	objdump -d model_malloc > model_malloc.asm

clean:
	rm -f model_malloc
	rm -f *.core

run: model_malloc
	rm -rf workdir
	rm -f *.core
	uv run ../../fuzzolic/fuzzolic.py --keep-run-dirs --address-reasoning --optimistic-solving --timeout 90000 -o ./workdir/ -i ./malloc.in -- ./model_malloc @@

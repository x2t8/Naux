COQC=coqc
COQFLAGS=-Q . NauxCore

FILES=Syntax Typing Smallstep Soundness DataAlgo

all: $(FILES:%=%.vo)

%.vo: %.v
	$(COQC) $(COQFLAGS) $<

clean:
	rm -f *.vo *.vos *.vok *.glob *.aux *.d

.PHONY: all clean
	
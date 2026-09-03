COQC=rocq c
COQFLAGS=-Q . NauxCore

FILES=Syntax Typing Smallstep Soundness DataAlgo I64Arithmetic RegisterResidency DefiniteInitialization ProjectedCFGResidency ScalarMachineIRResidency HeapMachineIRResidency OwnershipMachineIRResidency ControlFlowMachineIRResidency X86ResidencyEncoding ELF64ResidencyEnvelope ResidencyProcessTarget ELF64ResidencyProcessEnvelope NauxCore

all: $(FILES:%=%.vo)

%.vo: %.v
	$(COQC) $(COQFLAGS) $<

clean:
	rm -f *.vo *.vos *.vok *.glob *.aux .*.aux *.d .lia.cache
	rm -rf .coq-native

.PHONY: all clean

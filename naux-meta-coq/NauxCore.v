(** NauxCore — master export of the mini NAUX Coq model. *)

From NauxCore Require Export
  Syntax Typing Smallstep Soundness DataAlgo I64Arithmetic RegisterResidency
  DefiniteInitialization ProjectedCFGResidency ScalarMachineIRResidency
  HeapMachineIRResidency OwnershipMachineIRResidency
  ControlFlowMachineIRResidency X86ResidencyEncoding ELF64ResidencyEnvelope
  ResidencyProcessTarget ELF64ResidencyProcessEnvelope
  ResidencyResultProtocol ResidencyCandidateRole ResidencyControlledHost
  ResidencyTimingCarrier ResidencyMeasurementRunner ResidencyEvidenceReplay
  ResidencyPairedRunner ResidencyPairedEvidenceReplay
  ResidencyPairedThreshold ResidencyClaimAdmission
  ResidencyPublicProtocolAcceptance.

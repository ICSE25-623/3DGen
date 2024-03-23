# 3DGen: AI-Assisted Generation of Provably Correct Binary Format Parsers

This repository contains supplementary materials for ICSE 2025 submission #623. 

### 3DGen Agent
- Code and prompts for the 3DGen agent is included in the 3DGen-src/agents folder
- Examples and 3D manual are included in the 3DGen-src/examples and 3DGen-src/3d_manuals folders
- Scripts to generate and validate tests are in the main 3DGen-src/ folder
- packets.zip contains the test set of packets used for each protocol
- experiments.zip contains the generated specifications and agent logs for the experiments in the paper.

### 3DTestGen
- test1.smt2 contains the SMT2 encoding of an example message parser from the TestMessage.3d file, generated by 3DTestGen. This file is a replayable transcript of all the SMT2 commands generated by 3DTestGen and sent to Z3, along with comments showing the responses from Z3, to generate and retrieve positive and negative test cases with branch coverage depth 2.

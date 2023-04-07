# Call of Duty - Code Flow Deobfuscation
A program written in C++ to remove and cleanup code flow obfuscation seen in a variety of Call of Duties titles.

## Brief Explanation
A tactic created by Treyarch to make reverse engineering their recent titles a pain is to add junk instructions specifically targetting how IDA parses opcodes. What you end up with is a junk instruction followed by a call that loops back to a few bytes into the current location with junk opcodes that vary, making it difficult to scan.

## Usage
### 1. Compile the source
### 2. Drag a dumped Call of Dutry executable onto the deobfuscator
### 3. Wait 5-10s (depending on your computer) for it to finish analysis

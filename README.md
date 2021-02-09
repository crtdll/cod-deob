# Cold War - Code Flow Deobfuscation
A program written in C++ to remove and cleanup code flow obfuscation seen in Activisions latest title - **Call of Duty: Black Ops Cold War**

## Brief Explanation
A tactic created by Treyarch to make reverse engineering their recent titles a pain is to add junk instructions specifically targetting how IDA parses opcodes. What you end up with is a junk instruction followed by a call that loops back to a few bytes into the current location with junk opcodes that vary, making it difficult to scan (see below).

![](https://indian.vagina.guru/DQdnmT.png)

Followed after the junk instruction setup is a random block of bytes varying in size. 

## Usage
### 1. Compile the source
### 2. Drag a dumped executable of Cold War onto the executable
### 3. Wait 10-30s (depending on your computer) for it to finish analysis
### 4. Run the .fixed output executable in IDA
### 5. Run the IDC generated to fix locations (File -> Script File -> loc_fix.idc)

## Example Output
An example of how the fixed executable looks in IDA (compared to the above, rebased to 0x140000000)

![](https://indian.vagina.guru/T4GvHC.png)

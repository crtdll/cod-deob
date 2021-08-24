# Cold War - Code Flow Deobfuscation
A program written in C++ to remove and cleanup code flow obfuscation seen in Activisions latest titles (**Call of Duty: Black Ops Cold War** & **Call of Duty: Modern Warfare**)

## Brief Explanation
A tactic created by Treyarch to make reverse engineering their recent titles a pain is to add junk instructions specifically targetting how IDA parses opcodes. What you end up with is a junk instruction followed by a call that loops back to a few bytes into the current location with junk opcodes that vary, making it difficult to scan (see below).

![](https://tbhhh.i-really-dont-want-to.live/57_FddvES.png)

Followed after the junk instruction setup is a random block of bytes varying in size. 

## Usage
### 1. Compile the source
### 2. Drag a dumped Call of Dutry executable onto the deobfuscator
### 3. Wait 5-10s (depending on your computer) for it to finish analysis

## Example Output
An example of how the fixed executable looks in IDA (compared to the above)

![](https://tbhhh.i-really-dont-want-to.live/57_FEEey1.png)

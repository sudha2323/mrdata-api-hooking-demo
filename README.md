# 🔍 .mrdata API Hooking Demo (C++ Malware Technique)

**Author:** Amit Chaudhary  
**Blog:** *Coming Soon*  
**Purpose:** Demonstrates stealthy API hooking using the `.mrdata` section of `ntdll.dll`, like real malware (ScyllaHide-style).

---

## 🔧 What This Does

- Hooks `IsDebuggerPresent()` by patching a pointer inside `.mrdata`
- No `.text` or IAT changes — avoids static detection
- Shows both local and remote `.mrdata` pointer patching

---

## 💡 How It Works

1. Finds `ntdll.dll` base in current process
2. Calculates `.mrdata` offset for `IsDebuggerPresent()` stub
3. Overwrites it with a fake function pointer
4. Calls the API — and returns fake result!

---

## 🧪 How to Verify in x32dbg

1. Run this binary
2. Attach x32dbg to the process
3. Set breakpoint on `.mrdata` memory region
4. Step through `IsDebuggerPresent()` → you land in fake function

---

## 🛠 Build Instructions

```bash
cl mrdata_hook_demo.cpp /link psapi.lib


#ifndef PCH_H
#define PCH_H

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <mutex>
#include <unordered_map>
#include <stdlib.h>
#include <fstream>
#include <stdio.h>

#ifdef _WIN64
#define ProcessEnvironmentBlock ((PEB*)__readgsqword(0x60))
#else
#define ProcessEnvironmentBlock = ((PEB*)__readfsqword(0x30))
#endif

#endif
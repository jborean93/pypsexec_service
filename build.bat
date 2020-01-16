@echo off

if not defined DevEnvDir (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
    ) else (
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
    )
)

set COMPILER_CONSTANTS=/D "WIN32" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /D "NOCOMM" /D "SECURITY_WIN32" /D "PSAPI_VERSION=1"
REM /D "NDEBUG"
REM /D "WIN32_LEAN_AND_MEAN" 
REM set COMPILER_FLAGS=/permissive- /GS /GL /Gy /Zc:wchar_t /Zi /O1 /sdl /WX /Gd /Oy- /MT /std:c++17 /EHsc /I external
set COMPILER_FLAGS=/permissive- /GS /GL /Gy /Zc:wchar_t /Zi /Od /sdl /WX /Gd /Oy- /MT /std:c++17 /EHsc /I external
set LINKER_FLAGS=/OUT:bin\main.exe /DEBUG /MACHINE:X86 /OPT:REF /OPT:ICF /INCREMENTAL:NO /SUBSYSTEM:CONSOLE /NOLOGO
set LIBRARIES=Advapi32.lib Kernel32.lib Psapi.lib Secur32.lib User32.lib Userenv.lib Wtsapi32.lib
cl.exe %COMPILER_CONSTANTS% %COMPILER_FLAGS% src\*.cpp /link %LINKER_FLAGS% %LIBRARIES%
del *.obj *.pdb
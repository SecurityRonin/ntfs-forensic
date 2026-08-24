@echo off
REM ===================================================================
REM  Mint a Windows-authored NTFS fixture carrying CLASSIC reparse
REM  points (0xA000000C symlink / 0xA0000003 junction), which no Linux
REM  tool can create via mklink.
REM
REM  RUN AS ADMINISTRATOR:
REM    right-click cmd.exe -> "Run as administrator", then:
REM      \\Mac\Cases\make-ntfs-reparse-fixture.cmd
REM
REM  Produces, in \\Mac\Cases\ :
REM    win_reparse.vhd        the fixed VHD (raw NTFS volume + 512b footer)
REM    win_reparse_truth.txt  Windows' OWN decode of each reparse point,
REM                           via fsutil - this is the answer key
REM ===================================================================
setlocal

set VHD=C:\win_reparse.vhd
set OUT=\\Mac\Cases
set DRV=W:

echo.
echo === checking privileges ===
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: not elevated. Re-run from an Administrator cmd.exe.
    echo Symbolic links need SeCreateSymbolicLinkPrivilege.
    pause
    exit /b 1
)
echo OK, elevated.

if exist "%VHD%" del /f /q "%VHD%"

echo.
echo === creating + formatting a 64 MB VHD ===
(
  echo create vdisk file="%VHD%" maximum=64 type=fixed
  echo select vdisk file="%VHD%"
  echo attach vdisk
  echo create partition primary
  echo format fs=ntfs quick label=CLASSICRP
  echo assign letter=%DRV:~0,1%
) > "%TEMP%\mkvhd.txt"
diskpart /s "%TEMP%\mkvhd.txt"
if errorlevel 1 goto :fail

echo.
echo === populating: targets, then every reparse variant ===
cd /d %DRV%\
echo real target contents> target.txt
mkdir realdir
echo inside realdir> realdir\inner.txt

REM --- 0xA000000C symbolic links --------------------------------------
REM relative: SubstituteName has NO \??\ prefix and Flags = 1
REM           (SYMLINK_FLAG_RELATIVE). This is the load-bearing case:
REM           a non-zero Flags word.
mklink rel_link.txt target.txt
REM absolute: SubstituteName = \??\W:\target.txt and Flags = 0
mklink abs_link.txt %DRV%\target.txt
REM directory symlinks, relative and absolute
mklink /D rel_dirlink realdir
mklink /D abs_dirlink %DRV%\realdir

REM --- 0xA0000003 junction (mount point) — NO Flags field --------------
mklink /J junction %DRV%\realdir

REM --- controls: a hardlink and a plain file are NOT reparse points ----
mklink /H hardlink.txt target.txt

echo.
echo === recording Windows' own decode as the answer key ===
set TRUTH=%TEMP%\win_reparse_truth.txt
> "%TRUTH%" echo # Windows-authored NTFS reparse fixture
>> "%TRUTH%" echo # generated %DATE% %TIME%
>> "%TRUTH%" ver
>> "%TRUTH%" echo.
>> "%TRUTH%" echo ## dir listing (note ^<SYMLINK^>, ^<SYMLINKD^>, ^<JUNCTION^> tags)
>> "%TRUTH%" dir %DRV%\
>> "%TRUTH%" echo.
for %%F in (rel_link.txt abs_link.txt rel_dirlink abs_dirlink junction) do (
    >> "%TRUTH%" echo ## fsutil reparsepoint query %%F
    >> "%TRUTH%" fsutil reparsepoint query %DRV%\%%F
    >> "%TRUTH%" echo.
)

cd /d C:\

echo.
echo === detaching ===
(
  echo select vdisk file="%VHD%"
  echo detach vdisk
) > "%TEMP%\dtvhd.txt"
diskpart /s "%TEMP%\dtvhd.txt"

echo.
echo === copying to %OUT% ===
copy /y "%VHD%" "%OUT%\win_reparse.vhd"
copy /y "%TRUTH%" "%OUT%\win_reparse_truth.txt"

echo.
echo DONE. On the Mac these are in ~/Documents/Cases/ :
echo   win_reparse.vhd
echo   win_reparse_truth.txt
echo.
pause
exit /b 0

:fail
echo.
echo FAILED during diskpart. Nothing was copied.
pause
exit /b 1

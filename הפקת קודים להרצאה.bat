@echo off
rem Opens the lecture code generator window (new-lecture.ps1)
start "" powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0new-lecture.ps1"

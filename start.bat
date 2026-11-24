@echo off
setlocal
if not exist node_modules\ (
  echo Dependencies are missing. Run npm install first.
  exit /b 1
)
npm start

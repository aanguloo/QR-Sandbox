# Programa en Windows la descarga diaria de listas (Experimento 1).
# Ejecutar en PowerShell (normal, no hace falta administrador):
#   powershell -ExecutionPolicy Bypass -File \\wsl.localhost\Ubuntu\home\andre\QR-Sandbox\scripts\programar_descarga.ps1
# Crea la tarea "QR-Sandbox descarga diaria": todos los días a las 10:00 y al iniciar sesión
# (si el notebook estaba apagado a las 10:00, corre apenas pueda). Llama a
# scripts/descarga_diaria.sh dentro de Ubuntu, que solo descarga si falta el snapshot del día.
# Para quitarla después del 14-nov:
#   Unregister-ScheduledTask -TaskName "QR-Sandbox descarga diaria" -Confirm:$false

$nombre = "QR-Sandbox descarga diaria"
$accion = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-d Ubuntu -u andre -- bash /home/andre/QR-Sandbox/scripts/descarga_diaria.sh"
$diaria = New-ScheduledTaskTrigger -Daily -At 10:00
$inicio = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$ajustes = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
$desc = "QR-Sandbox: descarga diaria de listas de phishing para el Experimento 1. Solo descarga si falta el snapshot del dia. Borrar despues del 14-nov."

try {
  Register-ScheduledTask -TaskName $nombre -Action $accion -Trigger $diaria,$inicio -Settings $ajustes -Description $desc -Force -ErrorAction Stop | Out-Null
  Write-Host "Tarea creada: todos los dias a las 10:00 y al iniciar sesion."
} catch {
  # Algunos equipos exigen administrador para el disparador "al iniciar sesion".
  Register-ScheduledTask -TaskName $nombre -Action $accion -Trigger $diaria -Settings $ajustes -Description $desc -Force | Out-Null
  Write-Host "Tarea creada solo a las 10:00 (el disparador al iniciar sesion requiere administrador)."
}
$info = Get-ScheduledTaskInfo -TaskName $nombre
Write-Host "Proxima ejecucion: $($info.NextRunTime)"
Write-Host "Para probarla ahora: Start-ScheduledTask -TaskName '$nombre'  (y revisa data/listas/descargas.log)"

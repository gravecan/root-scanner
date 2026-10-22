$jar = "C:\Users\ginob\.gradle\caches\fabric-loom\1.20.1\minecraft-merged.jar"
if (!(Test-Path $jar)) {
    $jar = (Get-ChildItem -Path "$env:USERPROFILE\.gradle\caches\fabric-loom" -Recurse -Filter "*minecraft-merged*.jar" | Select-Object -First 1).FullName
}
Write-Host "Using Jar: $jar"

# Extract firework_rocket.png
& jar xf $jar "assets/minecraft/textures/item/firework_rocket.png"
if (Test-Path "assets/minecraft/textures/item/firework_rocket.png") {
    Write-Host "Successfully extracted official Minecraft firework rocket texture!"
} else {
    Write-Host "Extraction failed"
}

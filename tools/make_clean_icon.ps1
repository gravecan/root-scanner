Add-Type -AssemblyName System.Drawing

$srcPath = "assets/minecraft/textures/item/firework_rocket.png"
$src = [System.Drawing.Bitmap]::FromFile($srcPath)

# 128x128 crisp nearest-neighbor icon
$dst = New-Object System.Drawing.Bitmap 128, 128
$g = [System.Drawing.Graphics]::FromImage($dst)
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::None

# Draw pixel-perfect 16x16 scaled to 128x128 with transparent background
$g.DrawImage($src, 0, 0, 128, 128)
$g.Dispose()
$src.Dispose()

# Save to assets in both projects and root
$dest1 = "FireworkSwapper\src\main\resources\assets\fireworkswapper\icon.png"
$dest2 = "FireworkSwapper-Old\src\main\resources\assets\fireworkswapper\icon.png"
$dest3 = "c:\Users\ginob\Downloads\ee\firework_icon.png"

$dst.Save($dest1, [System.Drawing.Imaging.ImageFormat]::Png)
$dst.Save($dest2, [System.Drawing.Imaging.ImageFormat]::Png)
$dst.Save($dest3, [System.Drawing.Imaging.ImageFormat]::Png)
$dst.Dispose()

Write-Host "Pixel-perfect official Minecraft firework icon generated at $dest1 and $dest2"

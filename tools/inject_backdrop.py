import base64

with open('stage_backdrop.webp', 'rb') as f:
    b64 = base64.b64encode(f.read()).decode('ascii')

with open('ui/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace stage background
old_stage = """.stage {
  position: relative;
  display: grid;
  width: min(100%, 440px);
  height: clamp(300px, 50svh, 360px);
  place-items: center;
  border-radius: 18px;
  background: #000;
  overflow: hidden;
}"""

new_stage = f""".stage {{
  position: relative;
  display: grid;
  width: min(100%, 440px);
  height: clamp(300px, 50svh, 360px);
  place-items: center;
  border-radius: 18px;
  background: #08080a url("data:image/webp;base64,{b64}") center / cover no-repeat;
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.1), 0 20px 50px rgba(0, 0, 0, 0.9);
  overflow: hidden;
}}"""

if old_stage in content:
    content = content.replace(old_stage, new_stage)
    with open('ui/index.html', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Updated stage with authentic backdrop texture successfully!")
else:
    print("Notice: old_stage exact match not found, looking for .stage { ... background: ... }")

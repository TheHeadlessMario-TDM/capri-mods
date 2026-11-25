# Paint Job

Capri's colour skins only reach part of her UI. **Paint Job** repaints the rest: the Night City Mainframe theme, her speech bubble and small widgets, her HUD portrait, her own computer window, and her file editor and panel art.

It ships in yellow and cyan. Pick any **main** and **accent** colour as hex in Options and every shade follows by hue, keeping its own brightness, so dark glows and borders change too, not just the bright bits. Each area can be switched off on its own. Turning the mod off puts Capri's originals back.

**Options:** each area on/off · main colour (hex) · accent colour (hex)

For the Mainframe, pick **Night City** under Mainframe colours.

Reaches into Capri's own colour tables, so a Capri update that renames one can make that one area stop changing (the rest keep working).

- Kind: code mod
- Made by: Quaisar_THM
- Needs: Capri with mod API 3 (0.8.7 or newer), Windows

### Why the mod check flags it
- **Loads code while it runs**: Capri's colour values are read-only fields, and a tiny generated setter (`DynamicMethod`) is the only way to change them. It writes colours and nothing else; there's no hidden or unpacked text.

No network access, no keys, nothing sent anywhere.

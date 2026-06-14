#!/bin/bash
set -euo pipefail

# Tile all Terminal windows whose *window name* contains "AV-LISTENER:"
# into a 2x4 grid (8 listeners). Extra windows will continue in further rows.

FOUND="$(osascript <<'EOF'
tell application "Terminal"
    set listenerWindows to (every window whose name contains "AV-LISTENER:")
    return (count of listenerWindows) as text
end tell
EOF
)"

echo "[tile] Found ${FOUND} AV-LISTENER windows"

osascript <<'EOF'
tell application "Terminal"
    activate

    set listenerWindows to (every window whose name contains "AV-LISTENER:")
    set winCount to (count of listenerWindows)
    if winCount = 0 then return

    -- Screen bounds (more robust than hardcoding)
    -- Finder's desktop window bounds are usually the full screen in pixels.
    tell application "Finder"
        set b to bounds of window of desktop
    end tell

    set screenLeft to item 1 of b
    set screenTop to item 2 of b
    set screenRight to item 3 of b
    set screenBottom to item 4 of b

    -- Small margins so windows don't overlap the menu bar / dock
    set marginLeft to 10
    set marginTop to 40
    set marginRight to 10
    set marginBottom to 10

    set usableLeft to screenLeft + marginLeft
    set usableTop to screenTop + marginTop
    set usableRight to screenRight - marginRight
    set usableBottom to screenBottom - marginBottom

    set totalWidth to usableRight - usableLeft
    set totalHeight to usableBottom - usableTop

    set colCount to 3
    set rowCount to ((winCount + colCount - 1) div colCount)

    set colWidth to totalWidth div colCount
    set rowHeight to totalHeight div rowCount

    repeat with idx from 1 to winCount
        set w to item idx of listenerWindows

        set rowIndex to (idx - 1) div colCount
        set colIndex to (idx - 1) mod colCount

        set leftPos to usableLeft + (colIndex * colWidth)
        set topPos to usableTop + (rowIndex * rowHeight)
        set rightPos to leftPos + colWidth
        set bottomPos to topPos + rowHeight

        try
            set bounds of w to {leftPos, topPos, rightPos, bottomPos}
        end try
    end repeat
end tell
EOF

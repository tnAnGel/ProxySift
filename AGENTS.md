# Project agent instructions

## CodeGraph

- Keep this repository indexed with CodeGraph. If `.codegraph/` is missing, initialize it with `codegraph init` before exploring or editing source code; if it is stale, run `codegraph sync` or `codegraph index` before continuing.
- For every code task, check CodeGraph status and query it before locating, reading, or editing source symbols (`codegraph_explore` MCP tool, or `codegraph explore` in the shell). Use its source and call paths to understand the implementation and impact before opening files directly.
- After edits, let the index watcher synchronize (or run `codegraph sync`), then query changed symbols again to review the resulting source and callers. Use direct file reads only for details CodeGraph does not index, such as UI assets, configuration, and documentation.

## Parallel agents

- For substantial, multi-area tasks, proactively split independent research, implementation, and review into sub-agents. Use up to six agents in parallel when the work benefits from it; assign each a narrow scope and explicit file ownership to avoid overlapping edits. Keep tightly coupled integration in the coordinating agent and review all returned changes before merging them.
- Do not create agents for trivial single-line changes where parallel work would add coordination cost.

## UI alignment

- In summary cards, vertically center the entire multi-line text group against the icon and the card's full height, not just against the group's intrinsic content height.
- For text or numbers inside an icon tile, make the text fill the tile and center it against the tile's full width and height.
- In every table or list row, vertically center cell content against the full row height. This includes text, status badges, icons, and row actions.
- Center row-action buttons within the row, and center their icon or label within the button's own bounds. Do not assume that centering text inside a small control also centers that control in its row.
- Keep row-action columns inside the visible table width; verify that rightmost actions are not clipped by the table or its scroll area.
- Make each `TouchArea` match the visible control's bounds so hover and click feedback stay aligned.
- In compact header buttons, center the icon and hover tile on the same fixed bounds; explicitly center both axes instead of relying on a vertical layout's main-axis alignment.
- Before finishing a UI change, inspect the rendered screen at normal desktop size and check row alignment, including hover and in-progress states where applicable.

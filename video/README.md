# The Breakwater explainer video

A 2 min 45 s explainer, written as code with [Remotion](https://www.remotion.dev/) (React
components rendered frame by frame to MP4). The rendered video is in
[docs/media/breakwater.mp4](../docs/media/breakwater.mp4).

```sh
cd video
npm ci
npm run studio    # preview and scrub in the browser
npm run render    # out/breakwater.mp4 (1920×1080, 30 fps, H.264)
npm run srt       # out/breakwater.srt, the captions as a subtitle file
npm run still     # out/poster.png
```

The first render downloads Remotion's headless Chrome; fonts (Inter, JetBrains Mono) come from
Google Fonts at render time.

## Layout

| File | What it holds |
| --- | --- |
| [src/timeline.ts](src/timeline.ts) | Scene lengths and every caption with its timing. Edit captions here. |
| [src/theme.ts](src/theme.ts) | Size, fonts, colours, and the stage and caption areas |
| [src/Video.tsx](src/Video.tsx) | The composition: scenes with transitions, and the caption band |
| [src/components.tsx](src/components.tsx) | Shared motion pieces: word reveals, springs, counters, code and terminal panels, the backdrop |
| [src/scenes/](src/scenes/) | Intro, Problem, Solution, Proof, Integrate, Made, Outro |

**Captions** sit in a fixed band at the bottom of the frame (y 900 to 1080). Scenes draw only
in the stage above it, which is clipped, so no text, graphic or transition ever enters the
caption band.

The numbers on screen come from Breakwater's own runs (see the README's Results and
[docs/DECISIONS.md](../docs/DECISIONS.md)); update [src/scenes/Proof.tsx](src/scenes/Proof.tsx)
and re-render when they change. There is no soundtrack; to add one, place an audio file in
`public/` and add Remotion's `<Audio>` to `src/Video.tsx`.

Remotion is free for individuals and small teams; larger companies need a
[company license](https://www.remotion.dev/license).

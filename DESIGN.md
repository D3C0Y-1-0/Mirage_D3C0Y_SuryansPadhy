# DESIGN.md: Cascade cyber twin

Design contract for any person or AI building UI in this project. Follow it exactly; change it only on purpose.

## 1. Visual theme and art direction
**Civic night district.** A hospital and power district seen at night, as a control room would see it on one wall
display. Textured 3D buildings with lit windows on a deep blue city. The attack is the only pink thing on screen.
One bold element: the big clock and the city. Everything else is quiet.

## 2. Colour palette and roles
| Token | Hex | Role |
|---|---|---|
| `--abyss` | `#050B24` | Deepest layer: ground plane, page background |
| `--deep` | `#0A1640` | Dominant canvas (deep blue) |
| `--navy` | `#12225E` | Sheets and panels |
| `--sheet-2` | `#1A2C72` | Sheet stacked on top of a sheet (asset card) |
| `--line` | `#2B3D86` | Hairlines, inactive tracks, pads |
| `--white` | `#FFFFFF` | Pure white: text, structure, healthy and protected states, primary button |
| `--mute` | `#A9B4DA` | Secondary text |
| `--pink` | `#FF6FB5` | Bubblegum pink: the attack. Compromised, lost, alarm, selected entry point. Nothing else. |
| `--pink-deep` | `#E43F8E` | Lost service, pressed pink |
| `--soft` | `#8E9DE0` | Default data series (single-measure charts) |
| `--warn` | `#F2B84B` | Needs attention: known-exploited CVE, needs a maintenance window, model not delivered. Always with a word. |
| `--atk-a..d` | `#E5559F` `#2A8FD6` `#9A74F0` `#2BA58A` | Attacker A-D in multi-attacker views. Always with the letter badge. C moved from ochre to violet in PASS 12 so it can never be confused with amber (maintenance, warnings). In the twin, A keeps the twin pink `#FF6FB5`. |

Rules: pink always means "the attacker got here". Good news is white, never pink. Depth comes from tonal steps
(abyss < deep < navy < sheet-2) and 1px hairlines, never grey drop shadows. No gradients as decoration.

## 3. Typography
- Display: **Big Shoulders Display** 600/700/800 (civic signage face). Clock, headings, big numbers.
- Body: **Plus Jakarta Sans** 400/500/600. Controls, data, prose. Numbers use tabular figures.
- Both shipped locally in `frontend/vendor/fonts` (works offline).
- Scale (ratio 1.25, base 14px): 12, 14, 17.5, 22, 27, 34, 42. Clock 96px desktop, 56px phone.
- Big Shoulders has proportional digits, so the clock puts each digit in a fixed-width slot (no jitter).
- Sentence case. No all-caps labels, no eyebrow labels, no middle-dot meta strings, no arrows in buttons.
- Panel text at most about 70 characters per line.

## 4. Components
- **Sheets**: navy, 1px `--line` border, radius 14px. Asset card is a second sheet (`--sheet-2`) offset 16px over the dossier.
- **Buttons**: primary = white fill, deep-blue text, radius 8px. Secondary = transparent, 1px white-30% border.
- **Chips** (entry points): radius 999px; selected = pink border and pink-tinted fill.
- **Tags**: radius 3px.
- **Bars**: expected-risk reduction = soft blue-white `#8E9DE0`; worst-case reduction = pure white.
- **Clock**: Big Shoulders 800, fixed-width digit slots; turns pink once any service is lost.

## 5. Layout principles
Full-bleed 3D city. Floating sheets, asymmetric:
- Top-left: brand and view tabs; below it the clock (overlapping the city).
- Left rail (260px, starts below the clock): services, detection, event log, legend.
- Right dossier sheet (400px): the active view (replay, fix ranking, optimizer).
- Asset card: slides over the dossier, offset 16px.
- Bottom ticker: play, timeline with event ticks, latest event line, playback speed.
- The 3D camera is framed to the visible area between rail and dossier.
- Spacing scale: 4, 8, 12, 16, 24, 32, 48, 72. Text left-aligned; numbers right-aligned in tables.

## 6. Depth and elevation
Tonal only: abyss (ground) < deep (canvas) < navy (sheet) < sheet-2 (stacked sheet). 3D depth comes from moonlight,
shadows, lit windows and a soft bloom on light sources. No CSS box shadows.

## 7. Do and don't
Do: lit-window textures, real asset names and numbers, state shown by colour AND shape (pink pulse + time label for
compromised; white dome + "protected" for fixed). Don't: pink for anything that is not the attack, gradients,
glassmorphism, cards inside cards, fake status pills, placeholder copy, generic fonts.

## 8. Responsive behaviour
- 1100px and below: the rail folds into the dossier.
- 760px and below: city takes the top 52% of the screen, ticker below it, then the sheets; view tabs fold into a
  menu button; asset card becomes a bottom sheet.
- Checked at 1440, 1024 and 390px wide on every pass.

## 9. Instructions for AI agents
- Use only the tokens above; add a token here before using a new colour.
- Keep markup, styles and script in `frontend/index.html`; libraries stay in `frontend/vendor`.
- After any UI change: screenshot at 1440, 1024 and 390px with Playwright, require zero console errors.
- Motion: only event-triggered, plus one city light-up on load (zone by zone, about 1.5 s). Events: a thin pink
  ring when a building falls; two wide shock rings and a clock flash when a service is lost; the entry beam drops
  from the sky; the camera flies to a building opened in the card and back on close; buildings lift slightly on
  hover; the building menu pops in. All of it is off under `prefers-reduced-motion`.
- Presenter mode and the graphics panel are floating sheets centred over the city (sheet-2), never covering the clock.
- Busy districts (more than 14 systems): labels stay quiet except entry points, compromised, protected, hovered,
  selected and the five riskiest systems. Quiet labels stay keyboard-focusable.
- Interaction: every building and its label is clickable (and keyboard-focusable via its label) and opens the
  building menu: attack from here, add as a second attack, why is it at risk, protect it.
- Accessibility: visible focus rings, text labels on icon buttons, Space = play/pause, Esc = close card,
  touch targets at least 44px, readable contrast.

## 10. Platform and landing page (added for the full platform)
- Same tokens and fonts, shared in `frontend/static/cascade.css`. The twin keeps its own copy and is never edited by the platform.
- Landing: long scroll, sticky nav, sections reveal once (fade + 14px rise), stage dots light in order. Nothing else moves except the hero network, which replays one real attack from the dataset; static under reduced motion.
- Platform: 252px sidebar with six groups, 60px top bar with status pills, sheets for content, drawers for detail.
- Charts: hand-written SVG (`charts.js`), recessive grid, 2px lines, rounded bar ends, hover tooltip, legend for 2+ series, CSV and SVG export on every chart. Count axes use whole-number ticks.
- Pink is still only the attack (compromised, lost, harm, attacker A). High risk is white; known-exploited is amber.

## 11. Landing theme (light) — `frontend/landing.html` only
- Look: royal blue (#1E3BFF) to azure (#4F8BFF) to mist (#EAF2FF) hero gradient, white dotted pixel field on the sides
  (mouse-reactive, calmer as you scroll), frosted glass pill navigation, light Outfit headings, white floating cards.
- Tokens (landing only): --royal #1E3BFF, --royal-2 #2F5BFF, --azure #4F8BFF, --sky #A9CBFF, --mist #EAF2FF, --paper #F5F8FF,
  --ink #0B1640, --ink-2 #3B4A78, --ink-3 #6A78A6, --pink #FF4FA3, --pink-2 #FF6FB5, --pink-soft #FFE3F1.
- On the landing page gradients, glass and pink as a brand accent (main button, highlights) are allowed.
  Inside /app and /twin pink still means only "the attacker got here".
- Fonts: Outfit 300-600 (headings), Plus Jakarta Sans (body), Big Shoulders Display 800 (big numbers). All vendored.
- Motion: Lenis smooth scroll; staggered headline reveal; floating cards tilt with the mouse and spread on scroll; pinned
  "zoom into the city" section (card grows to full screen, five callouts, X-ray of the worst way in); pipeline beam fills
  with scroll; bento tiles have a cursor spotlight; architecture boxes light in sequence. Everything is static under
  prefers-reduced-motion, and canvases pause off-screen.
- Data: every number comes from /api/public/* (landing, hero, headline, attack). Water data is labelled historical replay.

## 12. Platform light theme (default) and dark data islands
- `:root[data-theme="light"]` remaps the same tokens (light surfaces, ink text). Charts, network maps and other SVG-heavy
  panels (`.chart-card`, `.dk`) stay dark navy "data islands", so every chart colour keeps its validated contrast.
- In light theme pink is #E3338C for text contrast; it still only means the attack. Known-exploited and warnings use
  dark amber text (#9A5B00) on light amber.
- Interaction: page enter fade (.35 s), skeleton loaders, KPI numbers count up once, Ctrl+K command palette.
- Twin labels: collision-culled every 140 ms against each other and against the clock, hero, rail, panel, ticker and card.

## 13. Multi-attacker and map conventions (PASS 12)
- **Fill = first attacker to get there; outer ring = a second attacker also got there (contested).** Same rule on the 2D
  map and in the twin. Never mix the two meanings.
- **Dashed ring = a way in that is not open yet** (2D). In the twin the beam simply has not dropped; the label says
  "B comes in at T+00:15".
- **Dome = protected by a fix you applied in this session. Dashed ground ring = already monitored in the dataset.**
  Both appear in the legend; they are never the same marker.
- **Amber = maintenance or a service on backup.** No attacker colour may be amber.
- Attack lines in the twin are drawn without tone mapping so each attacker keeps its hue under bloom.
- Every drawn edge comes from the backend's `parents`; an edge grows between the parent's and the child's compromise
  time. No decorative animation that is not data.
- Labels: placed above, then below, otherwise hidden if they would overlap a higher-priority label, a sector name or
  the screen edge. Full names are always in the tooltip.
- Landing zoom frames are real captures. Re-run `node tools/capture_twin_frames.js` after changing the twin or the
  dataset; hotspots are projected from the twin, never placed by hand.

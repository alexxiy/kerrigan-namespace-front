# Image assets

All artwork derives from two SVG sources, so the icon set and the social card cannot drift
apart. Regenerate after editing either source — the PNGs are build output, not originals.

| Source | Used for |
|:---|:---|
| `favicon.svg` | the full brand mark: the Kerrigan icon + DNS-node overlay |
| `favicon-small.svg` | 16px and 32px only — same icon, overlay dropped and icon enlarged, because at 16px the overlay is ~5px across and reads as noise |
| `og-image.svg` | the 1200x630 social card |

The SVG lives only at `images/favicon.svg`, which is what both `index.html` and
`app.html` link. There is no root-level copy: browsers only auto-request `/favicon.ico`
(which does sit at the root) when a page declares no `<link rel="icon">`, and never
`/favicon.svg`. A root duplicate would just be a second file to keep in sync.

## Regenerating

```bash
cd ..                      # repository root

# full mark
inkscape images/favicon.svg -w 180 -h 180 -o images/apple-touch-icon.png
inkscape images/favicon.svg -w 192 -h 192 -o images/android-chrome-192x192.png
inkscape images/favicon.svg -w 512 -h 512 -o images/android-chrome-512x512.png

# simplified mark for the small sizes
inkscape images/favicon-small.svg -w 16 -h 16 -o images/favicon-16x16.png
inkscape images/favicon-small.svg -w 32 -h 32 -o images/favicon-32x32.png

# multi-resolution .ico: simplified at 16/32, full at 48
D=$(mktemp -d)
inkscape images/favicon-small.svg -w 16 -h 16 -o $D/i16.png
inkscape images/favicon-small.svg -w 32 -h 32 -o $D/i32.png
inkscape images/favicon.svg -w 48 -h 48 -o $D/i48.png
convert $D/i16.png $D/i32.png $D/i48.png favicon.ico && rm -rf $D

# social card
inkscape images/og-image.svg -w 1200 -h 630 -o images/og-image.png
convert images/og-image.png -strip PNG24:images/og-image.png
```

Brand colours, Kerrigan's own (Kerrigan Core's `src/qt/res/css/kerrigan.css`,
`Graphics/logo.svg` and the black page of kerrigan.network), matching `css/style.css` and
`tailwind.config.js`: `#8341ed` logo purple, `#43de78` logo green, `#a05ff4` accent,
`#000000` page, `#140828` raised, `#cba8fb` light accent; `#1a0a2e` is the DNS overlay's
nodes. The favicon tile is `#ffffff` -> `#ede3fd`, which a light browser tab strip needs;
the social card's tile, like the app's header mark, is `#1d0d38` -> `#0b0416` ringed in
`#8341ed`.
`convert` is ImageMagick 6's name; on ImageMagick 7 it is `magick`.

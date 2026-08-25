/**
 * Chart palette.
 *
 * The dashboard renders on a dark surface only, so these are the dark-mode
 * steps of a categorical scale validated for colour-vision deficiency: adjacent
 * pairs stay separable under deuteranopia and protanopia, and every step clears
 * 3:1 contrast against the chart surface.
 *
 * Two rules matter when editing this file:
 *
 *  1. Series colours are assigned by *position*, never cycled. A ninth series
 *     folds into "Other" rather than reusing slot 1 - otherwise two unrelated
 *     platforms end up the same colour.
 *  2. Status colours are reserved. They mean good/warning/serious/critical and
 *     must never be borrowed as "series 4", or a neutral series will read as an
 *     incident.
 */

/** Chart surface, matching the MUI `background.paper`. */
export const VIZ_SURFACE = '#1e1e1e';

/** Recessive grid and axis ink. */
export const VIZ_GRID = '#333333';
export const VIZ_AXIS_TEXT = '#b0b0b0';
export const VIZ_TEXT = '#ffffff';

/**
 * Categorical series colours, in fixed assignment order.
 * Only the first three are safe for forms that put every pair side by side
 * (scatter, bubble); beyond three, prefer facets or an "Other" bucket.
 */
export const SERIES_COLORS = [
  '#3987e5', // 1 blue
  '#d95926', // 2 orange
  '#199e70', // 3 aqua
  '#c98500', // 4 yellow
  '#d55181', // 5 magenta
  '#008300', // 6 green
  '#9085e9', // 7 violet
  '#e66767', // 8 red
] as const;

/** Colour for anything past the last categorical slot. */
export const SERIES_OTHER = '#6b6b6b';

/**
 * Reserved status colours. Always paired with an icon or a text label so the
 * meaning never rests on hue alone.
 */
export const STATUS_COLORS = {
  good: '#0ca30c',
  warning: '#fab219',
  serious: '#ec835a',
  critical: '#d03b3b',
} as const;

/** Risk level is ordinal severity, so it maps onto the status scale. */
export const RISK_COLORS: Record<string, string> = {
  low: STATUS_COLORS.good,
  medium: STATUS_COLORS.warning,
  high: STATUS_COLORS.serious,
  critical: STATUS_COLORS.critical,
};

/** Pick the series colour for a slot, folding overflow into the "other" grey. */
export function seriesColor(index: number): string {
  return SERIES_COLORS[index] ?? SERIES_OTHER;
}

/** Map a 0-100 risk score onto the severity scale. */
export function riskScoreColor(score: number): string {
  if (score >= 85) return STATUS_COLORS.critical;
  if (score >= 60) return STATUS_COLORS.serious;
  if (score >= 30) return STATUS_COLORS.warning;
  return STATUS_COLORS.good;
}

/** Human-readable band for a 0-100 risk score. */
export function riskScoreLabel(score: number): string {
  if (score >= 85) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

/** Shared Recharts tooltip styling, so every chart's tooltip matches. */
export const TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: VIZ_SURFACE,
    border: `1px solid ${VIZ_GRID}`,
    borderRadius: 8,
    color: VIZ_TEXT,
    fontSize: 13,
  },
  labelStyle: { color: VIZ_AXIS_TEXT, marginBottom: 4 },
  itemStyle: { color: VIZ_TEXT },
} as const;

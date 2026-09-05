/**
 * The browser half of `PlotlyChart`.
 *
 * Kept in its own module because everything here touches `window`: Plotly builds its
 * bundle against the DOM at require time, so this module must never be evaluated during
 * the server render. `PlotlyChart` only reaches it from inside `<BrowserOnly>`, which is
 * what makes the `require` calls below safe.
 *
 * The figure specs themselves are generated from the committed result files by
 * `scripts/generate_benchmarks.py` and served from `static/charts/`. Nothing in this file
 * invents, rounds or rescales a number; it applies theme colors to whatever spec it was
 * handed and hands the rest to Plotly.
 */

import React, {useEffect, useMemo, useState} from 'react';
import {useColorMode} from '@docusaurus/theme-common';

import styles from './styles.module.css';

/** The shape the generator writes: a Plotly figure plus the provenance of its numbers. */
export interface ChartSpec {
  data: unknown[];
  layout: Record<string, any>;
  config?: Record<string, any>;
}

interface FigureProps {
  /** Absolute URL of the figure spec, already run through `useBaseUrl`. */
  src: string;
  /** Accessible description of what the chart shows. */
  alt: string;
}

/**
 * Colors that follow the site theme, so a chart never sits on a white rectangle in dark
 * mode. Only the chrome is themed. Series colors come from the spec, because they carry
 * meaning: one arm is one color across every chart on the page.
 */
function chrome(dark: boolean) {
  return dark
    ? {
        text: '#e6e6e6',
        muted: '#a9b0b8',
        grid: 'rgba(255, 255, 255, 0.14)',
        line: 'rgba(255, 255, 255, 0.28)',
      }
    : {
        text: '#1c1e21',
        muted: '#5c6773',
        grid: 'rgba(0, 0, 0, 0.10)',
        line: 'rgba(0, 0, 0, 0.22)',
      };
}

/**
 * Apply theme chrome to a generated layout without touching its data-bearing fields.
 *
 * @param layout - The layout the generator wrote.
 * @param dark - Whether the site is currently in dark mode.
 * @returns A layout with themed text, gridlines and a transparent background.
 */
function themeLayout(layout: Record<string, any>, dark: boolean): Record<string, any> {
  const c = chrome(dark);
  // A log axis labels every minor tick by default, which turns a decade into "1000 5 2
  // 100 5 2" and reads as noise. Decades only, unless the spec asked for something else.
  const axis = (existing: Record<string, any> = {}) => ({
    automargin: true,
    ...(existing.type === 'log' && existing.dtick === undefined ? {dtick: 1} : {}),
    ...existing,
    gridcolor: c.grid,
    zerolinecolor: c.line,
    linecolor: c.line,
    tickfont: {...(existing.tickfont ?? {}), color: c.muted},
    title:
      typeof existing.title === 'string'
        ? {text: existing.title, font: {color: c.muted}}
        : {...(existing.title ?? {}), font: {...(existing.title?.font ?? {}), color: c.muted}},
  });

  // A horizontal legend sits below the plot, so it needs room, and it needs more room
  // when there is an axis title under the ticks for it to clear. Both are derived from
  // the spec rather than fixed, and a spec that sets its own margin still wins.
  const xTitle = layout.xaxis?.title;
  const hasXTitle = Boolean(typeof xTitle === 'string' ? xTitle : xTitle?.text);
  const bottom = hasXTitle ? 108 : 78;

  const themed: Record<string, any> = {
    autosize: true,
    ...layout,
    margin: {l: 64, r: 20, t: 44, b: bottom, ...(layout.margin ?? {})},
    paper_bgcolor: 'rgba(0, 0, 0, 0)',
    plot_bgcolor: 'rgba(0, 0, 0, 0)',
    font: {
      family:
        'system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
      size: 13,
      ...(layout.font ?? {}),
      color: c.text,
    },
    legend: {
      orientation: 'h',
      yanchor: 'top',
      y: hasXTitle ? -0.3 : -0.18,
      x: 0,
      ...(layout.legend ?? {}),
      font: {...(layout.legend?.font ?? {}), color: c.muted},
      bgcolor: 'rgba(0, 0, 0, 0)',
    },
    hoverlabel: {bordercolor: c.line, ...(layout.hoverlabel ?? {})},
  };

  themed.xaxis = axis(layout.xaxis);
  themed.yaxis = axis(layout.yaxis);
  if (typeof layout.title === 'string') {
    themed.title = {text: layout.title, font: {color: c.text, size: 15}};
  } else if (layout.title) {
    themed.title = {
      ...layout.title,
      font: {...(layout.title.font ?? {}), color: c.text, size: 15},
    };
  }
  return themed;
}

/**
 * Fetch a generated figure spec and render it with Plotly.
 *
 * @param props - The spec URL and an accessible description.
 * @returns The rendered chart, a loading placeholder, or an error notice.
 */
export default function Figure({src, alt}: FigureProps): React.ReactElement {
  const {colorMode} = useColorMode();
  const [spec, setSpec] = useState<ChartSpec | null>(null);
  const [error, setError] = useState<string | null>(null);

  const Plot = useMemo(() => {
    // Required lazily: `plotly.js-cartesian-dist-min` reads `window` while it evaluates.
    // The cartesian bundle rather than the full one, because every figure here is a bar,
    // scatter or line chart and the full bundle is several times the size.
    const createPlotlyComponent = require('react-plotly.js/factory').default;
    const Plotly = require('plotly.js-cartesian-dist-min');
    return createPlotlyComponent(Plotly);
  }, []);

  useEffect(() => {
    let cancelled = false;
    setSpec(null);
    setError(null);
    fetch(src)
      .then((response) => {
        if (!response.ok) {
          throw new Error(`${response.status} ${response.statusText}`);
        }
        return response.json();
      })
      .then((document: ChartSpec) => {
        if (!cancelled) {
          setSpec(document);
        }
      })
      .catch((cause: unknown) => {
        if (!cancelled) {
          setError(String(cause));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [src]);

  if (error !== null) {
    return (
      <div className={styles.placeholder} role="alert">
        This chart could not be loaded ({error}). Its figure spec is generated from the
        result files by <code>just charts</code>.
      </div>
    );
  }

  if (spec === null) {
    return <div className={styles.placeholder}>Loading chart…</div>;
  }

  return (
    <Plot
      key={colorMode}
      data={spec.data}
      layout={themeLayout(spec.layout, colorMode === 'dark')}
      config={{displayModeBar: false, responsive: true, ...(spec.config ?? {})}}
      style={{width: '100%', height: '100%'}}
      useResizeHandler
      aria-label={alt}
    />
  );
}

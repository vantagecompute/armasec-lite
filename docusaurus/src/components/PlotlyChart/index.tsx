/**
 * A Plotly figure with the provenance of its numbers attached to it.
 *
 * Plotly reads `window` at import time, so the rendering half lives in `Figure.tsx` and is
 * only reached from inside `<BrowserOnly>`. The caption is rendered outside it, on both the
 * server and the client, because a chart's provenance is the part a reader most needs and
 * the part that must survive with JavaScript disabled, in a text extraction, and in the
 * generated `llms.txt`.
 *
 * The `src` is a path under `static/charts/`, written by `scripts/generate_benchmarks.py`
 * from the committed result files and from nothing else.
 */

import React from 'react';
import BrowserOnly from '@docusaurus/BrowserOnly';
import useBaseUrl from '@docusaurus/useBaseUrl';

import styles from './styles.module.css';

interface PlotlyChartProps {
  /** Path to the generated figure spec, relative to the site root, e.g. `/charts/x.json`. */
  src: string;
  /** Accessible description of what the chart shows. */
  alt: string;
  /** Host, date and both library versions. Rendered under the chart, always. */
  provenance: string;
  /** Rendered height. Charts are responsive in width and fixed in height. */
  height?: number;
}

/**
 * Render one generated figure with its provenance caption.
 *
 * @param props - The spec path, an accessible description, and the provenance line.
 * @returns A figure element containing the chart and its caption.
 */
export default function PlotlyChart({
  src,
  alt,
  provenance,
  height = 380,
}: PlotlyChartProps): React.ReactElement {
  const url = useBaseUrl(src);
  return (
    <figure className={styles.figure}>
      <div className={styles.canvas} style={{height: `${height}px`}}>
        <BrowserOnly fallback={<div className={styles.placeholder}>Loading chart…</div>}>
          {() => {
            const Figure = require('./Figure').default;
            return <Figure src={url} alt={alt} />;
          }}
        </BrowserOnly>
      </div>
      <figcaption className={styles.caption}>{provenance}</figcaption>
    </figure>
  );
}

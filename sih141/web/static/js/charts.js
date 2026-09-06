/* charts.js -- inline SVG, hand-rolled, and the ONLY arithmetic in this app.
 *
 * WHY NO CHART LIBRARY
 * --------------------
 * Nothing on this page may be fetched from a network, ever, so a chart library
 * would have to be vendored: a megabyte of minified third-party code committed
 * into a repository whose whole claim is that it is the artefact and that every
 * number in it is covered by a test. These charts are four horizontal bars with
 * a threshold marker. Writing them costs less than auditing a bundle, they draw
 * as SVG rather than canvas -- so they stay sharp on a projector and their text
 * is real text a screen reader can reach -- and every element on them is one
 * this file put there on purpose.
 *
 * WHAT THIS FILE IS AND IS NOT ALLOWED TO DO (D8)
 * -----------------------------------------------
 * Allowed: turning a value the API supplied into a pixel coordinate. That is
 * plotting, which D8 names as permitted, and it is all `scale()` does.
 *
 * NOT allowed, and structurally prevented rather than promised:
 *
 *   * This file contains no `toFixed`, `toExponential` or `toPrecision`. It
 *     cannot format a number for display. EVERY string that reaches the screen
 *     from here arrived as a caller-supplied `label`, formatted in `format.js`
 *     from a value the API sent. A test greps for those three names.
 *   * No axis maximum is computed from the data. Every domain passed in is
 *     DEFINITIONAL -- [0, 1] for a rate, [0, 4] for CHSH, [0, trials] for a
 *     count where `trials` came from the API -- so no "nice number" chosen by a
 *     layout algorithm can ever be read as a result.
 *   * Nothing here decides a colour from a value. The caller passes a class
 *     name it derived from the API's own `signals` list; a bar is never red
 *     because this file compared it to a threshold.
 *
 * The one comparison in the file is `clamp`, which keeps a bar inside the plot
 * rectangle. It changes geometry and never a number, and a clamped bar is
 * always accompanied by its value as text in the right-hand column.
 */

const Charts = (function () {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";

  const LABEL_WIDTH = 148;
  const VALUE_WIDTH = 150;
  const RIGHT_PAD = 8;
  const TOP_PAD = 36;
  const AXIS_PAD = 30;
  const ROW_HEIGHT = 34;
  const BAR_HEIGHT = 13;
  const WIDTH = 760;

  // Every chart carries its own copy of the hatch pattern, so each needs its
  // own id: three charts sharing one would put duplicate ids in the document,
  // and `url(#id)` would resolve to whichever chart happened to render first.
  // Correct today only because the three patterns are identical, and silently
  // wrong the moment one is not.
  let patternSerial = 0;

  /**
   * Create an SVG element with attributes.
   *
   * @param {string} name
   * @param {Object} attrs
   * @returns {SVGElement}
   */
  function el(name, attrs) {
    const node = document.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (key) {
      node.setAttribute(key, attrs[key]);
    });
    return node;
  }

  /**
   * Create an SVG text node carrying a caller-supplied string.
   *
   * `label` is never produced in this file. It is always a string the caller
   * formatted from an API value.
   *
   * @param {number} x
   * @param {number} y
   * @param {string} label
   * @param {string} className
   * @param {string} anchor
   * @returns {SVGElement}
   */
  function text(x, y, label, className, anchor) {
    const node = el("text", {
      x: x,
      y: y,
      class: className,
      "text-anchor": anchor || "start",
    });
    node.textContent = label;
    return node;
  }

  /**
   * Keep a coordinate inside the plot rectangle.
   *
   * Geometry only: a clamped bar always has its value printed as text beside
   * it, so nothing is hidden by the clamp.
   *
   * @param {number} value
   * @param {number} low
   * @param {number} high
   * @returns {number}
   */
  function clamp(value, low, high) {
    if (value < low) {
      return low;
    }
    if (value > high) {
      return high;
    }
    return value;
  }

  /**
   * Map a data value onto an x coordinate. The whole of the arithmetic.
   *
   * @param {number} value
   * @param {{min: number, max: number}} domain
   * @param {number} left
   * @param {number} right
   * @returns {number}
   */
  function scale(value, domain, left, right) {
    const span = domain.max - domain.min;
    if (span === 0) {
      return left;
    }
    const fraction = (value - domain.min) / span;
    return clamp(left + fraction * (right - left), left, right);
  }

  /**
   * Append the hatch pattern used for a cell that could not be evaluated.
   *
   * @param {SVGElement} svg
   * @param {string} id
   * @returns {void}
   */
  function addHatch(svg, id) {
    const defs = el("defs", {});
    const pattern = el("pattern", {
      id: id,
      width: 8,
      height: 8,
      patternUnits: "userSpaceOnUse",
      patternTransform: "rotate(45)",
    });
    pattern.appendChild(
      el("rect", { width: 8, height: 8, fill: "#e8eaee" })
    );
    pattern.appendChild(
      el("line", {
        x1: 0,
        y1: 0,
        x2: 0,
        y2: 8,
        stroke: "#8b93a1",
        "stroke-width": 3,
      })
    );
    defs.appendChild(pattern);
    svg.appendChild(defs);
  }

  /**
   * Draw a horizontal bar chart with markers and whiskers.
   *
   * @param {Object} options
   * @param {Array<Object>} options.rows One per bar. Each row carries
   *   `label` (left gutter, string), `valueLabel` (right column, string),
   *   `value` (number or null), `className` (a bar class the CALLER chose from
   *   the API's own signals), optional `interval` and `bound` objects with
   *   `low`/`high`, and optional `unavailable` (a string, which replaces the
   *   bar with a hatched cell carrying that text).
   * @param {{min: number, max: number}} options.domain Definitional, never
   *   derived from the data.
   * @param {Array<{value: number, label: string}>} options.ticks
   * @param {Array<{value: number, label: string, className: string}>}
   *   options.markers Threshold and reference lines, values from the API.
   * @param {string} options.title Accessible title for the whole figure.
   * @returns {SVGElement}
   */
  function bars(options) {
    const rows = options.rows || [];
    const domain = options.domain;
    const ticks = options.ticks || [];
    const markers = options.markers || [];
    const left = LABEL_WIDTH;
    const right = WIDTH - VALUE_WIDTH - RIGHT_PAD;
    const plotHeight = ROW_HEIGHT * rows.length;
    const height = TOP_PAD + plotHeight + AXIS_PAD;
    patternSerial += 1;
    const hatchId = `hatch-withheld-${patternSerial}`;

    const svg = el("svg", {
      class: "chart",
      viewBox: `0 0 ${WIDTH} ${height}`,
      role: "img",
      "aria-label": options.title || "chart",
    });
    const titleNode = el("title", {});
    titleNode.textContent = options.title || "chart";
    svg.appendChild(titleNode);
    addHatch(svg, hatchId);

    ticks.forEach(function (tick) {
      const x = scale(tick.value, domain, left, right);
      svg.appendChild(
        el("line", {
          class: "grid-line",
          x1: x,
          y1: TOP_PAD,
          x2: x,
          y2: TOP_PAD + plotHeight,
        })
      );
      svg.appendChild(
        text(
          x,
          TOP_PAD + plotHeight + 16,
          tick.label,
          "tick-label",
          "middle"
        )
      );
    });

    svg.appendChild(
      el("line", {
        class: "axis-line",
        x1: left,
        y1: TOP_PAD,
        x2: left,
        y2: TOP_PAD + plotHeight,
      })
    );

    // Two label lanes, alternating, so that two markers close together on
    // the axis -- the classical and Tsirelson bounds are 0.83 apart -- do not
    // print their names on top of each other.
    markers.forEach(function (marker, index) {
      const x = scale(marker.value, domain, left, right);
      const lane = index % 2 === 0 ? 12 : 26;
      svg.appendChild(
        el("line", {
          class: marker.className,
          x1: x,
          y1: lane + 4,
          x2: x,
          y2: TOP_PAD + plotHeight,
        })
      );
      svg.appendChild(
        text(
          x,
          lane,
          marker.label,
          marker.labelClassName || "marker-label",
          "middle"
        )
      );
    });

    rows.forEach(function (row, index) {
      const top = TOP_PAD + ROW_HEIGHT * index;
      const mid = top + ROW_HEIGHT / 2;

      svg.appendChild(
        text(0, mid + 4, row.label, "row-label", "start")
      );

      if (row.unavailable) {
        svg.appendChild(
          el("rect", {
            class: "hatch-cell",
            x: left,
            y: top + 5,
            width: right - left,
            height: ROW_HEIGHT - 12,
            fill: `url(#${hatchId})`,
          })
        );
        svg.appendChild(
          text(
            left + (right - left) / 2,
            mid + 4,
            row.unavailable,
            "tick-label",
            "middle"
          )
        );
      } else if (row.value !== null && row.value !== undefined) {
        // Where a bar starts. Defaults to the low end of the domain; a signed
        // quantity (CHSH runs over [-4, 4]) passes 0 so its bars grow from the
        // middle. Both are definitional constants supplied by the caller, never
        // a value read off the data.
        const base =
          options.baseline === undefined ? domain.min : options.baseline;
        const zero = scale(base, domain, left, right);
        const x = scale(row.value, domain, left, right);
        // An SVG rect is anchored at its LEFT edge, so a bar running back from
        // the baseline starts at `x` and not at `zero`. Anchoring both at
        // `zero` drew a CHSH of -2 as a bar reaching +2 -- the right length on
        // the wrong side of the zero line, on the one chart whose whole point
        // is which side of a bound a link sits.
        svg.appendChild(
          el("rect", {
            class: row.className || "bar",
            x: Math.min(zero, x),
            y: mid - BAR_HEIGHT / 2,
            width: Math.abs(x - zero),
            height: BAR_HEIGHT,
          })
        );
        if (row.bound) {
          const lo = scale(row.bound.low, domain, left, right);
          const hi = scale(row.bound.high, domain, left, right);
          svg.appendChild(
            el("line", {
              class: "whisker-loose",
              x1: lo,
              y1: mid + BAR_HEIGHT,
              x2: hi,
              y2: mid + BAR_HEIGHT,
            })
          );
        }
        if (row.interval) {
          const lo = scale(row.interval.low, domain, left, right);
          const hi = scale(row.interval.high, domain, left, right);
          svg.appendChild(
            el("line", {
              class: "whisker",
              x1: lo,
              y1: mid - BAR_HEIGHT,
              x2: hi,
              y2: mid - BAR_HEIGHT,
            })
          );
          svg.appendChild(
            el("line", {
              class: "whisker",
              x1: lo,
              y1: mid - BAR_HEIGHT - 4,
              x2: lo,
              y2: mid - BAR_HEIGHT + 4,
            })
          );
          svg.appendChild(
            el("line", {
              class: "whisker",
              x1: hi,
              y1: mid - BAR_HEIGHT - 4,
              x2: hi,
              y2: mid - BAR_HEIGHT + 4,
            })
          );
        }
      }

      svg.appendChild(
        text(
          WIDTH - RIGHT_PAD,
          mid + 4,
          row.valueLabel,
          "value-label",
          "end"
        )
      );
    });

    return svg;
  }

  return { bars: bars };
})();
